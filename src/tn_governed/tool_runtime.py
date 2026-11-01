"""Registered tool workflows over independently authorized TN endpoints.

Provider proposals carry names and handles, never authority. Each invocation,
model turn, result inspection, and release crosses the endpoint's public gate.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from threading import RLock
from types import MappingProxyType
from uuid import uuid4

from jsonschema import Draft202012Validator


class WorkflowError(ValueError):
    """A proposal or result violates the configured workflow contract."""


def json_value(value, depth=0):
    """Detach ordinary JSON; governed objects and nonfinite numbers are rejected."""
    if depth > 64:
        raise WorkflowError("JSON nesting exceeds the workflow limit")
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if type(value) is list:
        return [json_value(item, depth + 1) for item in value]
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: json_value(item, depth + 1) for key, item in value.items()}
    raise WorkflowError("workflow data must be ordinary finite JSON")


def _wire(value):
    return json.dumps(json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _identity(value, field):
    if (
        type(value) is not str
        or not value
        or len(value) > 256
        or value != value.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise WorkflowError(f"{field} requires a nonempty bounded identity")
    return value


def _schema(schema):
    schema = json_value(schema)
    Draft202012Validator.check_schema(schema)

    def references(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"$ref", "$dynamicRef"} and not item.startswith("#"):
                    raise ValueError("tool schemas require local references")
                references(item)
        elif isinstance(value, list):
            for item in value:
                references(item)

    references(schema)
    return _wire(schema)


@dataclass(frozen=True, init=False)
class Call:
    id: str
    name: str
    _arguments: str
    inputs: tuple[str, ...]
    depends_on: tuple[str, ...]

    def __init__(self, id, name, arguments, inputs=(), depends_on=()):
        _identity(id, "call ID")
        _identity(name, "tool name")
        if type(arguments) is not dict:
            raise WorkflowError("tool arguments must be an object")
        if not isinstance(inputs, (tuple, list)) or not isinstance(depends_on, (tuple, list)):
            raise WorkflowError("tool inputs and dependencies must be sequences")
        for field, values in (("input handle", inputs), ("call dependency", depends_on)):
            for value in values:
                _identity(value, field)
            if len(set(values)) != len(values):
                raise WorkflowError(f"duplicate {field}")
        object.__setattr__(self, "id", id)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "_arguments", _wire(arguments))
        object.__setattr__(self, "inputs", tuple(inputs))
        object.__setattr__(self, "depends_on", tuple(depends_on))

    @property
    def arguments(self):
        return json.loads(self._arguments)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "arguments": self.arguments,
            "inputs": list(self.inputs),
            "depends_on": list(self.depends_on),
        }

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != {
            "id",
            "name",
            "arguments",
            "inputs",
            "depends_on",
        }:
            raise WorkflowError("invalid tool call shape")
        return cls(**value)


@dataclass(frozen=True)
class ProviderTurn:
    calls: tuple[Call, ...] = ()
    text: str | None = None

    def __post_init__(self):
        if not isinstance(self.calls, tuple) or any(
            not isinstance(call, Call) for call in self.calls
        ):
            raise ValueError("provider calls require an immutable sequence")
        if (bool(self.calls) and self.text is not None) or (
            not self.calls and type(self.text) is not str
        ):
            raise ValueError("a provider turn requires calls or terminal text")
        if len({call.id for call in self.calls}) != len(self.calls):
            raise WorkflowError("provider repeated a call ID in one turn")

    def to_dict(self):
        return {"calls": [call.to_dict() for call in self.calls], "text": self.text}

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != {"calls", "text"}:
            raise WorkflowError("invalid provider turn shape")
        return cls(tuple(Call.from_dict(call) for call in value["calls"]), value["text"])


@dataclass(frozen=True, init=False)
class ToolSpec:
    name: str
    description: str
    handler: Callable
    operation: str
    result_mode: str
    model_visible: bool
    retryable: bool
    result_admit: Callable | None
    result_validator: Callable | None
    _input_schema: str
    _output_schema: str

    def __init__(
        self,
        name,
        input_schema,
        output_schema,
        handler,
        *,
        description="",
        operation="tool.call",
        result_mode="local",
        model_visible=False,
        retryable=False,
        result_admit=None,
        result_validator=None,
    ):
        if type(name) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", name):
            raise ValueError("tool name must be a provider-compatible identifier")
        if not callable(handler) or type(description) is not str:
            raise TypeError("tool registration requires a handler and description")
        if result_mode not in {"local", "governed"}:
            raise ValueError("tool result mode must be local or governed")
        if type(model_visible) is not bool or type(retryable) is not bool:
            raise TypeError("tool visibility and retry settings must be Boolean")
        if result_validator is not None and not callable(result_validator):
            raise TypeError("result validator must be callable")
        if result_admit is not None and not callable(result_admit):
            raise TypeError("result admission must be callable")
        if result_mode == "governed" and result_admit is None:
            raise ValueError("governed tools require explicit result authority admission")
        if result_mode == "local" and result_admit is not None:
            raise ValueError("result authority admission applies to governed tool results")
        for key, value in {
            "name": name,
            "description": description,
            "handler": handler,
            "operation": _identity(operation, "operation"),
            "result_mode": result_mode,
            "model_visible": model_visible,
            "retryable": retryable,
            "result_admit": result_admit,
            "result_validator": result_validator,
            "_input_schema": _schema(input_schema),
            "_output_schema": _schema(output_schema),
        }.items():
            object.__setattr__(self, key, value)

    @property
    def input_schema(self):
        return json.loads(self._input_schema)

    @property
    def output_schema(self):
        return json.loads(self._output_schema)

    def validate_arguments(self, arguments):
        if not Draft202012Validator(self.input_schema).is_valid(arguments):
            raise WorkflowError(f"arguments do not satisfy tool {self.name!r}'s schema")

    def validate_output(self, output, invocation):
        output = json_value(output)
        if not Draft202012Validator(self.output_schema).is_valid(output):
            raise WorkflowError(f"result does not satisfy tool {self.name!r}'s schema")
        if (
            self.result_validator is not None
            and self.result_validator(invocation, json_value(output)) is not True
        ):
            raise WorkflowError(f"result failed tool {self.name!r}'s configured validation")
        return output


class ToolRegistry:
    def __init__(self, tools):
        tools = tuple(tools)
        if any(not isinstance(tool, ToolSpec) for tool in tools):
            raise TypeError("tools require ToolSpec registrations")
        if len({tool.name for tool in tools}) != len(tools):
            raise ValueError("duplicate tool registration")
        self._tools = MappingProxyType({tool.name: tool for tool in tools})

    def __getitem__(self, name):
        try:
            return self._tools[name]
        except KeyError as exc:
            raise WorkflowError("tool is not registered") from exc

    def descriptions(self):
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "arguments": tool.input_schema,
                        "inputs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "uniqueItems": True,
                        },
                        "depends_on": {
                            "type": "array",
                            "items": {"type": "string"},
                            "uniqueItems": True,
                        },
                    },
                    "required": ["arguments", "inputs", "depends_on"],
                    "additionalProperties": False,
                },
            }
            for tool in self._tools.values()
        ]


@dataclass(frozen=True)
class ToolInvocation:
    run_id: str
    call_id: str
    attempt: int
    artifacts: tuple
    _arguments: str
    _values: str
    _binding: str

    @property
    def arguments(self):
        return json.loads(self._arguments)

    @property
    def values(self):
        return tuple(json.loads(self._values))

    @property
    def binding(self):
        return json.loads(self._binding)

    @property
    def idempotency_key(self):
        return "tn-tool:" + hashlib.sha256(self._binding.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ToolCompletion:
    call_id: str
    name: str
    artifact: object
    attempt: int

    @property
    def handle(self):
        return "result:" + self.call_id


@dataclass
class _CallState:
    call: Call
    status: str = "running"
    attempt: int = 1
    completion: ToolCompletion | None = None
    error_type: str | None = None
    binding: str | None = None


class ToolWorkflow:
    """One run's handle namespace, dependency graph, and replay-safe call ledger.

    A run serializes its invocations. Distinct runs/endpoints may operate
    concurrently. A failed action is never retried by the provider loop; explicit
    retry requires a tool registered for idempotent retry with the same key.
    """

    def __init__(self, endpoint, tools, inputs, *, required_tools=(), max_calls=64, run_id=None):
        from .endpoints import GovernedArtifact

        if not isinstance(tools, ToolRegistry) or not isinstance(inputs, Mapping) or not inputs:
            raise ValueError("workflow requires registered tools and governed inputs")
        if type(max_calls) is not int or max_calls < 1:
            raise ValueError("max_calls must be a positive integer")
        self.endpoint, self.tools = endpoint, tools
        self.run_id = _identity(run_id or uuid4().hex, "run ID")
        self._inputs, self._artifacts = {}, {}
        for name, artifact in inputs.items():
            _identity(name, "input handle")
            if name.startswith(("result:", "turn:")) or not isinstance(artifact, GovernedArtifact):
                raise TypeError(
                    "workflow boundaries require governed artifacts and unreserved handles"
                )
            endpoint.metadata(artifact)
            self._inputs[name] = artifact
            self._artifacts[name] = artifact
        if isinstance(required_tools, str):
            raise TypeError("required tools must be a sequence")
        self.required_tools = frozenset(required_tools)
        for name in self.required_tools:
            tools[name]
        self.max_calls = max_calls
        self._calls, self._events = {}, []
        self._finished, self._finish_request = None, None
        self._lock = RLock()

    @property
    def events(self):
        with self._lock:
            return tuple(json_value(event) for event in self._events)

    @property
    def handles(self):
        with self._lock:
            return tuple(self._artifacts)

    def _scope(self, artifacts):
        unique = {}
        for artifact in artifacts:
            unique.setdefault(_wire(artifact.to_dict()), artifact)
        return tuple(unique.values())

    def _dependencies(self, call):
        return set(call.depends_on) | {
            name.removeprefix("result:") for name in call.inputs if name.startswith("result:")
        }

    def _validate_call(self, call, pending=()):
        if not isinstance(call, Call):
            raise TypeError("workflow execution requires a Call")
        tool = self.tools[call.name]
        tool.validate_arguments(call.arguments)
        for name in call.inputs:
            if name not in self._artifacts and not (
                name.startswith("result:") and name[7:] in pending
            ):
                raise WorkflowError("tool names an unknown input handle")
        for dependency in self._dependencies(call):
            if dependency == call.id or dependency not in self._calls and dependency not in pending:
                raise WorkflowError("tool names an invalid dependency")
        return tool

    def execute(self, call, *, control=None, retry=False):
        with self._lock:
            if self._finished is not None:
                raise WorkflowError("workflow has already released its result")
            tool = self._validate_call(call)
            state = self._calls.get(call.id)
            if state is not None:
                if state.call != call:
                    raise WorkflowError(
                        "call ID was reused with different arguments or dependencies"
                    )
                if state.status == "succeeded":
                    return state.completion
                if not retry or not tool.retryable or state.status != "failed":
                    raise WorkflowError("failed or running call cannot be repeated")
                state.attempt += 1
                state.status = "running"
            else:
                if len(self._calls) >= self.max_calls:
                    raise WorkflowError("workflow call limit exceeded")
                state = self._calls[call.id] = _CallState(call)
            dependencies = self._dependencies(call)
            try:
                if any(self._calls[item].status != "succeeded" for item in dependencies):
                    raise WorkflowError("tool dependency has not completed")
                selected = tuple(self._artifacts[name] for name in call.inputs)
                scope = self._scope(
                    [
                        *self._inputs.values(),
                        *selected,
                        *(self._calls[item].completion.artifact for item in sorted(dependencies)),
                        *(() if control is None else (control,)),
                    ]
                )
                positions = {
                    _wire(artifact.to_dict()): index for index, artifact in enumerate(scope)
                }
                binding = {
                    "run_id": self.run_id,
                    "call_id": call.id,
                    "tool": call.name,
                    "arguments": call.arguments,
                    "inputs": [artifact.to_dict() for artifact in selected],
                    "dependencies": sorted(dependencies),
                    "governance_inputs": [artifact.to_dict() for artifact in scope],
                    "operation": tool.operation,
                    "result_mode": tool.result_mode,
                    "input_schema": tool.input_schema,
                    "output_schema": tool.output_schema,
                }
                if state.binding is not None and state.binding != _wire(binding):
                    raise WorkflowError(
                        "retry changed the invocation's bound control inputs or contract"
                    )
                state.binding = _wire(binding)
                parameters = {
                    "tool_call": binding,
                    "attempt": state.attempt,
                    "input_schema": tool.input_schema,
                    "output_schema": tool.output_schema,
                }
                remote, invocations = [], []

                def invoke(opened):
                    values = [opened[positions[_wire(artifact.to_dict())]] for artifact in selected]
                    invocation = ToolInvocation(
                        self.run_id,
                        call.id,
                        state.attempt,
                        selected,
                        _wire(call.arguments),
                        _wire(values),
                        _wire(binding),
                    )
                    invocations.append(invocation)
                    self._events.append(
                        {
                            "kind": "tool_started",
                            "call_id": call.id,
                            "name": call.name,
                            "attempt": state.attempt,
                        }
                    )
                    output = tool.handler(invocation)
                    if tool.result_mode == "governed":
                        remote.append(output)
                        return {"status": "invoked", "tool_call": binding}
                    return tool.validate_output(output, invocation)

                artifact = self.endpoint.execute(
                    tool.operation,
                    scope,
                    invoke,
                    parameters=parameters,
                    destination="tool:" + call.name,
                )
                if tool.result_mode == "governed":
                    received = self.endpoint.receive(remote[0])
                    metadata = self.endpoint.metadata(received)
                    if metadata.get("parameters", {}).get("tool_call") != binding:
                        raise WorkflowError(
                            "signed remote tool result belongs to another invocation"
                        )
                    publication = self.endpoint.store.read(received.reference.object_id)
                    if tool.result_admit(publication, metadata) is not True:
                        raise WorkflowError(
                            "remote result authority or contract is not admitted for this tool"
                        )
                    result_scope = self._scope([*scope, artifact, received])
                    result_position = result_scope.index(received)
                    artifact = self.endpoint.execute(
                        "tool.result",
                        result_scope,
                        lambda values: tool.validate_output(
                            values[result_position], invocations[0]
                        ),
                        parameters=parameters,
                        destination="workflow:" + self.run_id,
                    )
                self.endpoint.metadata(artifact)
                completion = ToolCompletion(call.id, call.name, artifact, state.attempt)
                state.status, state.completion = "succeeded", completion
                self._artifacts[completion.handle] = artifact
                self._events.append(
                    {
                        "kind": "tool_completed",
                        "call_id": call.id,
                        "name": call.name,
                        "attempt": state.attempt,
                        "artifact": artifact.to_dict(),
                    }
                )
                return completion
            except Exception as exc:
                state.status, state.error_type = "failed", type(exc).__name__
                self._events.append(
                    {
                        "kind": "tool_failed",
                        "call_id": call.id,
                        "name": call.name,
                        "attempt": state.attempt,
                        "error_type": type(exc).__name__,
                    }
                )
                raise

    def execute_many(self, calls, *, control=None):
        with self._lock:
            calls = tuple(calls)
            if any(not isinstance(call, Call) for call in calls):
                raise TypeError("workflow execution requires Call objects")
            if len({call.id for call in calls}) != len(calls):
                raise WorkflowError("batch contains duplicate call IDs")
            pending = {call.id: call for call in calls}
            for call in calls:
                self._validate_call(call, pending)
                if call.id in self._calls and self._calls[call.id].call != call:
                    raise WorkflowError(
                        "call ID was reused with different arguments or dependencies"
                    )
            ordered, resolved = [], set(self._calls)
            while pending:
                ready = [call for call in pending.values() if self._dependencies(call) <= resolved]
                if not ready:
                    raise WorkflowError("tool dependencies contain a cycle")
                for call in ready:
                    ordered.append(call)
                    resolved.add(call.id)
                    del pending[call.id]
            return tuple(self.execute(call, control=control) for call in ordered)

    def expose(self, handle, *, destination):
        with self._lock:
            if handle not in self._artifacts:
                raise WorkflowError("unknown result handle")
            return self.endpoint.reveal(self._artifacts[handle], destination=destination)

    def provider_turn(self, provider, events, *, tools):
        with self._lock:
            if self._finished is not None:
                raise WorkflowError("workflow has already released its result")
            turn = sum(event["kind"] == "provider_turn" for event in self._events)
            snapshot = json_value(events)
            descriptions = json_value(tools)
            parameters = {
                "run_id": self.run_id,
                "turn": turn,
                "provider": provider.identity,
                "history_sha256": hashlib.sha256(_wire(snapshot).encode()).hexdigest(),
                "tools": descriptions,
            }

            def invoke(_):
                self._events.append(
                    {"kind": "provider_request", "turn": turn, "provider": provider.identity}
                )
                answer = provider.turn(snapshot, descriptions)
                if not isinstance(answer, ProviderTurn):
                    raise WorkflowError("provider must return a normalized turn")
                self._events.append(
                    {
                        "kind": "provider_response",
                        "turn": turn,
                        "provider": provider.identity,
                        "call_ids": [call.id for call in answer.calls],
                    }
                )
                return answer.to_dict()

            artifact = self.endpoint.execute(
                "model.turn",
                self._scope(self._artifacts.values()),
                invoke,
                parameters=parameters,
                destination="model:" + provider.identity,
            )
            self._artifacts[f"turn:{turn}"] = artifact
            answer = ProviderTurn.from_dict(
                self.endpoint.reveal(artifact, destination="workflow:" + self.run_id)
            )
            self._events.append(
                {
                    "kind": "provider_turn",
                    "turn": turn,
                    "provider": provider.identity,
                    "artifact": artifact.to_dict(),
                    "call_ids": [call.id for call in answer.calls],
                }
            )
            return answer, artifact

    def finish(self, value, *, schema, destination):
        with self._lock:
            value, schema_wire = json_value(value), _schema(schema)
            if not Draft202012Validator(json.loads(schema_wire)).is_valid(value):
                raise WorkflowError("workflow result does not satisfy its release schema")
            requested = _wire(
                {"value": value, "schema": json.loads(schema_wire), "destination": destination}
            )
            if self._finished is not None:
                if self._finish_request != requested:
                    raise WorkflowError("workflow result cannot be replaced after release")
                return self._finished
            if any(state.status != "succeeded" for state in self._calls.values()):
                raise WorkflowError("workflow has incomplete or failed tool actions")
            if not self.required_tools <= {state.call.name for state in self._calls.values()}:
                raise WorkflowError("required tools have not completed")
            parameters = {
                "run_id": self.run_id,
                "required_tools": sorted(self.required_tools),
                "calls": [
                    {
                        "call": state.call.to_dict(),
                        "attempt": state.attempt,
                        "artifact": state.completion.artifact.to_dict(),
                    }
                    for state in self._calls.values()
                ],
                "result_schema": json.loads(schema_wire),
            }
            result = self.endpoint.execute(
                "workflow.release",
                self._scope(self._artifacts.values()),
                lambda _: json_value(value),
                parameters=parameters,
                destination=destination,
            )
            self._finished, self._finish_request = result, requested
            self._events.append({"kind": "workflow_released", "artifact": result.to_dict()})
            return result


class ToolRunner:
    """Provider-neutral bounded loop; proposals never directly execute a tool."""

    def __init__(self, provider, *, max_turns=16, format_retries=1):
        _identity(provider.identity, "provider identity")
        if (
            type(max_turns) is not int
            or max_turns < 1
            or type(format_retries) is not int
            or not 0 <= format_retries <= 2
        ):
            raise ValueError("runner requires bounded turns and formatting retries")
        self.provider, self.max_turns, self.format_retries = provider, max_turns, format_retries

    def run(self, workflow, prompt, *, result_schema, destination, model_inputs=()):
        from .tool_providers import load_json

        if type(prompt) is not str:
            raise TypeError("prompt must be ordinary text; governed content needs an input handle")
        schema = json.loads(_schema(result_schema))
        events = [
            {"kind": "user", "text": prompt},
            {
                "kind": "user",
                "text": _wire(
                    {"available_handles": list(workflow.handles), "result_schema": schema}
                ),
            },
        ]
        for handle in model_inputs:
            value = workflow.expose(handle, destination="model:" + self.provider.identity)
            events.append({"kind": "user", "text": _wire({"handle": handle, "value": value})})
        retries, formatting = 0, False
        for _ in range(self.max_turns):
            turn, control = workflow.provider_turn(
                self.provider, events, tools=[] if formatting else workflow.tools.descriptions()
            )
            events.append({"kind": "assistant", "turn": turn.to_dict()})
            if turn.calls:
                if formatting:
                    raise WorkflowError("formatting turn cannot request tools")
                for completion in workflow.execute_many(turn.calls, control=control):
                    result = {
                        "handle": completion.handle,
                        "artifact": completion.artifact.to_dict(),
                    }
                    if workflow.tools[completion.name].model_visible:
                        result["value"] = workflow.expose(
                            completion.handle, destination="model:" + self.provider.identity
                        )
                    events.append(
                        {
                            "kind": "tool",
                            "call_id": completion.call_id,
                            "name": completion.name,
                            "result": result,
                        }
                    )
                continue
            try:
                value = load_json(turn.text)
                if not Draft202012Validator(schema).is_valid(value):
                    raise WorkflowError("provider result does not match the requested schema")
            except (ValueError, TypeError) as exc:
                if retries >= self.format_retries:
                    raise WorkflowError("provider did not return a valid workflow result") from exc
                retries += 1
                formatting = True
                events.append(
                    {
                        "kind": "user",
                        "text": (
                            "Return only JSON satisfying the supplied result schema. "
                            "No tools are available."
                        ),
                    }
                )
                continue
            return workflow.finish(value, schema=schema, destination=destination)
        raise WorkflowError("provider turn limit reached without a released result")
