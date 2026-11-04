"""Registered tool workflows over independently authorized TN endpoints.

A call carries names and handles, never authority. Each invocation, result
inspection, and release crosses the endpoint's public gate.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from threading import RLock
from uuid import uuid4

from jsonschema import Draft202012Validator

from .tool_specs import (
    Call,
    ToolCompletion,
    ToolInvocation,
    ToolRegistry,
    ToolSpec,
    WorkflowError,
    _identity,
    _schema,
    _wire,
    json_value,
)

__all__ = ["Call", "ToolCompletion", "ToolInvocation", "ToolRegistry", "ToolSpec",
           "ToolWorkflow", "WorkflowError", "json_value"]


@dataclass
class _CallState:
    call: Call
    status: str = "running"
    attempt: int = 1
    completion: ToolCompletion | None = None
    error_type: str | None = None
    binding: str | None = None


class _Invocation:
    """The endpoint callback for one call: it runs the handler on the call's opened inputs."""

    def __init__(self, run_id, call, tool, state, selected, scope, binding, events):
        self.run_id, self.call, self.tool, self.state = run_id, call, tool, state
        self.selected, self.binding, self.events = selected, binding, events
        self.positions = {_wire(artifact.to_dict()): index for index, artifact in enumerate(scope)}
        self.invocations, self.remote = [], []

    def __call__(self, opened):
        values = [opened[self.positions[_wire(artifact.to_dict())]] for artifact in self.selected]
        invocation = ToolInvocation(
            self.run_id,
            self.call.id,
            self.state.attempt,
            self.selected,
            _wire(self.call.arguments),
            _wire(values),
            _wire(self.binding),
        )
        self.invocations.append(invocation)
        self.events.append(
            {
                "kind": "tool_started",
                "call_id": self.call.id,
                "name": self.call.name,
                "attempt": self.state.attempt,
            }
        )
        output = self.tool.handler(invocation)
        if self.tool.result_mode == "governed":
            self.remote.append(output)
            return {"status": "invoked", "tool_call": self.binding}
        return self.tool.validate_output(output, invocation)


class ToolWorkflow:
    """One run's handle namespace, dependency graph, and replay-safe call ledger.

    A run serializes its invocations. Distinct runs/endpoints may operate
    concurrently. A failed action is never retried by the provider loop; explicit
    retry requires a tool registered for idempotent retry with the same key.
    """

    def __init__(self, endpoint, tools, inputs, *, required_tools=(), max_calls=64, run_id=None):
        from .artifact_types import GovernedArtifact

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
            state = self._attempt(call, tool, retry)
            if state.status == "succeeded":
                return state.completion
            try:
                return self._run(call, tool, state, control)
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

    def _attempt(self, call, tool, retry):
        """The call's state for this attempt; a succeeded call's state is returned unchanged."""
        state = self._calls.get(call.id)
        if state is None:
            if len(self._calls) >= self.max_calls:
                raise WorkflowError("workflow call limit exceeded")
            state = self._calls[call.id] = _CallState(call)
            return state
        if state.call != call:
            raise WorkflowError("call ID was reused with different arguments or dependencies")
        if state.status == "succeeded":
            return state
        if not retry or not tool.retryable or state.status != "failed":
            raise WorkflowError("failed or running call cannot be repeated")
        state.attempt += 1
        state.status = "running"
        return state

    def _run(self, call, tool, state, control):
        """Invoke the tool through the endpoint gate over its bound scope and record its result."""
        dependencies = self._dependencies(call)
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
        binding = self._binding(call, tool, selected, dependencies, scope)
        if state.binding is not None and state.binding != _wire(binding):
            raise WorkflowError("retry changed the invocation's bound control inputs or contract")
        state.binding = _wire(binding)
        parameters = {
            "tool_call": binding,
            "attempt": state.attempt,
            "input_schema": tool.input_schema,
            "output_schema": tool.output_schema,
        }
        invocation = _Invocation(self.run_id, call, tool, state, selected, scope, binding, self._events)
        artifact = self.endpoint.execute(
            tool.operation, scope, invocation, parameters=parameters, destination="tool:" + call.name
        )
        if tool.result_mode == "governed":
            artifact = self._admit_remote(tool, invocation, (*scope, artifact), parameters)
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

    def _binding(self, call, tool, selected, dependencies, scope):
        return {
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

    def _admit_remote(self, tool, invocation, scope, parameters):
        """Receive a governed tool's signed remote result and bind it to this invocation."""
        received = self.endpoint.receive(invocation.remote[0])
        metadata = self.endpoint.metadata(received)
        if metadata.get("parameters", {}).get("tool_call") != invocation.binding:
            raise WorkflowError("signed remote tool result belongs to another invocation")
        publication = self.endpoint.store.read(received.reference.object_id)
        if tool.result_admit(publication, metadata) is not True:
            raise WorkflowError(
                "remote result authority or contract is not admitted for this tool"
            )
        result_scope = self._scope([*scope, received])
        result_position = result_scope.index(received)
        return self.endpoint.execute(
            "tool.result",
            result_scope,
            lambda values: tool.validate_output(values[result_position], invocation.invocations[0]),
            parameters=parameters,
            destination="workflow:" + self.run_id,
        )

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


