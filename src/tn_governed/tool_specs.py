"""Tool calls and registered tools: identities, detached JSON arguments, and schemas."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType

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


@dataclass(frozen=True, init=False)
class ToolSpec:
    name: str
    handler: Callable
    operation: str
    result_mode: str
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
        operation="tool.call",
        result_mode="local",
        retryable=False,
        result_admit=None,
        result_validator=None,
    ):
        if type(name) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", name):
            raise ValueError("tool name must be a provider-compatible identifier")
        if not callable(handler):
            raise TypeError("tool registration requires a handler")
        if result_mode not in {"local", "governed"}:
            raise ValueError("tool result mode must be local or governed")
        if type(retryable) is not bool:
            raise TypeError("tool retry setting must be Boolean")
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
            "handler": handler,
            "operation": _identity(operation, "operation"),
            "result_mode": result_mode,
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
