"""Strict provider event adapters for governed tool workflows."""

from __future__ import annotations

import json
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .tool_runtime import Call, ProviderTurn, WorkflowError, _identity, json_value


def load_json(value):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise WorkflowError("JSON contains a duplicate key")
            result[key] = item
        return result

    def constant(_):
        raise WorkflowError("JSON contains a nonfinite number")

    return json_value(json.loads(value, object_pairs_hook=unique, parse_constant=constant))


def _arguments(call_id, name, raw):
    try:
        value = load_json(raw)
        if (
            type(value) is not dict
            or not {"arguments", "inputs"} <= set(value)
            or set(value) - {"arguments", "inputs", "depends_on"}
        ):
            raise WorkflowError("tool request has an invalid argument envelope")
        return Call(call_id, name, value["arguments"], value["inputs"], value.get("depends_on", ()))
    except (TypeError, KeyError, ValueError) as exc:
        raise WorkflowError("provider returned an invalid tool call") from exc


def _function(call):
    return {
        "name": call["name"],
        "arguments": json.dumps(
            {key: call[key] for key in ("arguments", "inputs", "depends_on")}, separators=(",", ":")
        ),
    }


class ChatCompletionsProvider:
    def __init__(self, send, *, model, identity):
        if not callable(send):
            raise TypeError("provider requires a JSON request transport")
        self.send, self.model = send, _identity(model, "model")
        self.identity = _identity(identity, "provider")

    def turn(self, events, tools):
        messages = []
        for event in events:
            if event["kind"] == "user":
                messages.append({"role": "user", "content": event["text"]})
            elif event["kind"] == "assistant":
                turn = ProviderTurn.from_dict(event["turn"])
                message = {"role": "assistant", "content": turn.text}
                if turn.calls:
                    message["tool_calls"] = [
                        {"id": call.id, "type": "function", "function": _function(call.to_dict())}
                        for call in turn.calls
                    ]
                messages.append(message)
            elif event["kind"] == "tool":
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": event["call_id"],
                        "content": json.dumps(event["result"], separators=(",", ":")),
                    }
                )
            else:
                raise WorkflowError("unknown provider conversation event")
        request = {"model": self.model, "messages": messages, "stream": False}
        if tools:
            request["tools"] = [{"type": "function", "function": tool} for tool in tools]
        response = self.send(json_value(request))
        try:
            if type(response) is not dict or len(response["choices"]) != 1:
                raise WorkflowError("provider must return one complete choice")
            choice = response["choices"][0]
            if choice.get("finish_reason") not in {"stop", "tool_calls"}:
                raise WorkflowError("provider response is incomplete or refused")
            message = choice["message"]
            if message.get("refusal"):
                raise WorkflowError("provider refused the request")
            calls = []
            for call in message.get("tool_calls", []):
                if call["type"] != "function":
                    raise WorkflowError("only registered function calls are supported")
                calls.append(
                    _arguments(call["id"], call["function"]["name"], call["function"]["arguments"])
                )
            return ProviderTurn(tuple(calls), None if calls else message.get("content"))
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkflowError("provider returned an invalid completion") from exc


class ResponsesProvider:
    def __init__(self, send, *, model, identity):
        if not callable(send):
            raise TypeError("provider requires a JSON request transport")
        self.send, self.model = send, _identity(model, "model")
        self.identity = _identity(identity, "provider")

    def turn(self, events, tools):
        inputs = []
        for event in events:
            if event["kind"] == "user":
                inputs.append({"role": "user", "content": event["text"]})
            elif event["kind"] == "assistant":
                turn = ProviderTurn.from_dict(event["turn"])
                if turn.calls:
                    inputs.extend(
                        {"type": "function_call", "call_id": call.id, **_function(call.to_dict())}
                        for call in turn.calls
                    )
                else:
                    inputs.append({"role": "assistant", "content": turn.text})
            elif event["kind"] == "tool":
                inputs.append(
                    {
                        "type": "function_call_output",
                        "call_id": event["call_id"],
                        "output": json.dumps(event["result"], separators=(",", ":")),
                    }
                )
            else:
                raise WorkflowError("unknown provider conversation event")
        request = {"model": self.model, "input": inputs, "stream": False, "store": False}
        if tools:
            request["tools"] = [{"type": "function", **tool} for tool in tools]
        response = self.send(json_value(request))
        try:
            if response.get("status", "completed") != "completed" or response.get("error"):
                raise WorkflowError("provider response is incomplete or failed")
            calls, texts = [], []
            for item in response["output"]:
                if item["type"] == "function_call":
                    if item.get("status", "completed") != "completed":
                        raise WorkflowError("provider tool call is incomplete")
                    calls.append(_arguments(item["call_id"], item["name"], item["arguments"]))
                elif item["type"] == "message":
                    if (
                        item.get("role") != "assistant"
                        or item.get("status", "completed") != "completed"
                    ):
                        raise WorkflowError("provider message is incomplete")
                    for content in item["content"]:
                        if content["type"] == "refusal":
                            raise WorkflowError("provider refused the request")
                        if content["type"] != "output_text" or type(content["text"]) is not str:
                            raise WorkflowError("provider output is not terminal text")
                        texts.append(content["text"])
                elif item["type"] != "reasoning":
                    raise WorkflowError("provider returned an unregistered tool event")
            if not calls and not texts:
                raise WorkflowError("provider returned no calls or terminal text")
            return ProviderTurn(tuple(calls), None if calls else "".join(texts))
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkflowError("provider returned an invalid response") from exc


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class JsonHTTPTransport:
    """Single-request JSON HTTP transport; credentials are never redirected."""

    def __init__(self, url, *, headers=None, timeout=60, max_response_bytes=16 * 1024 * 1024):
        parsed = urlparse(url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
        ):
            raise ValueError("provider URL requires HTTP(S) without embedded credentials")
        if timeout <= 0 or type(max_response_bytes) is not int or max_response_bytes < 1:
            raise ValueError("provider transport requires positive limits")
        self.url, self.timeout, self.max_response_bytes = url, timeout, max_response_bytes
        self.headers = {"Content-Type": "application/json", **dict(headers or {})}
        self._opener = build_opener(_NoRedirect())

    def __call__(self, body):
        request = Request(
            self.url,
            data=json.dumps(json_value(body), allow_nan=False).encode(),
            headers=self.headers,
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                payload = response.read(self.max_response_bytes + 1)
                if len(payload) > self.max_response_bytes:
                    raise WorkflowError("provider response exceeds its configured byte limit")
                return load_json(payload)
        except HTTPError as exc:
            raise WorkflowError(f"provider HTTP request failed with status {exc.code}") from None
