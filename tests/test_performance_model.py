import importlib.util

import pytest


def module():
    assert importlib.util.find_spec("experiments.paper_evaluation.performance_model") is not None
    from experiments.paper_evaluation import performance_model

    return performance_model


def test_plain_model_request_uses_business_input_and_bounded_deterministic_generation():
    model = module()
    body = model.plain_request("ACME: 1234 demonstration cents")
    assert body["temperature"] == 0
    assert body["max_tokens"] == 2048
    assert body["cache_prompt"] is False
    assert body["reasoning_effort"] == "none"
    assert "ACME: 1234 demonstration cents" in body["messages"][-1]["content"]
    assert "tools" not in body


def test_plain_response_rejects_truncation_empty_or_tool_outputs():
    model = module()
    for choice in (
        {"finish_reason": "length", "message": {"content": "<p>partial</p>"}},
        {"finish_reason": "stop", "message": {"content": ""}},
        {"finish_reason": "tool_calls", "message": {"tool_calls": [{}]}},
    ):
        with pytest.raises(ValueError):
            model.response_html({"choices": [choice]})
    assert (
        model.response_html(
            {"choices": [{"finish_reason": "stop", "message": {"content": "<p>report</p>"}}]}
        )
        == "<p>report</p>"
    )
