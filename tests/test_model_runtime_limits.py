"""Model endpoints enforce configured transport and ancestry bounds before submission."""

import json

import pytest
import tn
from test_model_singleton import MODEL, TransportReached, records_since
from test_model_singleton import source_values as source_values
from test_report_review_completion import report_workflow as report_workflow

from tn_governed.values.model import NativeModelEndpoint, prepare_native_model


def test_retained_runtime_limits_keep_defaults_and_configured_bounds():
    from tn_governed.values.model import runtime_limits_from_config

    assert runtime_limits_from_config({}) == {
        "max_request_bytes": 1024 * 1024, "max_message_bytes": 16 * 1024,
        "lineage_max_objects": 1024, "lineage_max_depth": 64,
    }
    assert runtime_limits_from_config({
        "max_request_bytes": 64 * 1024 * 1024,
        "governed_objects": {"lineage_max_objects": 65536, "lineage_max_depth": 256},
    }) == {
        "max_request_bytes": 64 * 1024 * 1024, "max_message_bytes": 16 * 1024,
        "lineage_max_objects": 65536, "lineage_max_depth": 256,
    }


@pytest.mark.parametrize("overrides", [{"unknown": 1}, {"max_request_bytes": 0},
    {"max_message_bytes": True}, {"lineage_max_objects": 65537}, {"lineage_max_depth": 257}])
def test_preparation_rejects_invalid_limits_before_touching_sources(tmp_path, overrides):
    with pytest.raises(ValueError, match="limit"):
        prepare_native_model(None, context=None, input_session=None, output_session=None,
            recipient_session=None, input_config=None, output_config=None, directory=tmp_path,
            model=None, binary=None, runtime_limits=overrides)


@pytest.mark.parametrize("limit", ["max_request_bytes", "max_message_bytes"])
def test_actual_encoded_request_is_checked_before_transport(source_values, tmp_path,
                                                           monkeypatch, limit):
    from tn_llama_client.protocol import build_model_request

    context, (first, _) = source_values
    with context:
        value = first.upper()
    prompt = "Summarize € correctly."
    source = context.store_object(value.reference.object_id)
    use = tn.UseContext(**MODEL["use"])
    request = build_model_request(source, prompt, use, destination=MODEL["report_destination"])
    required = len(request) if limit == "max_request_bytes" else len(prompt.encode("utf-8"))
    calls = []

    def reached(*args, **kwargs):
        calls.append(args)
        raise TransportReached()

    monkeypatch.setattr("tn_governed.values.model.submit_governed_report", reached)
    for maximum in (required - 1, required):
        config = tmp_path / f"runtime-{maximum}.json"
        config.write_text(json.dumps({limit: maximum}), encoding="utf-8")
        endpoint = NativeModelEndpoint(context=context, value=value, base_url="http://unused",
            api_key="test", output_reader=None, directory=tmp_path, requirements=MODEL,
            runtime_config=config)
        before = len(context.recorder.records())
        expected = ValueError if maximum < required else TransportReached
        with context, pytest.raises(expected):
            endpoint.generate(value, prompt=prompt)
        records = records_since(context, before)
        if maximum < required:
            assert calls == []
            assert [record.body["kind"] for record in records] == ["Decision", "Failure"]
        else:
            assert len(calls) == 1


def test_recipient_verification_uses_configured_lineage_limit(report_workflow):
    from tn_llama_client.clients import NativeOutputReader

    original = report_workflow.reader
    release = report_workflow.construct_release()
    for limit in (1, 4096):
        reader = NativeOutputReader(
            original.session, expected_source=original.expected_source,
            expected_writer=original.expected_writer, use=original.use,
            destination=original.destination, release_use=original.release_use,
            catalog=original.catalog, policy_dag=original.policy_dag,
            resolve_ancestor=original.resolve_ancestor, decide=original.decide,
            tool_expectations=tuple(original.tool_expectations.values()),
            required_tools=tuple(original.required_tools), lineage_max_objects=limit,
        )
        if limit == 1:
            with pytest.raises(Exception, match="lineage.*object|object.*limit"):
                reader.open(release)
        else:
            opened = reader.open(release)
            assert "ACME" in opened.get("report_html", group="default")
