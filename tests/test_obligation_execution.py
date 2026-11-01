"""Required actions retain completion evidence before protected operations proceed."""

import pytest
import tn

from tn_governed.publications import PublicationStore
from tn_governed.values import Assessment, EvidenceRecorder, ObligationResult, verify_tape
from tn_governed.values.primitives import VALUE_TYPE
from tn_governed.values.primitives import Context as PrimitiveContext
from tn_governed.values.runtime import Context as StringContext
from tn_governed.values.runtime import Request, publish_source
from tn_governed.values.string import OperationDenied

POLICY = """## experiment.string
### instruction
Preserve governed source strings through authorized transformations.
### use_for
Internal calculation.
### do_not_use_for
Unapproved disclosure.
### consequences
Keep source attribution.
### on_violation_or_error
Stop the operation and record its outcome.

## experiment.primitive
### instruction
Preserve governed values through authorized transformations.
### use_for
Internal calculation.
### do_not_use_for
Unapproved disclosure.
### consequences
Keep source attribution.
### on_violation_or_error
Stop the operation and record its outcome.

## experiment.evidence
### instruction
Record endpoint decisions and required action outcomes.
### use_for
Inspection by enrolled readers.
### do_not_use_for
Changing the author of a retained statement.
### consequences
Retain reported completion evidence.
### on_violation_or_error
Refuse unverifiable evidence.
"""


@pytest.fixture(params=["string", "primitive"])
def endpoint(request, tmp_path):
    with tn.Session(POLICY, groups=["strings", "values", "evidence"]) as session:
        store = PublicationStore(tmp_path / "publications")
        recorder = EvidenceRecorder(session, store, session.policy("experiment.evidence"))
        primitive = request.param == "primitive"
        object_type = VALUE_TYPE if primitive else "experiment.string"
        policy = session.policy(object_type)

        def admit(ctx):
            return (ctx.writer == session.did and ctx.object_type == object_type
                    and ctx.governance.matches_contract(policy))

        options = {"actor": "reader"} if primitive else {}
        context = (PrimitiveContext if primitive else StringContext)(
            session, recorder, lambda _: Assessment(True, "authorized"),
            application="analytics", purpose="internal", metadata_accept=admit, **options)
        if primitive:
            source_request = Request("analytics", "internal", "select", (), (), (policy,), ())
            decision = context._decision(source_request, "source")
            value = context.originate(
                "Ada", policy, source={"table": "people", "column": "name"},
                request=source_request, decision_id=decision, call_id="source")
        else:
            value = publish_source(session, store, {"name": "Ada"})["name"]
        yield context, value


def decision_details(context):
    records = verify_tape(
        context.recorder.records(), session=context.session,
        expected_writer=context.session.did, expected_head=context.recorder.head,
        expected_context=context.recorder.context_id, policy=context.recorder.policy)
    return next(record.body["details"] for record in reversed(records)
                if record.body["kind"] == "Decision")


def forbid_plaintext(context, monkeypatch):
    def opening(*args):
        pytest.fail("a failed required action must prevent business content opening")
    monkeypatch.setattr(context, "_open_values", opening)


def test_later_handler_exception_retains_evidence_and_failing_action(endpoint, monkeypatch):
    context, value = endpoint
    error = RuntimeError("untrusted handler detail")
    calls = []

    def completed(request):
        calls.append("record")
        return ObligationResult(True, "ledger:entry-17")

    def failed(request):
        calls.append("queue")
        raise error

    context.evaluator = lambda _: Assessment(True, "conditional", ("record", "queue", "later"))
    context.obligations.update(record=completed, queue=failed,
                               later=lambda _: calls.append("later"))
    forbid_plaintext(context, monkeypatch)
    with context, pytest.raises(OperationDenied) as caught:
        value.upper()
    details = decision_details(context)
    assert calls == ["record", "queue"]
    assert details["discharged"] == [
        {"obligation": "record", "satisfied": True, "evidence": "ledger:entry-17"},
        {"obligation": "queue", "satisfied": False, "evidence": None},
    ]
    assert details["failed_obligation"] == "queue"
    assert details["error_type"] == "RuntimeError"
    assert details["permitted"] is False
    assert caught.value.__cause__ is error
    assert "untrusted handler detail" not in repr(details)


@pytest.mark.parametrize("evidence", [None, "", "  ", 1, True, ["record"]])
def test_completion_requires_a_nonempty_evidence_reference(endpoint, monkeypatch, evidence):
    context, value = endpoint
    context.evaluator = lambda _: Assessment(True, "conditional", ("record",))
    context.obligations["record"] = lambda _: ObligationResult(True, evidence)
    forbid_plaintext(context, monkeypatch)
    with context, pytest.raises(OperationDenied):
        value.upper()
    details = decision_details(context)
    assert details["failed_obligation"] == "record"
    assert details["discharged"] == [
        {"obligation": "record", "satisfied": False, "evidence": None}]


@pytest.mark.parametrize("result", [
    None, True, {"satisfied": True, "evidence": "record"},
    ObligationResult(1, "record"), ObligationResult(False, "record"),
])
def test_invalid_completion_status_stops_the_operation(endpoint, monkeypatch, result):
    context, value = endpoint
    context.evaluator = lambda _: Assessment(True, "conditional", ("record",))
    context.obligations["record"] = lambda _: result
    forbid_plaintext(context, monkeypatch)
    with context, pytest.raises(OperationDenied):
        value.upper()
    assert decision_details(context)["failed_obligation"] == "record"


def test_missing_handler_is_recorded_as_an_incomplete_action(endpoint, monkeypatch):
    context, value = endpoint
    context.evaluator = lambda _: Assessment(True, "conditional", ("absent",))
    forbid_plaintext(context, monkeypatch)
    with context, pytest.raises(OperationDenied):
        value.upper()
    details = decision_details(context)
    assert details["failed_obligation"] == "absent"
    assert details["discharged"] == [
        {"obligation": "absent", "satisfied": False, "evidence": None}]


def test_handler_lookup_failure_retains_completed_actions(endpoint, monkeypatch):
    context, value = endpoint
    error = RuntimeError("handler registry unavailable")

    class Registry(dict):
        def get(self, name, default=None):
            if name == "queue":
                raise error
            return super().get(name, default)

    context.obligations = Registry(record=lambda _: ObligationResult(True, "ledger:17"))
    context.evaluator = lambda _: Assessment(True, "conditional", ("record", "queue"))
    forbid_plaintext(context, monkeypatch)
    with context, pytest.raises(OperationDenied) as caught:
        value.upper()
    details = decision_details(context)
    assert details["discharged"] == [
        {"obligation": "record", "satisfied": True, "evidence": "ledger:17"},
        {"obligation": "queue", "satisfied": False, "evidence": None},
    ]
    assert details["failed_obligation"] == "queue"
    assert caught.value.__cause__ is error


def test_completion_validation_failure_retains_completed_actions(endpoint, monkeypatch):
    context, value = endpoint
    error = RuntimeError("completion evidence could not be validated")

    class Evidence(str):
        def strip(self, *_args, **_kwargs):
            raise error

    context.obligations.update(
        record=lambda _: ObligationResult(True, "ledger:17"),
        queue=lambda _: ObligationResult(True, Evidence("queue:19")))
    context.evaluator = lambda _: Assessment(True, "conditional", ("record", "queue"))
    forbid_plaintext(context, monkeypatch)
    with context, pytest.raises(OperationDenied) as caught:
        value.upper()
    details = decision_details(context)
    assert details["discharged"][0]["evidence"] == "ledger:17"
    assert details["failed_obligation"] == "queue"
    assert caught.value.__cause__ is error


@pytest.mark.parametrize("names", [("record", ""), ("record", 1), ("record", "  ")])
def test_action_names_are_validated_before_any_handler_runs(endpoint, monkeypatch, names):
    context, value = endpoint
    calls = []
    context.evaluator = lambda _: Assessment(True, "conditional", names)
    context.obligations["record"] = lambda _: calls.append("record")
    forbid_plaintext(context, monkeypatch)
    with context, pytest.raises(OperationDenied):
        value.upper()
    assert calls == []


def test_all_required_actions_complete_before_a_durable_permit_and_plaintext(endpoint, monkeypatch):
    context, value = endpoint
    calls = []
    context.evaluator = lambda _: Assessment(True, "conditional", ("record", "queue"))

    def completed(name):
        def run(request):
            calls.append(name)
            return ObligationResult(True, "evidence:" + name)
        return run

    context.obligations.update(record=completed("record"), queue=completed("queue"))
    opening = context._open_values

    def checked_open(*args):
        assert calls == ["record", "queue"]
        details = decision_details(context)
        assert details["permitted"] is True
        assert [entry["evidence"] for entry in details["discharged"]] == [
            "evidence:record", "evidence:queue"]
        return opening(*args)

    monkeypatch.setattr(context, "_open_values", checked_open)
    with context:
        output = value.upper()
    assert output.reference.object_id != value.reference.object_id
