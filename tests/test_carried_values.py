"""Governed values carry native publications across ordinary in-memory operations."""

import builtins
import io
import sqlite3
from contextlib import ExitStack, contextmanager

import pytest
import tn
from tn.governed import NotEntitled

from tn_governed.native_objects import CarriedPublication
from tn_governed.publications import PublicationStore
from tn_governed.sqlite_publications import SQLitePublicationStore
from tn_governed.values.evidence import EvidenceError, EvidenceRecorder
from tn_governed.values.numeric import TNNumeric
from tn_governed.values.primitives import VALUE_TYPE, Context
from tn_governed.values.provision import provision
from tn_governed.values.runtime import Assessment, ObligationResult, Request
from tn_governed.values.string import OperationDenied, TNString

POLICY = """## experiment.primitive
### instruction
Preserve source attribution through authorized calculations.
### use_for
Internal analysis and explicit internal display.
### do_not_use_for
Disclosure to an unapproved destination.
### consequences
Retain each source claim and its issuer.
### on_violation_or_error
Stop the operation and retain its decision.

## experiment.evidence
### instruction
Attributed operation records for enrolled readers.
### use_for
Inspect the decisions and contributions carried with a value.
### do_not_use_for
Accepting another endpoint's claims without local evaluation.
### consequences
Each endpoint evaluates the requested use.
### on_violation_or_error
Refuse invalid evidence.
"""


def _context(session, policy, audit_policy, writers, *, actor="analyst"):
    return Context(
        session,
        EvidenceRecorder(session, policy=audit_policy),
        lambda request: Assessment(
            request.operation != "reveal" or request.destination == "internal",
            "requested internal use",
            obligations=("monitor",),
        ),
        application="analysis",
        purpose="internal",
        actor=actor,
        metadata_accept=lambda ctx: (
            ctx.writer in writers
            and ctx.object_type == VALUE_TYPE
            and len(ctx.policies) == 1
            and ctx.governance.matches_contract(policy)
        ),
    )


def _source(row):
    return {
        "table": "observations",
        "column": "amount",
        "row": row,
        "query_id": "observation-query",
        "assignment_id": "observation-assignment",
        "snapshot_sha256": "a" * 64,
    }


def _originate(context, contents, policy):
    request = Request(context.application, context.purpose, "select", (), (), (policy,), ())
    decision = context._decision(request, "observation-query")
    return context.originate_batch(
        tuple((content, _source(row)) for row, content in enumerate(contents)),
        policy,
        request=request,
        decision_id=decision,
        call_id="observation-query",
    )


@contextmanager
def _without_persistence(monkeypatch):
    def unexpected_io(*args, **kwargs):
        raise AssertionError("governed computation attempted persistent I/O")

    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, "connect", unexpected_io)
        patch.setattr(builtins, "open", unexpected_io)
        patch.setattr(io, "open", unexpected_io)
        for cls in (PublicationStore, SQLitePublicationStore):
            for method in ("put", "put_record", "get", "read", "record_ids"):
                patch.setattr(cls, method, unexpected_io)
        yield


def test_numeric_operations_carry_native_objects_without_persistence(monkeypatch):
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        policy = session.policy(VALUE_TYPE)
        with _without_persistence(monkeypatch):
            context = _context(
                session, policy, session.policy("experiment.evidence"), {session.did}
            )
            left, right = _originate(context, (7, 11), policy)
            with context:
                result = (left + right) * 3
            actual = result.reveal(context, destination="internal")
            _, binding, _ = context._metadata(result)
            publication = result.publication.object
        assert actual == 54
        assert isinstance(result, TNNumeric)
        assert isinstance(publication, tn.GovernedObject)
        assert publication.id == result.reference.object_id
        assert "origins" not in binding


def test_string_operations_preserve_claims_without_persistence(monkeypatch):
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        policy = session.policy(VALUE_TYPE)
        with _without_persistence(monkeypatch):
            context = _context(
                session, policy, session.policy("experiment.evidence"), {session.did}
            )
            first, second = _originate(context, ("Ada", "Lovelace"), policy)
            with context:
                claimed = first.attest("Approved spelling", context)
                result = claimed.upper() + " " + second
            actual = result.reveal(context, destination="internal")
            _, binding, claims = context._metadata(result)
        assert actual == "ADA Lovelace"
        assert isinstance(result, TNString)
        assert len(claims) == 1
        assert claims[0].issuer == session.did
        assert claims[0].subjects == (first.reference,)
        assert claims[0].statement == "Approved spelling"
        assert "origins" not in binding


@pytest.fixture
def enrolled(tmp_path):
    roles = ("producer", "recipient", "metadata_only")
    paths = provision(tmp_path / "sessions", roles=roles, read_only_roles=())
    primitive_policy = POLICY.split("## experiment.evidence", 1)[0]
    for path in paths.values():
        policy_file = path.parent / ".tn" / "config" / "agents.md"
        with policy_file.open("a", encoding="utf-8") as output:
            output.write("\n" + primitive_policy)
    with ExitStack() as stack:
        sessions = {
            role: stack.enter_context(tn.Session.from_config(str(path)))
            for role, path in paths.items()
        }
        policy = sessions["producer"].policy(VALUE_TYPE)
        audit = sessions["producer"].policy("experiment.evidence")
        yield sessions, policy, audit


def test_fresh_receiver_uses_carried_claims_after_producer_session_closes(enrolled, monkeypatch):
    sessions, policy, audit = enrolled
    writers = {session.did for session in sessions.values()}
    producer = _context(sessions["producer"], policy, audit, writers, actor="producer")
    issuer = producer.session.did
    with _without_persistence(monkeypatch):
        first, second = _originate(producer, (7, 11), policy)
        with producer:
            claimed = first.attest("Estimated amount", producer)
            supplied = claimed + second
        producer.session.close()

        def producer_lookup(*args, **kwargs):
            raise AssertionError("recipient attempted a producer-context lookup")

        monkeypatch.setattr(producer, "store_object", producer_lookup)
        monkeypatch.setattr(producer.recorder, "read", producer_lookup)
        receiver = _context(sessions["recipient"], policy, audit, writers, actor="recipient")
        with receiver:
            result = supplied * 2
        actual = result.reveal(receiver, destination="internal")
        _, binding, claims = receiver._metadata(result)
        decision = receiver.recorder.read(binding["actions"][-1])
    assert actual == 36
    assert "parents" not in binding
    assert "origins" not in binding
    assert claims[0].issuer == issuer
    assert claims[0].subjects == (first.reference,)
    assert claims[0].statement == "Estimated amount"
    assert decision.writer == sessions["recipient"].did
    assert decision.writer != issuer


def test_receiver_denial_precedes_opening_carried_values(enrolled, monkeypatch):
    sessions, policy, audit = enrolled
    writers = {session.did for session in sessions.values()}
    with _without_persistence(monkeypatch):
        producer = _context(sessions["producer"], policy, audit, writers)
        supplied = _originate(producer, (7,), policy)[0]
        receiver = _context(sessions["recipient"], policy, audit, writers)
        receiver.evaluator = lambda request: Assessment(False, "purpose refused")
        opened = []
        monkeypatch.setattr(receiver, "_open_values", lambda *args: opened.append(args))
        with receiver, pytest.raises(OperationDenied):
            supplied + 1
        refusal = receiver.recorder.read(receiver.recorder.head)
    assert opened == []
    assert refusal.writer == sessions["recipient"].did
    assert refusal.body["kind"] == "Refusal"


def test_carried_object_does_not_supply_missing_decryption_keys(enrolled, monkeypatch):
    sessions, policy, audit = enrolled
    writers = {session.did for session in sessions.values()}
    with _without_persistence(monkeypatch):
        producer = _context(sessions["producer"], policy, audit, writers)
        supplied = _originate(producer, (7,), policy)[0]
        receiver = _context(sessions["metadata_only"], policy, audit, writers)
        _, binding, _ = receiver._metadata(supplied)
        with receiver, pytest.raises(NotEntitled):
            supplied + 1
        with pytest.raises(NotEntitled):
            supplied.reveal(receiver, destination="internal")
    assert supplied.reference.field == "value_0" and "source" not in binding


@pytest.mark.parametrize("contents", [("Ada", "Grace"), (7, 11)])
def test_carried_publication_does_not_authorize_a_forged_field_citation(monkeypatch, contents):
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        policy = session.policy(VALUE_TYPE)
        with _without_persistence(monkeypatch):
            context = _context(
                session, policy, session.policy("experiment.evidence"), {session.did}
            )
            first = _originate(context, contents[:1], policy)[0]
            second = _originate(context, contents[1:], policy)[0]
            forged = type(first)(
                second.reference,
                second.decision_id,
                first.reference.object_id,
                metadata_provider=context.string_metadata,
                publication=second.publication,
            )
            with pytest.raises(EvidenceError):
                context._metadata(forged)


def test_carried_branches_keep_source_and_sibling_state(monkeypatch):
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        policy = session.policy(VALUE_TYPE)
        with _without_persistence(monkeypatch):
            context = _context(
                session, policy, session.policy("experiment.evidence"), {session.did}
            )
            first, sibling = _originate(context, (7, 818181), policy)
            source_wire = first.publication.object.forward()
            with context:
                left = first + 1
                right = first * 3
            actual = [
                value.reveal(context, destination="internal")
                for value in (first, sibling, left, right)
            ]
            left_data = context._read(left, ["values", "evidence"], "reveal")
            payload = left_data.get(None, group="values")
            retained_source_wire = first.publication.object.forward()
            with pytest.raises(AttributeError):
                first.publication = left.publication
        assert actual == [7, 818181, 8, 21]
        assert source_wire == retained_source_wire
        assert payload == {"value": "8"}
        assert left.reference.object_id != right.reference.object_id


def _transport(value, *, omit=()):
    objects = tuple(
        tn.GovernedObject.parse(publication.forward())
        for publication in value.publication.objects()
        if publication.id not in omit
    )
    root = next(obj for obj in objects if obj.id == value.reference.object_id)
    carried = CarriedPublication(root, support=tuple(obj for obj in objects if obj.id != root.id))
    return type(value)(
        value.reference,
        value.decision_id,
        value.result_id,
        publication=carried,
    )


def test_serialized_native_objects_supply_claims_without_arithmetic_inputs(
    enrolled, monkeypatch
):
    sessions, policy, audit = enrolled
    writers = {session.did for session in sessions.values()}
    with _without_persistence(monkeypatch):
        producer = _context(sessions["producer"], policy, audit, writers)
        first, second = _originate(producer, (7, 11), policy)
        with producer:
            claimed = first.attest("Estimated amount", producer)
            supplied = claimed + second
        received = _transport(supplied)
        receiver = _context(sessions["recipient"], policy, audit, writers)
        with receiver:
            result = received + 1
        actual = result.reveal(receiver, destination="internal")
        _, binding, claims = receiver._metadata(result)
    assert actual == 19
    carried_ids = {obj.id for obj in received.publication.objects()}
    assert carried_ids.isdisjoint({first.reference.object_id, second.reference.object_id, claimed.reference.object_id})
    assert received.publication.object is not supplied.publication.object
    assert received.metadata_provider is None
    assert "origins" not in binding
    assert claims[0].issuer == sessions["producer"].did
    assert claims[0].subjects == (first.reference,)
    assert claims[0].statement == "Estimated amount"


@pytest.mark.parametrize("missing", ["decision", "action", "claim"])
def test_incomplete_native_handoff_is_refused_before_computation(enrolled, monkeypatch, missing):
    sessions, policy, audit = enrolled
    writers = {session.did for session in sessions.values()}
    with _without_persistence(monkeypatch):
        producer = _context(sessions["producer"], policy, audit, writers)
        source = _originate(producer, (7,), policy)[0]
        with producer:
            claimed = source.attest("Estimated amount", producer)
            supplied = claimed + 1
        _, binding, claims = producer._metadata(supplied)
        decision = producer.recorder.read(binding["actions"][-1])
        missing_id = {
            "decision": decision.id,
            "action": decision.body["details"]["discharged"][0]["evidence"],
            "claim": claims[0].id,
        }[missing]
        received = _transport(supplied, omit=(missing_id,))
        receiver = _context(sessions["recipient"], policy, audit, writers)
        opened = []
        open_values = receiver._open_values

        def observe_open(*args):
            opened.append(args)
            return open_values(*args)

        monkeypatch.setattr(receiver, "_open_values", observe_open)
        with receiver, pytest.raises(OperationDenied, match="input admission failed"):
            received + 1
    assert opened == []


def test_required_action_failure_retains_completed_evidence_in_memory(monkeypatch):
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        policy = session.policy(VALUE_TYPE)
        with _without_persistence(monkeypatch):
            context = _context(
                session, policy, session.policy("experiment.evidence"), {session.did}
            )
            source = _originate(context, (7,), policy)[0]
            context.evaluator = lambda request: Assessment(
                True, "requires action completion", obligations=("register", "review")
            )
            receipts = []

            def register(request):
                receipt = context._append(
                    "Observation", request, "registration", {"completed_action": "register"}
                )
                receipts.append(receipt)
                return ObligationResult(True, receipt)

            def review(request):
                raise RuntimeError("review endpoint unavailable")

            context.obligations.update(register=register, review=review)
            opened = []
            monkeypatch.setattr(context, "_open_values", lambda *args: opened.append(args))
            with context, pytest.raises(OperationDenied):
                source + 1
            refusal = context.recorder.read(context.recorder.head)
            decision = context.recorder.read(refusal.body["details"]["decision_id"])
            receipt = context.recorder.read(receipts[0])
        assert opened == []
        assert receipt.body["details"]["completed_action"] == "register"
        assert decision.body["details"]["permitted"] is False
        assert decision.body["details"]["failed_obligation"] == "review"
        assert decision.body["details"]["discharged"] == [
            {"obligation": "register", "satisfied": True, "evidence": receipt.id},
            {"obligation": "review", "satisfied": False, "evidence": None},
        ]
        assert refusal.body["kind"] == "Refusal"


def test_arithmetic_without_obligations_carries_only_the_signed_value(enrolled):
    sessions, policy, audit = enrolled
    writers = {session.did for session in sessions.values()}
    producer = _context(sessions["producer"], policy, audit, writers)
    producer.evaluator = lambda request: Assessment(True, "internal use")
    left, right = _originate(producer, (4, 7), policy)
    recorded = producer.recorder.ids()
    with producer:
        intermediate = left * 3
        output = intermediate + right
    assert producer.recorder.ids() == recorded
    assert output.decision_id is None and output.result_id is None
    assert list(output.publication.objects()) == [output.publication.object]
    assert not producer.session.governance(output.publication.object).governance.sources
    assert set(producer._metadata(output)[1]) == {"declared", "claims", "actions"}
    receiver = _context(sessions["recipient"], policy, audit, writers)
    assert _transport(output).reveal(receiver, destination="internal") == 19


def test_two_policy_result_admitted_without_either_source(enrolled):
    sessions, public, audit = enrolled
    writers = {session.did for session in sessions.values()}
    restricted = tn.Governance.from_markdown(
        sessions["producer"].did, POLICY.replace("Internal analysis", "Research use"),
        "research-policy", VALUE_TYPE)
    policies = (public, restricted)

    def admits(accepted):
        return lambda ctx: (ctx.object_type == VALUE_TYPE and ctx.writer in writers and
                            all(any(p.matches_contract(q) for q in accepted) for p in ctx.policies))

    producer = _context(sessions["producer"], public, audit, writers)
    producer.evaluator = lambda _: Assessment(True, "internal calculation")
    producer.metadata_accept = admits(policies)
    first = _originate(producer, [10], public)[0]
    second = _originate(producer, [12], restricted)[0]
    with producer:
        total = (first + second) + first
    received = _transport(total)
    assert len(tuple(received.publication.objects())) == 1
    consumer = _context(sessions["recipient"], public, audit, writers)
    consumer.metadata_accept = admits((public,))
    with pytest.raises(OperationDenied):
        received.reveal(consumer, destination="internal")
    consumer.metadata_accept = admits(policies)
    result_policies = consumer.inspect(received).policies
    assert len(result_policies) == 2
    assert all(any(source.matches_contract(p) for p in result_policies) for source in policies)
    assert received.reveal(consumer, destination="internal") == 32
