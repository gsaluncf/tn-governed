"""Archive hydration and required-action receipts remain attached to values."""

import pytest
import tn
from test_carried_values import _context, _originate
from test_carried_values import enrolled as enrolled

from tn_governed.native_objects import NativeObjects
from tn_governed.values.runtime import Assessment, ObligationResult


@pytest.mark.parametrize("count", [3, 6])
def test_received_handle_rejects_missing_or_extra_fields(enrolled, count):
    sessions, policy, audit = enrolled
    context = _context(sessions["producer"], policy, audit, {sessions["producer"].did})
    with pytest.raises(ValueError, match="received handles"):
        context.hydrate_many([(None,) * count])


def test_hydrated_handle_keeps_the_signed_claim_after_the_archive_context_is_gone(enrolled, tmp_path):
    sessions, policy, audit = enrolled
    writers = {session.did for session in sessions.values()}
    producer = _context(sessions["producer"], policy, audit, writers)
    source = _originate(producer, (7,), policy)[0]
    with producer:
        claimed = source.attest("Estimated amount", producer)
        supplied = claimed + 2
    unrelated = _originate(producer, (99,), policy)[0]
    archive = producer.recorder.store.export(tmp_path / "archive")
    receiver = _context(sessions["recipient"], policy, audit, writers)
    receiver.recorder.store = NativeObjects.from_archive(archive)
    received = receiver.hydrate(
        supplied.reference, supplied.decision_id, supplied.result_id, kind="int"
    )
    assert received.publication is not None
    carried = {obj.id for obj in received.publication.objects()}
    assert carried.isdisjoint({unrelated.reference.object_id, source.reference.object_id, claimed.reference.object_id})
    with receiver:
        result = received + 1
    producer.recorder.store = NativeObjects()
    receiver.recorder.store = NativeObjects()
    with tn.Session.from_config(str(tmp_path / "sessions" / "producer" / "tn.yaml")) as session:
        consumer = _context(session, policy, audit, writers)
        assert result.reveal(consumer, destination="internal") == 10
        assert consumer.inspect(result).claims[0].statement == "Estimated amount"


def test_completed_required_action_native_receipt_travels_with_the_result(enrolled):
    sessions, policy, audit = enrolled
    writers = {session.did for session in sessions.values()}
    producer = _context(sessions["producer"], policy, audit, writers)
    source = _originate(producer, (7,), policy)[0]
    producer.evaluator = lambda _: Assessment(True, "registration required", ("register",))
    receipts = []

    def register(request):
        receipt = producer._append("Observation", request, "registration", {"complete": True})
        receipts.append(receipt)
        return ObligationResult(True, receipt)

    producer.obligations["register"] = register
    with producer:
        result = source + 1
    assert result.publication.resolve(receipts[0]).id == receipts[0]
    producer.recorder.store = NativeObjects()
    consumer = _context(sessions["recipient"], policy, audit, writers)
    assert result.reveal(consumer, destination="internal") == 8
    assert consumer.recorder.read(receipts[0]).body["details"]["complete"] is True
