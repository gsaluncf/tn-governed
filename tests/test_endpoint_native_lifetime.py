"""Endpoint values share native ancestry and admit transfers as one bounded batch."""

import pytest
import tn
from test_native_objects import POLICY

from tn_governed.endpoints import Endpoint
from tn_governed.native_objects import CarriedPublication
from tn_governed.values.runtime import Assessment, ObligationResult


@pytest.fixture
def endpoints():
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        def endpoint():
            return Endpoint(
                session=session,
                evidence_policy=session.policy("experiment.evidence"),
                evaluator=lambda _: Assessment(True, "local calculation"),
                application="calculation",
                purpose="internal",
                accept_metadata=lambda ctx: ctx.writer == session.did,
            )

        yield endpoint, session.policy("finance.account")


def test_unrelated_origins_do_not_accumulate_the_endpoint_record_tape(endpoints):
    endpoint, policy = endpoints
    source = endpoint()
    values = [source.originate(index, policies=(policy,)) for index in range(5)]
    closures = [{obj.id for obj in value.carrier.objects()} for value in values]
    assert len({len(closure) for closure in closures}) == 1
    for index, closure in enumerate(closures):
        assert all(
            earlier.reference.object_id not in closure for earlier in values[:index]
        )
        assert endpoint().reveal(values[index], destination="internal") == index


def test_derived_carriers_share_parents_without_flattening_their_graph(endpoints, monkeypatch):
    endpoint, policy = endpoints
    source = endpoint()
    value = source.originate(1, policies=(policy,))
    local_sizes = []

    def do_not_flatten(_):
        pytest.fail("value construction flattened an existing parent carrier")

    with monkeypatch.context() as patch:
        patch.setattr(CarriedPublication, "objects", do_not_flatten)
        for _ in range(5):
            parent = value
            value = source.execute("increment", (parent,), lambda values: values[0] + 1)
            assert value.carrier.parents == (parent.carrier,)
            local_sizes.append(len(value.carrier.support))
    assert len(set(local_sizes)) == 1
    assert endpoint().reveal(value, destination="internal") == 6


def test_receive_many_rejects_incomplete_batch_before_adopting_any_value(endpoints):
    endpoint, policy = endpoints
    source, recipient = endpoint(), endpoint()
    first = source.originate(1, policies=(policy,))
    second = source.originate(2, policies=(policy,))
    objects = {
        obj.id: obj.forward()
        for value in (first, second)
        for obj in value.carrier.objects()
    }
    del objects[second.reference.object_id]
    with pytest.raises(FileNotFoundError):
        recipient.receive_many((first, second), publications=tuple(objects.values()))
    assert recipient.store.publication_sizes() == {}


def test_receive_many_does_not_fill_missing_wire_from_a_retained_value(endpoints):
    endpoint, policy = endpoints
    source, recipient = endpoint(), endpoint()
    value = source.originate(7, policies=(policy,))
    assert recipient.reveal(value, destination="internal") == 7
    bundle = source.export(value)
    missing = source.session.governance(value.carrier.object).governance.sources[0].object_id
    wires = tuple(
        wire for wire in bundle.publications if tn.GovernedObject.parse(wire).id != missing
    )
    with pytest.raises(FileNotFoundError):
        recipient.receive_many((value,), publications=wires)


def test_required_action_observations_travel_without_unrelated_tape_records(endpoints):
    endpoint, policy = endpoints
    source = endpoint()
    unrelated = source.originate(0, policies=(policy,))
    source.evaluator = lambda _: Assessment(True, "action required", ("receipt",))
    source.obligations["receipt"] = lambda _: ObligationResult(True, "receipt:completed")
    value = source.originate(7, policies=(policy,))
    decision = source.read_record(value.decision_id)
    progress = decision.body["details"]["action_progress"]
    carried = {obj.id for obj in value.carrier.objects()}
    assert progress and set(progress) <= carried
    assert unrelated.decision_id not in carried
    recipient = endpoint()
    arrived = recipient.receive(source.export(value))
    assert recipient.reveal(arrived, destination="internal") == 7
    assert recipient.read_record(progress[0]).body["details"]["evidence"] == "receipt:completed"
