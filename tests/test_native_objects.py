"""Native values retain their publications independently of endpoint storage."""

import sqlite3

import pytest
import tn

from tn_governed.endpoints import ArtifactBundle, Endpoint
from tn_governed.native_objects import CarriedPublication, NativeObjects
from tn_governed.values.runtime import Assessment

POLICY = """## finance.account
### instruction
Retain source attribution.
### use_for
Internal calculation.
### do_not_use_for
Unapproved disclosure.
### consequences
Review.
### on_violation_or_error
Refuse.

## experiment.evidence
### instruction
Retain attributed records.
### use_for
Verify authorized operations.
### do_not_use_for
Unapproved disclosure.
### consequences
Review.
### on_violation_or_error
Refuse.
"""


def test_carrier_keeps_native_dependencies_after_collection_lifetime():
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        native = session.create({"value": 3}, session.policy("finance.account"), group="values")
        origin = native.snapshot
        publication = session.release(
            native,
            use=tn.UseContext("test", "internal", "publish"),
            to="recipient",
            decide=lambda _: True,
        )
        with NativeObjects() as objects:
            objects.put(origin)
            objects.put(publication)
            objects.link(publication.id, origin.id)
            carried = objects.carry(publication.id)
            assert carried.object is publication
        assert carried.resolve(origin.id) is origin
        receiver = NativeObjects()
        receiver.include(carried)
        assert receiver.read(publication.id) is publication
        assert receiver.read(origin.id) is origin


def test_carrier_shares_parent_objects_and_rejects_missing_dependency():
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        one = session.create(
            {"value": 1}, session.policy("finance.account"), group="values"
        ).snapshot
        two = session.create(
            {"value": 2}, session.policy("finance.account"), group="values"
        ).snapshot
        parent = CarriedPublication(one)
        child = CarriedPublication(two, parents=(parent, parent))
        assert tuple(child.objects()) == (two, one)
        objects = NativeObjects()
        objects.put(two)
        objects.link(two.id, "sha256:" + "0" * 64)
        with pytest.raises(FileNotFoundError):
            objects.carry(two.id)


def test_successor_carriers_share_ancestry_without_copying_it_into_local_support():
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        objects = NativeObjects()
        publications = [
            session.create(
                {"value": index}, session.policy("finance.account"), group="values"
            ).snapshot
            for index in range(8)
        ]
        objects.put(publications[0])
        carried = objects.carry(publications[0].id)
        for obj in publications[1:]:
            objects.put(obj)
            objects.link(obj.id, carried.object.id)
            parent = carried
            carried = objects.carry(obj.id, parents=(parent,))
            assert carried.parents == (parent,)
            assert carried.support == ()
        assert {obj.id for obj in carried.objects()} == {obj.id for obj in publications}


def test_native_archive_is_an_explicit_serialization_boundary(tmp_path):
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        obj = session.create(
            {"value": 7}, session.policy("finance.account"), group="values"
        ).snapshot
        objects = NativeObjects()
        objects.put(obj)
        assert list(tmp_path.iterdir()) == []
        archive = objects.export(tmp_path / "archive")
        restored = NativeObjects.from_archive(archive)
        assert restored.read(obj.id).forward() == obj.forward()


@pytest.mark.parametrize("backend", ["files", "sqlite"])
def test_archive_import_preserves_record_contexts_and_sequences(tmp_path, backend):
    from tn_governed.publications import open_publication_store

    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        data = session.create({"value": 7}, session.policy("finance.account"), group="values")
        snapshot = data.snapshot
        publication = session.release(
            data,
            use=tn.UseContext("test", "internal", "publish"),
            to="recipient",
            decide=lambda _: True,
        )
        with open_publication_store(tmp_path / "input", backend=backend) as archive:
            archive.put_record(snapshot, publication, context_id="context", sequence=1)
        with open_publication_store(tmp_path / "input", read_only=True) as archive:
            native = NativeObjects.from_archive(archive)
        assert native.record_ids("context") == (publication.id,)
        exported = native.export(tmp_path / "output")
        assert exported.record_ids("context") == (publication.id,)


def test_endpoints_pass_carried_values_without_persistence(monkeypatch):
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:

        def no_sql(*args, **kwargs):
            pytest.fail("governed computation opened a SQL connection")

        monkeypatch.setattr(sqlite3, "connect", no_sql)
        monkeypatch.setattr("tn_governed.publications.write_once", no_sql)

        def endpoint():
            return Endpoint(
                session=session,
                evidence_policy=session.policy("experiment.evidence"),
                evaluator=lambda _: Assessment(True, "local use"),
                application="calculation",
                purpose="internal",
                accept_metadata=lambda ctx: ctx.writer == session.did,
            )

        source = endpoint()
        value = source.originate(7, policies=(session.policy("finance.account"),))
        claimed = source.attest(value, "estimate")
        receiver = endpoint()
        result = receiver.execute("double", (claimed,), lambda inputs: inputs[0] * 2)
        assert receiver.reveal(result, destination="internal") == 14
        assert receiver.claims(result)[0].statement == "estimate"
        fresh = endpoint()
        assert fresh.reveal(result, destination="internal") == 14
        transported = endpoint().receive(receiver.export(result))
        assert endpoint().reveal(transported, destination="internal") == 14


def test_endpoint_requires_the_native_ancestors_in_the_transmitted_bundle():
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:

        def endpoint():
            return Endpoint(
                session=session,
                evidence_policy=session.policy("experiment.evidence"),
                evaluator=lambda _: Assessment(True, "local use"),
                application="calculation",
                purpose="internal",
                accept_metadata=lambda ctx: ctx.writer == session.did,
            )

        source = endpoint()
        value = source.originate(7, policies=(session.policy("finance.account"),))
        bundle = source.export(value)
        ancestor = session.governance(value.carrier.object).governance.sources[0].object_id
        incomplete = ArtifactBundle(
            value,
            tuple(
                wire for wire in bundle.publications if tn.GovernedObject.parse(wire).id != ancestor
            ),
        )
        receiver = endpoint()
        receiver.reveal(value, destination="internal")
        with pytest.raises(FileNotFoundError):
            receiver.receive(incomplete)


def test_carried_native_values_still_require_recipient_authorization():
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        arguments = {
            "session": session,
            "evidence_policy": session.policy("experiment.evidence"),
            "evaluator": lambda _: Assessment(True, "local use"),
            "application": "calculation",
            "purpose": "internal",
        }
        source = Endpoint(**arguments, accept_metadata=lambda _: True)
        value = source.originate(7, policies=(session.policy("finance.account"),))
        receiver = Endpoint(**arguments, accept_metadata=lambda _: False)
        with pytest.raises(tn.governed.UseDenied):
            receiver.execute("double", (value,), lambda _: pytest.fail("compute was called"))


def test_string_receiver_rejects_an_omitted_native_parent():
    from test_governed_string_runtime import POLICY as STRING_POLICY

    from tn_governed.values.evidence import EvidenceRecorder
    from tn_governed.values.runtime import Context, Rules, publish_source
    from tn_governed.values.string import OperationDenied, TNString

    with tn.Session(STRING_POLICY, groups=["strings", "evidence"]) as session:
        rules = Rules(
            writers=frozenset({session.did}),
            policies=(session.policy("experiment.string"),),
            operations=frozenset({"upper", "reveal"}),
            destinations=frozenset({"internal"}),
        )

        def context():
            return Context(
                session, EvidenceRecorder(session), rules, application="strings", purpose="internal"
            )

        producer = context()
        source = publish_source(session, {"name": "Ada"})["name"]
        with producer:
            result = source.upper()
        incomplete = CarriedPublication(
            result.publication.object,
            support=tuple(
                obj
                for obj in result.publication.objects()
                if obj.id not in {source.reference.object_id, result.reference.object_id}
            ),
        )
        received = TNString(
            result.reference, result.decision_id, result.result_id, publication=incomplete
        )
        with pytest.raises(OperationDenied):
            received.reveal(context(), destination="internal")
