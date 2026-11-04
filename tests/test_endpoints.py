"""Independent endpoints preserve authority, evidence and governed boundaries."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack

import pytest
import tn

from tn_governed.publications import PublicationStore
from tn_governed.values.provision import provision
from tn_governed.values.runtime import Assessment, ObligationResult
from tn_governed.values.string import OperationDenied


@pytest.fixture
def endpoints(tmp_path):
    from tn_governed.endpoints import Endpoint

    roles = ("source", "analyst", "restricted", "metadata_only")
    paths = provision(
        tmp_path / "sessions",
        roles=roles,
        read_only_roles=(),
        groups=(
            "tn.agents",
            "values",
            "evidence",
            "catalog_cfg",
            "policy_revision",
            "dataset_edition",
            "finance",
        ),
    )
    with ExitStack() as stack:
        sessions = {
            role: stack.enter_context(tn.Session.from_config(str(path)))
            for role, path in paths.items()
        }
        policies = tuple(
            session.policy("experiment.administration") for session in sessions.values()
        )
        evidence = tuple(session.policy("experiment.evidence") for session in sessions.values())
        writers = {session.did for session in sessions.values()}

        def accepted(context):
            return context.writer in writers and all(
                any(policy.matches_contract(expected) for expected in policies)
                for policy in context.policies
            )

        result = {
            role: Endpoint(
                session=session,
                store=PublicationStore(tmp_path / role),
                evidence_policy=session.policy("experiment.evidence"),
                evidence_policies=evidence,
                application=role,
                purpose="analysis",
                evaluator=lambda request: Assessment(True, "local authorization"),
                accept_metadata=accepted,
            )
            for role, session in sessions.items()
        }
        yield result, policies


def test_separate_stores_preserve_claims_and_parent_evidence(endpoints):
    peers, policies = endpoints
    source, analyst = peers["source"], peers["analyst"]
    value = source.originate({"amount": 7}, policies=(policies[0],))
    claimed = source.attest(value, "amount is an estimate")
    arrived = analyst.receive(source.export(claimed))
    result = analyst.execute(
        "multiply", (arrived,), lambda values: values[0]["amount"] * 3, parameters={"factor": 3}
    )
    assert analyst.reveal(result, destination="internal") == 21
    assert analyst.metadata(result)["claims"] == source.metadata(claimed)["claims"]
    claim = analyst.claims(result)[0]
    assert claim.issuer == source.session.did
    assert claim.subjects == (value.reference,)
    assert analyst.metadata(result)["parents"] == [arrived.to_dict()]
    restored = source.receive(analyst.export(result))
    assert source.reveal(restored, destination="internal") == 21


def test_denied_operation_never_calls_compute(endpoints):
    peers, policies = endpoints
    value = peers["source"].originate(12, policies=(policies[0],))
    endpoint = peers["restricted"]
    arrived = endpoint.receive(peers["source"].export(value))
    endpoint.evaluator = lambda request: Assessment(False, "purpose unavailable")
    invoked = []
    with pytest.raises(OperationDenied):
        endpoint.execute("calculate", (arrived,), lambda values: invoked.append(values))
    assert invoked == []
    assert endpoint.records()[-1].body["kind"] == "Refusal"


def test_key_possession_is_separate_from_policy_permission(endpoints):
    peers, policies = endpoints
    value = peers["source"].originate("protected", policies=(policies[0],))
    endpoint = peers["metadata_only"]
    arrived = endpoint.receive(peers["source"].export(value))
    assert endpoint.metadata(arrived)["state"] == "active"
    with pytest.raises(tn.governed.NotEntitled):
        endpoint.reveal(arrived, destination="internal")
    assert endpoint.records()[-1].body["kind"] == "Failure"


def test_later_action_failure_retains_completion_and_prevents_compute(endpoints):
    peers, policies = endpoints
    endpoint = peers["source"]
    value = endpoint.originate(12, policies=(policies[0],))
    endpoint.evaluator = lambda _: Assessment(True, "conditional", ("log", "queue"))
    endpoint.obligations.update(
        log=lambda _: ObligationResult(True, "ledger:7"),
        queue=lambda _: ObligationResult(False, "unavailable"),
    )
    with pytest.raises(OperationDenied):
        endpoint.execute("calculate", (value,), lambda _: pytest.fail("compute was called"))
    decision = endpoint.records()[-2].body["details"]
    assert decision["discharged"][0]["evidence"] == "ledger:7"
    assert decision["failed_obligation"] == "queue"


def test_dispute_retains_original_author_and_subject(endpoints):
    peers, policies = endpoints
    source, analyst = peers["source"], peers["analyst"]
    value = source.originate(5, policies=(policies[0],))
    claimed = source.attest(value, "suitable for audit")
    original_claim = source.claims(claimed)[0]
    arrived = analyst.receive(source.export(claimed))
    disputed = analyst.dispute(arrived, original_claim.id, "source lacks supporting records")
    assert analyst.claims(disputed)[0] == original_claim
    assert analyst.claims(disputed)[1].issuer == analyst.session.did
    manifest = analyst.metadata(disputed)
    assert manifest["disputes"][0]["claim_id"] == original_claim.id


def test_parallel_endpoints_make_separate_decisions(endpoints):
    peers, policies = endpoints
    source = peers["source"]
    value = source.originate(5, policies=(policies[0],))
    bundle = source.export(value)
    inputs = {role: peers[role].receive(bundle) for role in ("analyst", "restricted")}
    with ThreadPoolExecutor(2) as pool:
        futures = [
            pool.submit(
                peers[role].execute, "double", (inputs[role],), lambda values: values[0] * 2
            )
            for role in inputs
        ]
        outputs = [future.result() for future in futures]
    assert outputs[0].reference.object_id != outputs[1].reference.object_id
    assert outputs[0].decision_id != outputs[1].decision_id
    assert peers["analyst"].metadata(outputs[0])["parents"] == [value.to_dict()]


def test_full_policy_union_applies_before_business_values_are_stored(endpoints):
    peers, policies = endpoints
    endpoint = peers["source"]
    value = endpoint.originate("secret", policies=policies[:2])
    expected = {policy.policy_ref for policy in policies[:2]}
    for identity in endpoint.store.publication_sizes():
        obj = endpoint.store.read(identity)
        if obj.object_type != "tn.artifact":
            continue
        opened = endpoint.session.receive(
            obj,
            use=tn.UseContext("inspect", "audit", "read"),
            groups=["values"],
            decide=lambda _: True,
        )
        if "value" in opened.get(None, group="values"):
            assert {policy.policy_ref for policy in opened.policies} == expected
    assert endpoint.reveal(value, destination="internal") == "secret"


def test_governed_boundary_rejects_revealed_and_nested_plain_values(endpoints):
    from tn_governed.boundaries import BoundaryError, GovernedBoundary

    peers, policies = endpoints
    endpoint = peers["source"]
    value = endpoint.originate(8, policies=(policies[0],))
    boundary = GovernedBoundary(endpoint)
    assert boundary.accept({"amounts": [value]})["amounts"][0] == value
    plain = endpoint.reveal(value, destination="internal")
    for incoming in (plain, {"amounts": [value, plain]}, str(value.reference.object_id)):
        with pytest.raises(BoundaryError):
            boundary.accept(incoming)


def test_native_reference_can_identify_a_claim_subject_in_an_external_group():
    from tn_governed.values.string import ValueReference

    reference = ValueReference("sha256:" + "1" * 64, "rows", "finance")
    assert reference.to_dict()["group"] == "finance"
    for group in ("", "finance\n", None):
        with pytest.raises(ValueError):
            ValueReference(reference.object_id, "rows", group)


def test_import_native_dataframe_preserves_claim_subject_and_policies(endpoints):
    from tn_governed.values.string import ValueReference

    peers, policies = endpoints
    source, analyst = peers["source"], peers["analyst"]
    data = source.session.create(
        {"rows": [{"n": 7}, {"n": 8}]}, policies[0], object_type="frame", group="finance"
    )
    source.store.put(data.snapshot)
    publication = data.release(
        use=tn.UseContext("source", "analysis", "release"), to="analyst", decide=lambda _: True
    )
    source.store.put(publication)
    subject = ValueReference(publication.id, "rows", "finance")
    claim_id = source.recorder.append(
        "Claim",
        call_id="source-claim",
        application="source",
        purpose="analysis",
        operation="attest",
        inputs=(subject,),
        details={"statement": "estimates"},
    )
    wires = tuple(source.store.get(identity) for identity in source.store.publication_sizes())
    result = analyst.import_publication(
        publication,
        group="finance",
        field="rows",
        claims=(claim_id,),
        publications=wires,
        decide=lambda _: True,
    )
    assert analyst.reveal(result, destination="internal") == [{"n": 7}, {"n": 8}]
    assert analyst.claims(result)[0].subjects == (subject,)
    assert analyst.metadata(result)["external_inputs"] == [subject.to_dict()]
    restored = source.receive(analyst.export(result))
    assert source.claims(restored)[0].issuer == source.session.did


def test_artifact_import_cannot_discard_existing_claims(endpoints):
    peers, policies = endpoints
    endpoint = peers["source"]
    artifact = endpoint.attest(endpoint.originate(7, policies=(policies[0],)), "estimate")
    with pytest.raises(ValueError, match="receive"):
        endpoint.import_publication(
            endpoint.store.read(artifact.reference.object_id), group="values", field="value"
        )


@pytest.mark.parametrize("content", [{1: "a", "1": "b"}, {"n": float("nan")}])
def test_artifact_values_cannot_silently_change_json_meaning(endpoints, content):
    peers, policies = endpoints
    with pytest.raises((ValueError, TypeError)):
        peers["source"].originate(content, policies=(policies[0],))


def test_boundary_dispatch_rejects_an_unrelated_governed_result(endpoints):
    from tn_governed.boundaries import BoundaryError, GovernedBoundary

    peers, policies = endpoints
    endpoint = peers["source"]
    first = endpoint.originate(1, policies=(policies[0],))
    unrelated = endpoint.originate(2, policies=(policies[1],))
    with pytest.raises(BoundaryError, match="contributing"):
        GovernedBoundary(endpoint).dispatch(lambda _: unrelated, first)


def test_execution_requires_a_destination_before_running_actions(endpoints):
    peers, policies = endpoints
    endpoint = peers["source"]
    value = endpoint.originate(1, policies=(policies[0],))
    for destination in ("", "  ", None):
        with pytest.raises(ValueError, match="destination"):
            endpoint.execute(
                "compute", (value,), lambda _: pytest.fail("called"), destination=destination
            )


def test_invalid_evaluation_keeps_partial_action_evidence(endpoints):
    from tn_governed.endpoint_policy import PolicyAssessment

    peers, policies = endpoints
    endpoint = peers["source"]
    value = endpoint.originate(1, policies=(policies[0],))

    def unavailable(_):
        raise RuntimeError("queue unavailable")

    endpoint.evaluator = lambda _: PolicyAssessment(
        True, "conditional", ("log", "queue"), evaluation={"invalid": object()}
    )
    endpoint.obligations.update(
        log=lambda _: ObligationResult(True, "ledger:42"), queue=unavailable
    )
    with pytest.raises(OperationDenied):
        endpoint.execute("compute", (value,), lambda _: pytest.fail("called"))
    decision = endpoint.records()[-2].body["details"]
    assert decision["discharged"][0]["evidence"] == "ledger:42"
    assert decision["failed_obligation"] == "queue"
    assert decision["error_type"] == "TypeError"


def test_completed_action_is_durable_before_a_later_action_is_cancelled(endpoints):
    peers, policies = endpoints
    endpoint = peers["source"]
    value = endpoint.originate(1, policies=(policies[0],))

    def cancelled(_):
        raise KeyboardInterrupt()

    endpoint.evaluator = lambda _: Assessment(True, "conditional", ("log", "queue"))
    endpoint.obligations.update(log=lambda _: ObligationResult(True, "ledger:43"), queue=cancelled)
    with pytest.raises(KeyboardInterrupt):
        endpoint.execute("compute", (value,), lambda _: pytest.fail("called"))
    record = endpoint.records()[-1]
    assert record.body["kind"] == "Observation"
    assert record.body["details"]["obligation"] == "log"
    assert record.body["details"]["evidence"] == "ledger:43"
    assert endpoint.read_record(record.id) == record


def test_import_cannot_relabel_an_unrelated_claim_as_a_contribution(endpoints):
    from tn_governed.values.evidence import EvidenceError

    peers, policies = endpoints
    endpoint = peers["source"]
    unrelated = endpoint.attest(endpoint.originate(17, policies=(policies[0],)), "estimate")
    source = endpoint.session.create(
        {"rows": [3]}, policies[0], object_type="frame", group="finance"
    )
    endpoint.store.put(source.snapshot)
    publication = source.release(
        use=tn.UseContext("source", "analysis", "release"), to="analyst", decide=lambda _: True
    )
    with pytest.raises(EvidenceError, match="subject"):
        endpoint.import_publication(
            publication, group="finance", field="rows", claims=(endpoint.claims(unrelated)[0].id,)
        )


def test_endpoint_artifacts_designate_their_evidence_manifest(endpoints):
    from tn_governed.artifact_types import GovernedArtifact
    from tn_governed.values.string import ValueReference

    peers, policies = endpoints
    source = peers["source"]
    value = source.originate(5, policies=(policies[0],))
    derived = source.execute("double", (value,), lambda values: values[0] * 2)
    for artifact in (value, derived):
        assert source.store.read(artifact.reference.object_id).manifest_group == "evidence"
    undesignated = source.session.create({"value": 5}, policies[0], object_type="tn.artifact", group="values")
    undesignated.set(None, {"manifest": source.metadata(value)}, group="evidence")
    undesignated.select(["values", "evidence"])
    publication = undesignated.release(use=tn.UseContext("source", "analysis", "originate"),
                                       to="governed-runtime", object_type="tn.artifact", decide=lambda _: True)
    source.store.put(publication)
    handle = GovernedArtifact(ValueReference(publication.id, "value", "values"), value.decision_id, value.result_id)
    with pytest.raises(tn.governed.GovernedError):
        source.metadata(handle)


@pytest.mark.parametrize("count", [63, 64, 65])
def test_an_artifact_with_many_inputs_verifies_against_its_packed_decision(endpoints, count):
    peers, policies = endpoints
    source = peers["source"]
    values = [source.originate(index, policies=(policies[0],)) for index in range(count)]
    total = source.execute("sum", values, lambda opened: sum(opened))
    assert source.reveal(total, destination="internal") == sum(range(count))
    assert len(source.metadata(total)["parents"]) == count


def test_import_accepts_a_claim_on_a_field_its_carried_holder_signs(endpoints):
    from tn_governed.values.string import ValueReference

    peers, policies = endpoints
    source, analyst = peers["source"], peers["analyst"]
    use = tn.UseContext("source", "analysis", "release")
    data = source.session.create({"rows": [5]}, policies[0], object_type="frame", group="finance")
    data.set(None, {"label": "desk"}, group="values")
    source.store.put(data.snapshot)
    holder = data.release(use=use, to="analyst", decide=lambda _: True)
    working = source.session.receive(holder, use=use, groups=["values"], decide=lambda _: True)
    carrier = working.release(use=use, to="analyst", decide=lambda _: True)
    assert "finance" not in carrier.group_names
    assert holder.id in {item.id for item in carrier.carried}
    for obj in (holder, carrier):
        source.store.put(obj)
    subject = ValueReference(carrier.id, "rows", "finance")
    claim_id = source.recorder.append(
        "Claim", call_id="source-claim", application="source", purpose="analysis",
        operation="attest", inputs=(subject,), details={"statement": "estimates"},
    )
    wires = tuple(source.store.get(identity) for identity in source.store.publication_sizes())
    result = analyst.import_publication(carrier, group="finance", field="rows", claims=(claim_id,),
                                        publications=wires, decide=lambda _: True)
    assert analyst.claims(result)[0].subjects == (subject,)
    assert analyst.reveal(result, destination="internal") == [5]
