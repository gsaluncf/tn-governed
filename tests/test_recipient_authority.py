"""Recipients evaluate the same encrypted value under their own configuration."""

import base64
import hashlib
import json
from contextlib import ExitStack
from types import SimpleNamespace

import pytest
import tn
from tn.governed import NotEntitled

from tn_governed.publications import PublicationStore
from tn_governed.values.catalog import AssignedRules, UnityGovernance, markdown
from tn_governed.values.evidence import EvidenceRecorder, verify_tape
from tn_governed.values.primitives import Context
from tn_governed.values.provision import provision
from tn_governed.values.runtime import Request
from tn_governed.values.string import OperationDenied, TNString


@pytest.fixture
def recipients(tmp_path, monkeypatch):
    roles = ("catalog", "gateway", "internal", "external", "unrecognized", "metadata_only")
    paths = provision(tmp_path / "sessions", roles=roles)
    locations = {}

    def catalog_transport(method, path, payload=None):
        if method == "POST" and path == "/volumes":
            name = f"{payload['catalog_name']}.{payload['schema_name']}.{payload['name']}"
            locations[name] = payload["storage_location"]
        if method == "GET":
            return {"storage_location": locations[path.split("/")[-1]]}
        return {}

    with ExitStack() as stack:
        sessions = {
            role: stack.enter_context(tn.Session.from_config(str(path)))
            for role, path in paths.items()
        }
        catalog = sessions["catalog"]
        administration = catalog.policy("experiment.administration")
        audit = catalog.policy("experiment.evidence")
        store = PublicationStore(tmp_path / "publications")
        resolvers = {}
        for role, session in sessions.items():
            resolver = UnityGovernance(
                "http://unused", "test", session=session, authority=catalog.did,
                administration=administration, store=store,
            )
            monkeypatch.setattr(resolver.registry, "_request", catalog_transport)
            resolvers[role] = resolver

        source = {"snapshot_sha256": "a" * 64}
        assignment = resolvers["catalog"].publish_assignment(
            tmp_path / "assignment", table="people", source_identity=source,
            application="support", actors=["analyst"], purposes=["internal"],
            columns={"name": {"kind": "str", "markdown": markdown("name")}},
        )
        packet = None
        contexts = {}
        gateway = sessions["gateway"]
        for role in roles[1:]:
            resolver = resolvers[role]
            resolution = resolver.resolve(
                "people", ["name"], actor="analyst", application="support",
                purpose="internal", expected_source=source, packet=packet,
            )
            packet = resolution.packet
            purpose = "external" if role == "external" else "internal"
            rules = AssignedRules(
                resolver, actor="analyst", application="support", purpose=purpose,
                writers=[sessions[role].did] if role == "unrecognized"
                else [gateway.did, sessions[role].did],
            )
            contexts[role] = Context(
                sessions[role], EvidenceRecorder(sessions[role], store, audit), rules,
                application="support", purpose=purpose, actor="analyst", resolver=resolver,
            )

        context = contexts["gateway"]
        policy = resolvers["gateway"].policies[resolution.policies["name"].revision_id]
        request = Request("support", "internal", "select", (), (), (policy,), ())
        decision = context._decision(request, "query")
        original = context.originate(
            "Ada", policy, source={
                **source, "table": "people", "column": "name", "row": 0,
                "query_id": "query", "assignment_id": assignment,
            }, request=request, decision_id=decision, call_id="query",
        )
        statement = "Suitable for identifying the customer in internal support."
        with context:
            annotated = original.attest(statement, context)
            value = annotated.upper()
        yield SimpleNamespace(
            contexts=contexts, sessions=sessions, paths=paths, store=store,
            value=value, original=original, annotated=annotated, statement=statement,
            wire=store.get(value.reference.object_id), policy=policy, audit=audit,
        )


def received_value(run, role):
    context, value = run.contexts[role], run.value
    return TNString(
        value.reference, value.decision_id, value.result_id,
        metadata_provider=context.string_metadata,
    )


def records(run, role):
    context = run.contexts[role]
    return verify_tape(
        context.recorder.records(), session=run.sessions["catalog"], policy=run.audit,
        expected_writer=context.session.did, expected_context=context.recorder.context_id,
        expected_head=context.recorder.head,
    )


def test_same_publication_has_different_recipient_decisions(recipients, monkeypatch):
    run = recipients
    assert len({session.did for session in run.sessions.values()}) == len(run.sessions)
    opened = []
    for role in ("internal", "external", "unrecognized"):
        context = run.contexts[role]
        original_open = context._open_values

        def observe_open(*args, role=role, original_open=original_open):
            opened.append(role)
            return original_open(*args)

        monkeypatch.setattr(context, "_open_values", observe_open)
        assert (run.paths[role].parent / "keys" / "values.btn.mykit").is_file()
        assert context.store_object(run.value.reference.object_id).forward() == run.wire
        value = received_value(run, role)
        if role == "internal":
            assert value.reveal(context, destination="support-console") == "ADA"
        else:
            with pytest.raises(OperationDenied):
                value.reveal(context, destination="support-console")
        evidence = records(run, role)
        kinds = [record.body["kind"] for record in evidence]
        expected = ["Monitor", "Decision", "Disclosure"] if role == "internal" else [
            "Decision", "Refusal",
        ]
        assert kinds == expected
        decision = next(record for record in evidence if record.body["kind"] == "Decision")
        assert decision.body["details"]["permitted"] is (role == "internal")
        assert decision.body["inputs"] == [value.reference.to_dict()]
    assert opened == ["internal"]
    assert run.store.get(run.value.reference.object_id) == run.wire


def test_recipient_derivative_retains_original_claim_and_policy(recipients):
    run = recipients
    context = run.contexts["internal"]
    value = context.hydrate(
        run.value.reference, run.value.decision_id, run.value.result_id, kind="str",
    )
    with context:
        result = value.lower()
    assert result.reveal(context, destination="support-console") == "ada"
    source_data, _, source_claims = run.contexts["gateway"]._metadata(run.value)
    data, binding, claims = context._metadata(result)
    assert data.snapshot.writer == context.session.did
    assert source_data.snapshot.writer == run.sessions["gateway"].did
    assert data.snapshot.id != source_data.snapshot.id
    assert claims == source_claims
    assert len(claims) == 1
    assert claims[0].issuer == run.sessions["gateway"].did
    assert claims[0].subjects == (run.original.reference,)
    assert claims[0].statement == run.statement
    assert binding["parents"] == [run.value.reference.to_dict()]
    assert len(data.policies) == 1 and data.policies[0].matches_contract(run.policy)
    decision = next(record for record in records(run, "internal")
                    if record.body["kind"] == "Decision")
    assert decision.body["details"]["claim_judgments"] == [[claims[0].id, "informative"]]


def test_permitted_recipient_still_requires_values_key(recipients):
    run = recipients
    context = run.contexts["metadata_only"]
    assert not (run.paths["metadata_only"].parent / "keys" / "values.btn.mykit").exists()
    value = context.hydrate(
        run.value.reference, run.value.decision_id, run.value.result_id, kind="str",
    )
    assert context._metadata(value)[2][0].subjects == (run.original.reference,)
    with pytest.raises(NotEntitled):
        value.reveal(context, destination="support-console")
    evidence = records(run, "metadata_only")
    assert [record.body["kind"] for record in evidence] == ["Monitor", "Decision", "Failure"]
    assert evidence[1].body["details"]["permitted"] is True
    assert evidence[2].body["details"]["error_type"] == "NotEntitled"


@pytest.mark.parametrize("group", ["values", "tn.agents"])
def test_changed_encrypted_group_is_rejected_before_content_access(recipients, monkeypatch, group):
    run = recipients
    context = run.contexts["internal"]
    value = context.hydrate(
        run.value.reference, run.value.decision_id, run.value.result_id, kind="str",
    )
    envelope = json.loads(run.wire)
    ciphertext = bytearray(base64.b64decode(envelope[group]["ciphertext"]))
    ciphertext[0] ^= 1
    envelope[group]["ciphertext"] = base64.b64encode(ciphertext).decode()
    wire = json.dumps(envelope).encode()
    digest = value.reference.object_id.removeprefix("sha256:")
    (run.store.root / "objects" / f"{digest}.tn").write_bytes(wire)
    index_path = run.store.root / "index" / f"{digest}.json"
    index = json.loads(index_path.read_bytes())
    index["wire_sha256"] = hashlib.sha256(wire).hexdigest()
    index_path.write_text(json.dumps(index), encoding="utf-8")
    opened = []
    original_open = context._open_values

    def observe_open(*args):
        opened.append(args)
        return original_open(*args)

    monkeypatch.setattr(context, "_open_values", observe_open)
    with pytest.raises(OperationDenied, match="input admission failed"):
        value.reveal(context, destination="support-console")
    assert opened == []
    evidence = records(run, "internal")
    assert [record.body["kind"] for record in evidence] == ["Decision", "Refusal"]
    assert evidence[0].body["details"]["error_type"] == "VerificationError"
