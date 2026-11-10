"""Report acceptance and review registration with native signed publications.

The transport returns constructed tool and report publications. No model runs.
"""

import hashlib
import io
import json
import sqlite3
from contextlib import ExitStack, closing
from types import SimpleNamespace

import pytest
import tn
from tn.governed import UseDenied
from tn_llama_client.protocol import NativeModelRelease

from experiments.paper_evaluation.case_study import (
    APPLICATION,
    MODEL_USE,
    NOTICE,
    PURPOSE,
    RECIPIENT_USE,
    REVIEW_ACTION,
    policy,
)
from tn_governed.native_objects import NativeObjects
from tn_governed.publications import PublicationStore
from tn_governed.values.catalog import AssignedRules, UnityGovernance
from tn_governed.values.evidence import EvidenceRecorder, read_record, verify_tape
from tn_governed.values.model import NativeModelEndpoint, prepare_native_model
from tn_governed.values.primitives import Context
from tn_governed.values.provision import provision
from tn_governed.values.sql import GovernedSQL, source_identity


@pytest.fixture(params=["native", "archive"])
def report_workflow(tmp_path, monkeypatch, request):
    database = tmp_path / "market.sqlite"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE TABLE market_data (name TEXT NOT NULL)")
        connection.execute("INSERT INTO market_data VALUES ('ACME')")
        connection.commit()
    input_paths = provision(
        tmp_path / "input-sessions", roles=["catalog", "gateway", "worker", "model-reader"],
        read_only_roles=("model-reader",),
    )
    output_paths = provision(
        tmp_path / "output-sessions", roles=["model-writer", "recipient"],
        groups=["tn.agents", "default"], read_only_roles=("recipient",),
    )
    volumes = {}

    def catalog_request(method, path, payload=None):
        if path in {"/catalogs", "/schemas"}:
            return {}
        if method == "POST" and path == "/volumes":
            identity = ".".join(payload[key] for key in ("catalog_name", "schema_name", "name"))
            volumes[identity] = payload
            return payload
        if method == "GET" and path.startswith("/volumes/"):
            return volumes[path.removeprefix("/volumes/")]
        raise AssertionError((method, path))

    with ExitStack() as stack:
        sessions = {
            role: stack.enter_context(tn.Session.from_config(str(path)))
            for role, path in {**input_paths, **output_paths}.items()
        }
        authority = sessions["catalog"]
        store = (NativeObjects() if request.param == "native"
                 else PublicationStore(tmp_path / "publications"))
        resolvers = {}
        for role in ("catalog", "gateway", "worker"):
            resolver = UnityGovernance(
                "http://unused", "reports", session=sessions[role], authority=authority.did,
                administration=authority.policy("experiment.administration"), store=store,
            )
            monkeypatch.setattr(resolver.registry, "_request", catalog_request)
            resolvers[role] = resolver
        conditions = {
            "use": MODEL_USE, "recipient_use": RECIPIENT_USE,
            "destinations": ["internal-model"], "report_destination": "internal-report",
            "required_disclosure": NOTICE, "required_tool": "log_compliance_creation",
            "review": REVIEW_ACTION,
        }
        resolvers["catalog"].publish_assignment(
            tmp_path / "assignment", table="market_data",
            source_identity=source_identity(database), application=APPLICATION,
            actors=["analyst"], purposes=[PURPOSE], columns={"name": {
                "kind": "str", "markdown": policy("name"), "rule": {
                    "model": conditions, "additional_uses": [MODEL_USE, RECIPIENT_USE],
                    "obligations": [],
                },
            }},
        )
        contexts = {}
        writers = [sessions[role].did for role in ("gateway", "worker")]
        for role in ("gateway", "worker"):
            rules = AssignedRules(
                resolvers[role], actor="analyst", application=APPLICATION,
                purpose=PURPOSE, writers=writers,
            )
            contexts[role] = Context(
                sessions[role], EvidenceRecorder(
                    sessions[role], store, authority.policy("experiment.evidence"),
                ), rules, application=APPLICATION, purpose=PURPOSE, actor="analyst",
                resolver=resolvers[role],
            )
        context = contexts["worker"]
        db = GovernedSQL(
            database, gateway=contexts["gateway"], consumer=context,
            edition_publisher=resolvers["catalog"], directory=tmp_path / "editions",
        )
        name, = db.execute("SELECT name FROM market_data LIMIT 1").fetchone()
        with context:
            claimed = name.attest("Suitable for internal company identification.", context)
            value = claimed.upper()
        model_file = tmp_path / "model.gguf"
        binary = tmp_path / "server"
        model_file.write_bytes(b"configuration identity; no inference")
        binary.write_bytes(b"configuration identity; no server")
        directory = tmp_path / "model"
        config, reader, requirements = prepare_native_model(
            value, context=context, input_session=sessions["model-reader"],
            output_session=sessions["model-writer"], recipient_session=sessions["recipient"],
            input_config=input_paths["model-reader"], output_config=output_paths["model-writer"],
            directory=directory, model=model_file, binary=binary,
        )
        events, releases = [], []
        native_open = reader.open

        def open_report(release, **expectations):
            opened = native_open(release, **expectations)
            events.append("recipient-accepted")
            return opened

        monkeypatch.setattr(reader, "open", open_report)
        append = context._append

        def record(kind, request, call_id, details):
            identity = append(kind, request, call_id, details)
            events.append("signed:" + kind)
            return identity

        monkeypatch.setattr(context, "_append", record)
        from tn_governed.values import model as model_module

        write_once = model_module.write_once

        def queue(path, wire):
            write_once(path, wire)
            events.append("review-queued")

        monkeypatch.setattr(model_module, "write_once", queue)
        source = context.store_object(value.reference.object_id)
        use = tn.UseContext(**MODEL_USE)
        source_policies = sessions["model-reader"].governance(source).governance.policies

        def accept_release(release):
            return (
                release.writer == sessions["model-writer"].did
                and release.use_context == use
                and release.destination == requirements["report_destination"]
                and len(release.policies) == len(source_policies)
                and all(any(policy.matches_contract(original) for original in source_policies)
                        for policy in release.policies)
            )

        def construct_release(tool_payloads=None, *, request_digest="sha256:" + "a" * 64, source=source, selection=None):
            source_data = sessions["model-reader"].receive(
                source, use=use, groups=["values"], selection=selection,
                decide=lambda admission: (admission.object.id == selection.source_object_id if selection
                    else context.catalog.accepts(admission, context.policy_dag)),
            )
            data = source_data.copy()
            run_id = "report-request-" + str(len(releases) + 1)
            tools = []
            for index, supplied in enumerate(({},) if tool_payloads is None else tool_payloads):
                fields = dict(supplied)
                object_type = fields.pop("object_type", "compliance.creation.logged")
                payload = {
                    "run_id": run_id, "request_digest": request_digest,
                    "tool_name": requirements["required_tool"],
                    "model_tool_call_id": "creation-log-" + str(index),
                    "source_object_id": source.id, "source_writer": source.writer,
                    "source_type": source.object_type, "selected_sections": ["values"],
                    "action": use.operation,
                }
                payload.update(fields)
                tool_data = source_data.copy()
                tool_data.set(None, payload, group="default")
                tool_data.select(["default"])
                tool = sessions["model-writer"].release(
                    tool_data, use=use, to=requirements["report_destination"],
                    decide=accept_release, object_type=object_type,
                )
                events.append("tool-released")
                data.include(sessions["model-writer"].receive(
                    tool, use=use, groups=["default"],
                    decide=lambda admission: context.catalog.accepts(admission, context.policy_dag),
                ))
                tools.append(tool)
            html = f"<p>{NOTICE}</p><p>ACME internal report.</p>"
            data.set(None, {"report_html": html}, group="default")
            data.select(["default"])
            output = sessions["model-writer"].release(
                data, use=use, to=requirements["report_destination"],
                decide=accept_release, object_type="report.generated",
            )
            events.append("report-released")
            release = NativeModelRelease(run_id, source.id, output.id, output, [], tuple(tools))
            releases.append(release)
            return release

        class Client:
            def __init__(self, *_args):
                pass

            def submit_model(self, supplied, _prompt, requested_use, *, destination):
                assert supplied.forward() == source.forward()
                assert requested_use == use
                assert destination == requirements["report_destination"]
                return construct_release()

            def submit_request(self, body):
                from tn_llama_client.protocol import model_request_digest

                request = json.loads(body)
                assert request["tn_object"].encode() == source.forward()
                assert request["use"] == requirements["use"]
                assert request["destination"] == requirements["report_destination"]
                return construct_release(request_digest=model_request_digest(body))

        monkeypatch.setattr("tn_governed.llama.GovernedLlamaClient", Client)
        endpoint = NativeModelEndpoint(
            context=context, value=value, base_url="http://unused", api_key="test",
            output_reader=reader, directory=directory, requirements=requirements,
            runtime_config=config,
        )
        yield SimpleNamespace(
            context=context, value=value, source_handle=name, endpoint=endpoint, reader=reader, events=events,
            releases=releases, root=tmp_path, queue=queue,
            record_count=len(context.recorder.records()), source=source,
            construct_release=construct_release,
            input_session=sessions["model-reader"],
        )


def call(workflow):
    with workflow.context:
        result = workflow.endpoint.generate(workflow.value, prompt="Describe the supplied company.")
    workflow.events.append("returned")
    return result


def records(workflow):
    recorder = workflow.context.recorder
    verified = verify_tape(
        recorder.records(), session=recorder.session, policy=recorder.policy,
        expected_writer=recorder.session.did, expected_context=recorder.context_id,
        expected_head=recorder.head,
    )
    return verified[workflow.record_count:]


def test_report_returns_only_after_recipient_acceptance_and_signed_review_queue(report_workflow):
    workflow = report_workflow
    report = call(workflow)
    assert workflow.events == [
        "signed:Decision", "signed:ModelHandoff", "tool-released", "report-released",
        "recipient-accepted", "signed:ReviewRequested", "review-queued",
        "signed:ModelResult", "returned",
    ]
    decision, handoff, review, result = records(workflow)
    assert [entry.body["kind"] for entry in (decision, handoff, review, result)] == [
        "Decision", "ModelHandoff", "ReviewRequested", "ModelResult",
    ]
    assert len({entry.body["call_id"] for entry in (decision, handoff, review, result)}) == 1
    assert result.body["details"]["review_request_id"] == review.id == report.review.record_id
    assert review.body["details"]["report_object_id"] == report.object.id
    assert review.body["details"]["status"] == "pending"
    assert review.body["details"]["report_html_sha256"] == hashlib.sha256(
        report.report_html.encode(),
    ).hexdigest()
    queued = workflow.root / report.review.queue_entry
    assert queued.read_bytes() == workflow.context.recorder.store.get(review.id)
    assert report.needs_review
    assert NOTICE in report.report_html


@pytest.mark.parametrize("report_workflow", ["native"], indirect=True)
def test_report_carries_cross_ceremony_evidence_without_original_object_collection(
    report_workflow, monkeypatch,
):
    workflow = report_workflow
    report = call(workflow)
    configuration = json.loads(workflow.endpoint.runtime_config.read_text())
    assert configuration["ceremony_id"] != configuration["output_ceremony_id"]
    assert report.publication.object is report.object
    carried = {publication.id: publication for publication in report.publication.objects()}
    assert {publication.id for publication in workflow.value.publication.objects()} <= set(carried)
    assert {publication.id for publication in report.release.tool_objects} <= set(carried)
    for identity, kind in (
        (report.decision_id, "Decision"), (report.handoff_record_id, "ModelHandoff"),
        (report.review.record_id, "ReviewRequested"), (report.result_record_id, "ModelResult"),
    ):
        publication = tn.GovernedObject.read(io.BytesIO(carried[identity].forward()))
        record = read_record(publication, session=workflow.context.session,
                             policy=workflow.context.recorder.policy)
        assert record.id == identity and record.body["kind"] == kind
        assert record.writer == workflow.context.session.did
    received = NativeObjects()
    received.include(report.publication)
    accepted_writers = workflow.context.evaluator.writers

    def unavailable(*_):
        raise AssertionError("recipient accessed the sender's object collection")

    monkeypatch.setattr(workflow.context, "store_object", unavailable)
    monkeypatch.setattr(workflow.context.recorder.store, "read", unavailable)

    def resolve(identity):
        publication = received.read(identity)
        assert publication.writer in accepted_writers
        return workflow.input_session.governance(publication)

    monkeypatch.setattr(workflow.reader, "resolve_ancestor", resolve)
    reopened = workflow.reader.open(report.release)
    assert reopened.get("report_html", group="default") == report.report_html
    assert not (workflow.root / "publications").exists()


def test_recipient_refusal_records_failure_before_review_registration(report_workflow):
    workflow = report_workflow
    workflow.reader.decide = lambda admission: False
    with pytest.raises(UseDenied):
        call(workflow)
    assert workflow.events == [
        "signed:Decision", "signed:ModelHandoff", "tool-released", "report-released",
        "signed:Failure",
    ]
    decision, handoff, failure = records(workflow)
    assert failure.body["details"]["decision_id"] == decision.id
    assert failure.body["details"]["error_type"] == "UseDenied"
    assert failure.body["call_id"] == handoff.body["call_id"]
    assert not (workflow.root / "review-queue").exists()


def test_queue_failure_retains_signed_failure_and_retry_has_a_separate_call(
    report_workflow, monkeypatch,
):
    workflow = report_workflow

    def unavailable(_path, _wire):
        workflow.events.append("queue-failed")
        raise OSError("review queue unavailable")

    monkeypatch.setattr("tn_governed.values.model.write_once", unavailable)
    with pytest.raises(OSError, match="review queue unavailable"):
        call(workflow)
    assert workflow.events == [
        "signed:Decision", "signed:ModelHandoff", "tool-released", "report-released",
        "recipient-accepted", "signed:ReviewRequested", "queue-failed", "signed:Failure",
    ]
    first_attempt = records(workflow)
    assert [entry.body["kind"] for entry in first_attempt] == [
        "Decision", "ModelHandoff", "ReviewRequested", "Failure",
    ]
    assert first_attempt[-1].body["details"]["error_type"] == "OSError"
    assert not (workflow.root / "review-queue").exists()
    released = workflow.releases[0].output_object
    assert workflow.context.recorder.store.get(released.id) == released.forward()

    monkeypatch.setattr("tn_governed.values.model.write_once", workflow.queue)
    report = call(workflow)
    attempts = records(workflow)
    assert len({entry.body["call_id"] for entry in attempts}) == 2
    assert attempts[-1].body["kind"] == "ModelResult"
    assert report.review.record_id != first_attempt[2].id
    assert report.object.id != released.id
    entries = list((workflow.root / "review-queue").glob("*.tn"))
    assert len(entries) == 1
    assert entries[0].read_bytes() == workflow.context.recorder.store.get(report.review.record_id)


def test_review_record_failure_stops_before_queue_and_success_record(report_workflow, monkeypatch):
    workflow = report_workflow
    append = workflow.context.recorder.append

    def persist(kind, **kwargs):
        if kind == "ReviewRequested":
            raise OSError("review record storage unavailable")
        return append(kind, **kwargs)

    monkeypatch.setattr(workflow.context.recorder, "append", persist)
    with pytest.raises(OSError, match="review record storage unavailable"):
        call(workflow)
    assert workflow.events == [
        "signed:Decision", "signed:ModelHandoff", "tool-released", "report-released",
        "recipient-accepted", "signed:Failure",
    ]
    assert [entry.body["kind"] for entry in records(workflow)] == [
        "Decision", "ModelHandoff", "Failure",
    ]
    assert not (workflow.root / "review-queue").exists()


class TrackedRecipient:
    def __init__(self, session):
        self.session = session
        self.opened = []

    def __getattr__(self, name):
        return getattr(self.session, name)

    def receive(self, publication, **kwargs):
        result = self.session.receive(publication, **kwargs)
        self.opened.append(publication.id)
        return result


def evidence_reader(workflow, *, expectations, required_tools=(), expected_request_digest=None):
    from tn_llama_client.clients import NativeOutputReader

    original = workflow.reader
    session = TrackedRecipient(original.session)
    return NativeOutputReader(
        session, expected_source=original.expected_source,
        expected_writer=original.expected_writer, use=original.use,
        destination=original.destination, release_use=original.release_use,
        catalog=original.catalog, policy_dag=original.policy_dag,
        resolve_ancestor=original.resolve_ancestor, decide=original.decide, carried_policy=original.carried_policy,
        expected_source_view=original.expected_source_view,
        tool_expectations=expectations, required_tools=required_tools,
        expected_request_digest=expected_request_digest,
    ), session


def test_required_logging_evidence_blocks_source_only_report(report_workflow):
    workflow = report_workflow
    release = workflow.construct_release(())
    session = TrackedRecipient(workflow.reader.session)
    workflow.reader.session = session
    with pytest.raises(PermissionError, match="required tool"):
        workflow.reader.open(release)
    assert release.output_object.id not in session.opened


@pytest.mark.parametrize("with_optional_tool", [False, True])
def test_optional_evidence_does_not_create_a_required_action(report_workflow, with_optional_tool):
    from tn_llama_client.clients import ToolEvidenceExpectation

    workflow = report_workflow
    release = workflow.construct_release(
        ({"tool_name": "record_usage"},) if with_optional_tool else (),
    )
    reader, session = evidence_reader(workflow, expectations=(
        ToolEvidenceExpectation("record_usage", ("values",), "compliance.creation.logged"),
    ))
    opened = reader.open(release)
    assert opened.get("report_html", group="default").endswith("<p>ACME internal report.</p>")
    assert session.opened[-1] == release.output_object.id


@pytest.mark.parametrize("include_second", [False, True])
def test_each_required_tool_needs_its_own_verified_completion(report_workflow, include_second):
    from tn_llama_client.clients import ToolEvidenceExpectation

    workflow = report_workflow
    payloads = [{"tool_name": "record_usage", "object_type": "usage.recorded"}]
    if include_second:
        payloads.append({"tool_name": "record_delivery", "object_type": "delivery.recorded"})
    release = workflow.construct_release(tuple(payloads))
    reader, session = evidence_reader(workflow, expectations=(
        ToolEvidenceExpectation("record_usage", ("values",), "usage.recorded"),
        ToolEvidenceExpectation("record_delivery", ("values",), "delivery.recorded"),
    ), required_tools=("record_usage", "record_delivery"))
    if include_second:
        reader.open(release)
        assert session.opened == [tool.id for tool in release.tool_objects] + [release.output_object.id]
    else:
        with pytest.raises(PermissionError, match="required tool"):
            reader.open(release)
        assert release.output_object.id not in session.opened


@pytest.mark.parametrize("wrong_field", [
    {"tool_name": "unrecognized"},
    {"source_object_id": "sha256:" + "b" * 64},
    {"source_writer": "another-writer"},
    {"source_type": "another-type"},
    {"run_id": "another-request"},
    {"action": "another-action"},
    {"selected_sections": ["evidence"]},
    {"object_type": "another-tool-type"},
])
def test_required_tool_evidence_must_match_the_request(report_workflow, wrong_field):
    workflow = report_workflow
    release = workflow.construct_release((wrong_field,))
    session = TrackedRecipient(workflow.reader.session)
    workflow.reader.session = session
    with pytest.raises((PermissionError, ValueError)):
        workflow.reader.open(release)
    assert release.output_object.id not in session.opened


def test_one_tool_call_cannot_satisfy_two_required_tools(report_workflow):
    from tn_llama_client.clients import ToolEvidenceExpectation

    workflow = report_workflow
    release = workflow.construct_release((
        {"tool_name": "record_usage", "model_tool_call_id": "same-call"},
        {"tool_name": "record_delivery", "model_tool_call_id": "same-call"},
    ))
    reader, session = evidence_reader(workflow, expectations=(
        ToolEvidenceExpectation("record_usage", ("values",), "compliance.creation.logged"),
        ToolEvidenceExpectation("record_delivery", ("values",), "compliance.creation.logged"),
    ), required_tools=("record_usage", "record_delivery"))
    with pytest.raises(ValueError, match="call identity"):
        reader.open(release)
    assert release.output_object.id not in session.opened


def test_tool_completions_must_belong_to_one_request(report_workflow):
    workflow = report_workflow
    release = workflow.construct_release(({}, {"request_digest": "sha256:" + "b" * 64}))
    session = TrackedRecipient(workflow.reader.session)
    workflow.reader.session = session
    with pytest.raises(ValueError, match="request digest"):
        workflow.reader.open(release)
    assert release.output_object.id not in session.opened


def test_required_tools_must_have_validation_expectations(report_workflow):
    with pytest.raises(ValueError, match="required tool"):
        evidence_reader(report_workflow, expectations=(), required_tools=("record_usage",))


@pytest.mark.parametrize("fields", [
    {"name": ""},
    {"name": " record_usage"},
    {"name": "record\nusage"},
    {"object_type": ""},
    {"selected_sections": ()},
    {"selected_sections": ("values", "values")},
    {"selected_sections": ("",)},
])
def test_evidence_expectations_reject_ambiguous_identifiers(fields):
    from tn_llama_client.clients import ToolEvidenceExpectation

    configuration = {
        "name": "record_usage", "selected_sections": ("values",),
        "object_type": "usage.recorded",
    }
    configuration.update(fields)
    with pytest.raises(ValueError):
        ToolEvidenceExpectation(**configuration)


def test_evidence_expectations_snapshot_mutable_section_configuration():
    from tn_llama_client.clients import ToolEvidenceExpectation

    sections = ["values"]
    expectation = ToolEvidenceExpectation("record_usage", sections, "usage.recorded")
    sections.append("evidence")
    assert expectation.selected_sections == ("values",)


def test_conflicting_tool_validation_configuration_is_rejected(report_workflow):
    from tn_llama_client.clients import ToolEvidenceExpectation

    with pytest.raises(ValueError, match="unique names"):
        evidence_reader(report_workflow, expectations=(
            ToolEvidenceExpectation("record_usage", ("values",), "usage.recorded"),
            ToolEvidenceExpectation("record_usage", ("evidence",), "usage.recorded"),
        ))


@pytest.mark.parametrize("configured", [False, True])
def test_trusted_request_digest_rejects_another_prompt_before_report_open(report_workflow, configured):
    from tn_llama_client.clients import ToolEvidenceExpectation

    workflow = report_workflow
    release = workflow.construct_release(({"tool_name": "record_usage"},))
    expected = "sha256:" + "b" * 64
    reader, session = evidence_reader(workflow, expectations=(
        ToolEvidenceExpectation("record_usage", ("values",), "compliance.creation.logged"),
    ), expected_request_digest=expected if configured else None)
    with pytest.raises(ValueError, match="request digest"):
        reader.open(release, **({} if configured else {"expected_request_digest": expected}))
    assert release.output_object.id not in session.opened


def test_trusted_request_digest_accepts_matching_signed_completion(report_workflow):
    from tn_llama_client.clients import ToolEvidenceExpectation

    workflow = report_workflow
    release = workflow.construct_release(({"tool_name": "record_usage"},))
    reader, session = evidence_reader(workflow, expectations=(
        ToolEvidenceExpectation("record_usage", ("values",), "compliance.creation.logged"),
    ), expected_request_digest="sha256:" + "a" * 64)
    reader.open(release, expected_request_digest="sha256:" + "a" * 64)
    assert session.opened[-1] == release.output_object.id


def test_trusted_request_digest_requires_signed_evidence_even_without_required_names(report_workflow):
    workflow = report_workflow
    release = workflow.construct_release(())
    reader, session = evidence_reader(workflow, expectations=(),
        expected_request_digest="sha256:" + "a" * 64)
    with pytest.raises(PermissionError, match="request.*evidence"):
        reader.open(release)
    assert session.opened == []


def test_per_call_request_digest_cannot_override_configured_expectation(report_workflow):
    workflow = report_workflow
    release = workflow.construct_release()
    reader, session = evidence_reader(workflow, expectations=(),
        expected_request_digest="sha256:" + "a" * 64)
    with pytest.raises(ValueError, match="configured request digest"):
        reader.open(release, expected_request_digest="sha256:" + "b" * 64)
    assert session.opened == []


@pytest.mark.parametrize("invalid", ["", "a" * 64, "sha256:" + "A" * 64, 1])
def test_trusted_request_digest_must_be_canonical(report_workflow, invalid):
    with pytest.raises(ValueError, match="request digest"):
        evidence_reader(report_workflow, expectations=(), expected_request_digest=invalid)
    reader, session = evidence_reader(report_workflow, expectations=())
    with pytest.raises(ValueError, match="request digest"):
        reader.open(report_workflow.construct_release(()), expected_request_digest=invalid)
    assert session.opened == []


def test_request_digest_matches_native_canonical_request_binding(report_workflow):
    from tn.canonical import _canonical_bytes
    from tn_llama_client.protocol import build_model_request, model_request_digest

    workflow = report_workflow
    prompt = "Describe the supplied company — café."
    reader = workflow.reader
    body = build_model_request(workflow.source, prompt, reader.release_use,
                               destination=reader.destination)
    expected = "sha256:" + hashlib.sha256(b"tn.llama.request.v2\0" + _canonical_bytes({
        "object_id": workflow.source.id,
        "use": workflow.endpoint.requirements["use"],
        "destination": reader.destination,
        "messages": [{"role": "user", "content": prompt}],
    })).hexdigest()
    assert model_request_digest(body) == expected
    changed = json.loads(body)
    changed["messages"][0]["content"] += " Again."
    assert model_request_digest(json.dumps(changed).encode()) != expected


def test_model_endpoint_rejects_replayed_report_for_a_different_prompt(report_workflow, monkeypatch):
    workflow = report_workflow
    call(workflow)
    prior_release = workflow.releases[-1]

    class ReplayClient:
        def __init__(self, *_args):
            pass

        def submit_request(self, _body):
            return prior_release

    session = TrackedRecipient(workflow.reader.session)
    workflow.reader.session = session
    monkeypatch.setattr("tn_governed.llama.GovernedLlamaClient", ReplayClient)
    with workflow.context, pytest.raises(ValueError, match="request digest"):
        workflow.endpoint.generate(workflow.value, prompt="Describe a different reporting period.")
    assert prior_release.output_object.id not in session.opened
