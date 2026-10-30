"""Report acceptance and review registration with native signed publications.

The transport returns constructed tool and report publications. No model runs.
"""

import hashlib
import sqlite3
from contextlib import ExitStack, closing
from types import SimpleNamespace

import pytest
import tn
from tn.governed import UseDenied
from tn_llama_client.protocol import NativeModelRelease

from tn_governed.publications import PublicationStore
from tn_governed.values.catalog import AssignedRules, UnityGovernance
from tn_governed.values.evidence import EvidenceRecorder, verify_tape
from tn_governed.values.market_report import (
    APPLICATION,
    MODEL_USE,
    NOTICE,
    PURPOSE,
    RECIPIENT_USE,
    REVIEW_ACTION,
    policy,
)
from tn_governed.values.model import NativeModelEndpoint, prepare_native_model
from tn_governed.values.primitives import Context
from tn_governed.values.provision import provision
from tn_governed.values.sql import GovernedSQL, source_identity


@pytest.fixture
def report_workflow(tmp_path, monkeypatch):
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
        store = PublicationStore(tmp_path / "publications")
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

        def open_report(release):
            opened = native_open(release)
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

        def construct_release():
            data = sessions["model-reader"].receive(
                source, use=use, groups=["values"],
                decide=lambda admission: context.catalog.accepts(admission, context.policy_dag),
            )
            tool_data = data.copy()
            run_id = "report-request-" + str(len(releases) + 1)
            tool_data.set(None, {
                "run_id": run_id, "request_digest": "sha256:" + "a" * 64,
                "tool_name": requirements["required_tool"], "model_tool_call_id": "creation-log",
                "source_object_id": source.id, "source_writer": source.writer,
                "source_type": source.object_type, "selected_sections": ["values"],
                "action": use.operation,
            }, group="default")
            tool_data.select(["default"])
            tool = sessions["model-writer"].release(
                tool_data, use=use, to=requirements["report_destination"],
                decide=accept_release,
                object_type="compliance.creation.logged",
            )
            events.append("tool-released")
            data.include(sessions["model-writer"].receive(
                tool, use=use, groups=["default"],
                decide=lambda admission: context.catalog.accepts(admission, context.policy_dag),
            ))
            html = f"<p>{NOTICE}</p><p>ACME internal report.</p>"
            data.set(None, {"report_html": html}, group="default")
            data.select(["default"])
            output = sessions["model-writer"].release(
                data, use=use, to=requirements["report_destination"],
                decide=accept_release,
                object_type="report.generated",
            )
            events.append("report-released")
            release = NativeModelRelease(run_id, source.id, output.id, output, [], (tool,))
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

        monkeypatch.setattr("tn_governed.llama.GovernedLlamaClient", Client)
        endpoint = NativeModelEndpoint(
            context=context, value=value, base_url="http://unused", api_key="test",
            output_reader=reader, directory=directory, requirements=requirements,
            runtime_config=config,
        )
        yield SimpleNamespace(
            context=context, value=value, endpoint=endpoint, reader=reader, events=events,
            releases=releases, root=tmp_path, queue=queue,
            record_count=len(context.recorder.records()), source=source,
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
