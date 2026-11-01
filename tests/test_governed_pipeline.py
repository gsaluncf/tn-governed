"""Native SQL, dataframe, endpoint, tool and recipient composition."""

import json

import polars as pl
import pytest
import tn
from test_sql_query_results import database as database
from test_sql_query_results import sql_endpoint as sql_endpoint
from tn_polars import (
    Decision,
    EndpointEvaluator,
    PlanTransform,
    from_admitted_query,
    import_frame,
    load_relation,
    open_audited_frame,
)
from tn_polars.authority import policy_identity

from tn_governed.endpoints import Endpoint
from tn_governed.publications import PublicationStore
from tn_governed.tool_runtime import (
    Call,
    ProviderTurn,
    ToolRegistry,
    ToolRunner,
    ToolSpec,
    ToolWorkflow,
)
from tn_governed.values.runtime import Assessment, ObligationResult
from tn_governed.values.string import OperationDenied

USE = tn.UseContext("analytics", "internal", "select")


def prepared(sql_endpoint, tmp_path):
    result = sql_endpoint.driver.execute_query(
        "SELECT o.amount * 3 AS total, c.label FROM orders o "
        "JOIN customers c ON o.customer_id=c.id WHERE c.enabled=1 ORDER BY o.id"
    )
    admitted = result.open_for_processing("select", "support-console")
    policies = tuple(admitted.data.policies)
    evaluators = {
        policy_identity(policy): EndpointEvaluator(
            "analytics",
            "internal-use",
            "1",
            {},
            lambda request: Decision(
                request["use"]["purpose"] == "internal",
                "purpose",
                "decision:" + request["operation"],
            ),
        )
        for policy in policies
    }
    frame = from_admitted_query(admitted, use=USE, evaluators=evaluators)
    frame = frame.transform(
        PlanTransform(
            "group-totals", "1", lambda source: source.group_by("label").agg(pl.col("total").sum())
        )
    )
    publication = frame.release_tn(use=USE, to="support-console", decide=lambda _: True)
    session = sql_endpoint.contexts["consumer"].session
    audit = open_audited_frame(
        publication, session=session, use=USE, group="values", decide=lambda _: True
    )
    assert audit["support"]["known"] is False
    assert any(
        event["kind"] == "operation" and "upstream" in event["details"]["parameters"]
        for event in audit["events"]
    )
    writers = {context.session.did for context in sql_endpoint.contexts.values()}
    writers.add(sql_endpoint.resolvers["catalog"].session.did)
    evidence = tuple(
        resolver.session.policy("experiment.evidence")
        for resolver in sql_endpoint.resolvers.values()
    )

    def accepted(context):
        return context.writer in writers and all(
            any(policy.matches_contract(expected) for expected in policies)
            for policy in context.policies
        )

    endpoints = {
        role: Endpoint(
            session=context.session,
            store=PublicationStore(tmp_path / role),
            evidence_policy=context.session.policy("experiment.evidence"),
            evidence_policies=evidence,
            evaluator=lambda _: Assessment(True, "local operation"),
            application=role,
            purpose="internal",
            accept_metadata=accepted,
        )
        for role, context in sql_endpoint.contexts.items()
    }
    endpoint = endpoints["consumer"]
    artifact = import_frame(
        endpoint,
        publication,
        publications=tuple(
            sql_endpoint.store.get(identity) for identity in sql_endpoint.store.publication_sizes()
        ),
    )
    claimed = endpoint.attest(artifact, "Totals are from synthetic joined observations")
    attributed = endpoint.claims(claimed)[0]
    frame = load_relation(
        endpoint.store.read(claimed.reference.object_id),
        session=session,
        use=USE,
        group="values",
        rows_field="value",
        evaluators=evaluators,
        decide=accepted,
        verify_claim=endpoint.read_record,
    )
    frame = frame.with_columns((pl.col("total") + 2).alias("total"))
    publication = frame.release_tn(use=USE, to="support-console", decide=lambda _: True)
    audit = open_audited_frame(
        publication,
        session=session,
        use=USE,
        group="values",
        rows_field="value",
        decide=accepted,
        verify_claim=endpoint.read_record,
    )
    assert audit["claims"][0]["id"] == attributed.id
    artifact = import_frame(endpoint, publication)
    assert endpoint.metadata(artifact)["claims"] == [attributed.id]
    return endpoints, artifact, attributed, policies


def tools():
    return ToolRegistry(
        (
            ToolSpec(
                "sum_rows",
                {"type": "object", "maxProperties": 0},
                {"type": "number"},
                lambda inv: sum(row["total"] for row in inv.values[0]),
                model_visible=True,
            ),
            ToolSpec(
                "scale",
                {
                    "type": "object",
                    "properties": {"factor": {"type": "number"}},
                    "required": ["factor"],
                    "additionalProperties": False,
                },
                {"type": "number"},
                lambda inv: inv.values[0] * inv.arguments["factor"],
                model_visible=True,
            ),
        )
    )


def test_sql_polars_claim_tools_and_independent_recipient(sql_endpoint, tmp_path):
    peers, artifact, claim, policies = prepared(sql_endpoint, tmp_path)
    endpoint = peers["consumer"]
    endpoint.evaluator = lambda request: Assessment(
        True,
        "local purpose permits",
        ("ledger",) if request.operation == "workflow.release" else (),
    )
    endpoint.obligations["ledger"] = lambda _: ObligationResult(True, "ledger:derived-report")
    workflow = ToolWorkflow(
        endpoint, tools(), {"source": artifact}, required_tools=("sum_rows", "scale")
    )

    class Provider:
        identity = "local-planner"

        def turn(self, events, tool_schemas):
            completed = [event for event in events if event["kind"] == "tool"]
            if not completed:
                return ProviderTurn((Call("sum", "sum_rows", {}, ("source",)),))
            if len(completed) == 1:
                return ProviderTurn(
                    (
                        Call(
                            "scale",
                            "scale",
                            {"factor": 2},
                            (completed[0]["result"]["handle"],),
                            ("sum",),
                        ),
                    )
                )
            return ProviderTurn(text=json.dumps({"answer": completed[-1]["result"]["value"]}))

    output = ToolRunner(Provider()).run(
        workflow,
        "Compute the requested summary",
        result_schema={
            "type": "object",
            "properties": {"answer": {"type": "number"}},
            "required": ["answer"],
            "additionalProperties": False,
        },
        destination="internal-report",
    )
    recipient = peers["gateway"]
    received = recipient.receive(endpoint.export(output))
    assert recipient.reveal(received, destination="internal-report") == {"answer": 100}
    assert recipient.claims(received)[0] == claim
    assert {
        policy_identity(policy)
        for policy in recipient.session.governance(
            recipient.store.read(received.reference.object_id)
        ).governance.policies
    } == {policy_identity(policy) for policy in policies}
    decision = recipient.read_record(output.decision_id)
    assert decision.body["details"]["discharged"][0]["evidence"] == "ledger:derived-report"
    assert output.decision_id in recipient.metadata(received)["action_records"]
    recipient.evaluator = lambda _: Assessment(False, "recipient purpose differs")
    with pytest.raises(OperationDenied):
        recipient.reveal(received, destination="public")


def test_release_action_failure_blocks_pipeline_result(sql_endpoint, tmp_path):
    peers, artifact, _, _ = prepared(sql_endpoint, tmp_path)
    endpoint = peers["consumer"]
    workflow = ToolWorkflow(endpoint, tools(), {"source": artifact}, required_tools=("sum_rows",))
    workflow.execute(Call("sum", "sum_rows", {}, ("source",)))
    endpoint.evaluator = lambda request: Assessment(
        True, "conditional", ("approval",) if request.operation == "workflow.release" else ()
    )
    endpoint.obligations["approval"] = lambda _: ObligationResult(False, "unavailable")
    with pytest.raises(OperationDenied):
        workflow.finish({"answer": 50}, schema={"type": "object"}, destination="internal-report")
    assert not any(event["kind"] == "workflow_released" for event in workflow.events)


def test_frame_import_refusal_precedes_business_validation(sql_endpoint, tmp_path, monkeypatch):
    import tn_polars.endpoint as bridge

    peers, artifact, _, _ = prepared(sql_endpoint, tmp_path)
    endpoint = peers["consumer"]
    source_id = endpoint.metadata(artifact)["external_inputs"][0]["object_id"]
    publication = endpoint.store.read(source_id)
    calls = []
    monkeypatch.setattr(bridge, "verify_native_frame", lambda *args, **kwargs: calls.append(True))
    endpoint.evaluator = lambda _: Assessment(False, "destination refused")
    with pytest.raises(OperationDenied):
        import_frame(endpoint, publication)
    assert calls == []
