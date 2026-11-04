"""Relational query shapes retain admitted source scope through transport."""

import os

import pytest
from test_sql_query_results import database as database
from test_sql_query_results import sql_endpoint as sql_endpoint

from tn_governed.values.query import SQLiteQuery
from tn_governed.values.query_result import GovernedQueryResult, QueryTransport
from tn_governed.values.string import OperationDenied

SET_LEFT = "SELECT CASE WHEN id=4 THEN NULL ELSE amount END AS v FROM orders"
SET_RIGHT = (
    "SELECT CASE WHEN id=20 THEN NULL ELSE id/5 END AS v FROM customers WHERE enabled IN (0,1)"
)
QUERY_CASES = [
    pytest.param(
        "SELECT o.id, o.amount FROM orders o WHERE EXISTS "
        "(SELECT 1 FROM customers c WHERE c.id=o.customer_id AND c.enabled=:enabled) "
        "ORDER BY o.id",
        {"enabled": 1},
        [(1, 4), (2, 4)],
        {
            ("orders", "id"),
            ("orders", "amount"),
            ("orders", "customer_id"),
            ("customers", "id"),
            ("customers", "enabled"),
        },
        id="correlated-exists",
    ),
    pytest.param(
        "SELECT o.id, (SELECT sum(c.enabled) FROM customers c "
        "WHERE c.id=o.customer_id) AS enabled_matches FROM orders o ORDER BY o.id",
        (),
        [(1, 2), (2, 2), (3, 0), (4, None)],
        {
            ("orders", "id"),
            ("orders", "customer_id"),
            ("customers", "id"),
            ("customers", "enabled"),
        },
        id="correlated-scalar-aggregate",
    ),
    pytest.param(
        "WITH eligible AS (SELECT id FROM customers WHERE enabled=:enabled) "
        "SELECT o.id, o.amount*2 FROM orders o JOIN eligible e ON o.customer_id=e.id "
        "ORDER BY o.id",
        {"enabled": 1},
        [(1, 8), (1, 8), (2, 8), (2, 8)],
        {
            ("orders", "id"),
            ("orders", "amount"),
            ("orders", "customer_id"),
            ("customers", "id"),
            ("customers", "enabled"),
        },
        id="cte-join",
    ),
    *[
        pytest.param(
            f"{SET_LEFT} {operation} {SET_RIGHT} ORDER BY v",
            (),
            expected,
            {("orders", "id"), ("orders", "amount"), ("customers", "id"), ("customers", "enabled")},
            id=operation.lower().replace(" ", "-"),
        )
        for operation, expected in (
            ("UNION", [(None,), (2,), (4,), (9,)]),
            ("UNION ALL", [(None,), (None,), (2,), (2,), (4,), (4,), (9,)]),
            ("INTERSECT", [(None,)]),
            ("EXCEPT", [(4,), (9,)]),
        )
    ],
]


def require_exact_source(resolver, monkeypatch):
    """Require exact lineage for the unprojected customer-eligibility source."""
    resolve = resolver.resolve_query

    def resolve_exact(*args, **kwargs):
        resolution = resolve(*args, **kwargs)
        control = next(
            source
            for source in resolution.sources
            if source["table"] == "customers" and source["column"] == "enabled"
        )
        resolver.rules[control["revision_id"]]["sql_lineage"] = ["exact"]
        return resolution

    monkeypatch.setattr(resolver, "resolve_query", resolve_exact)


def assert_precision_refusal(context):
    refusal = context.recorder.read(context.recorder.head)
    assert refusal.body["kind"] == "Refusal"
    decision = context.recorder.read(refusal.body["details"]["decision_id"])
    assert decision.body["kind"] == "Decision"
    assert decision.body["details"]["permitted"] is False
    assert "lineage precision" in decision.body["details"]["reason"]
    assert refusal.body["details"]["reason"] == decision.body["details"]["reason"]


def test_snapshot_change_preserving_file_metadata_fails_the_final_hash(database):
    with SQLiteQuery(database, "SELECT amount FROM orders") as query:
        status = database.stat()
        content = bytearray(database.read_bytes())
        content[-1] ^= 1
        database.write_bytes(bytes(content))
        os.utime(database, ns=(status.st_atime_ns, status.st_mtime_ns))
        with pytest.raises(OperationDenied, match="changed"):
            query.execute()


def test_source_scope_is_selectable_for_a_query_with_known_contributors(sql_endpoint):
    sql = "SELECT sum(o.amount) FROM orders o"
    tracked = sql_endpoint.driver.execute_query(sql)
    scoped = sql_endpoint.driver.execute_query(sql, contributor_tracking=False)
    assert tracked.metadata()["lineage"]["row_support"] == "known"
    assert tracked.metadata()["lineage"]["contributor_rows"]
    lineage = scoped.metadata()["lineage"]
    assert lineage["row_support"] == "unknown"
    assert lineage["cells"] == []
    assert {item["column"] for item in lineage["source_columns"]} == {"amount"}
    assert {p.revision_id for p in scoped.policies} == {p.revision_id for p in tracked.policies}
    assert scoped.reveal("support-console") == tracked.reveal("support-console") == [(19,)]


@pytest.mark.parametrize("sql,parameters,expected,required_sources", QUERY_CASES)
def test_source_scoped_query_preserves_values_policies_and_transport(
    sql_endpoint, sql, parameters, expected, required_sources
):
    result = sql_endpoint.driver.execute_query(sql, parameters)
    manifest = result.metadata()
    sources = manifest["binding"]["sources"]
    source_columns = {(item["table"], item["column"]) for item in sources}
    assert source_columns >= required_sources
    assert manifest["binding"]["sql"] == sql
    assert manifest["lineage"]["precision"] == "conservative"
    assert manifest["lineage"]["row_support"] == "unknown"
    assert manifest["lineage"]["cells"] == []
    assert {
        (item["table"], item["column"]) for item in manifest["lineage"]["source_columns"]
    } == source_columns
    expected_policies = {item["revision_id"] for item in sources}
    assert {policy.revision_id for policy in result.policies} == expected_policies
    assert {item["table"] for item in sources} == {"orders", "customers"}
    assert all(item["assignment_id"] and item["scope"] for item in sources)

    transport = QueryTransport.from_bytes(result.export().to_bytes())
    received = GovernedQueryResult.receive(sql_endpoint.contexts["consumer"], transport)
    assert received.reveal("support-console") == expected
    assert received.metadata() == manifest
    assert {policy.revision_id for policy in received.policies} == expected_policies
    admitted = received.open_for_processing("select", "polars")
    assert admitted.rows == tuple(expected)
    assert admitted.manifest["lineage"]["row_support"] == "unknown"
    assert {policy.revision_id for policy in admitted.data.policies} == expected_policies


@pytest.mark.parametrize("sql,parameters,expected,required_sources", QUERY_CASES)
def test_source_scoped_query_is_refused_before_execution_when_exact_is_required(
    sql_endpoint, monkeypatch, sql, parameters, expected, required_sources
):
    require_exact_source(sql_endpoint.resolvers["gateway"], monkeypatch)
    with pytest.raises(OperationDenied, match="refused; decision"):
        sql_endpoint.driver.execute_query(sql, parameters)
    assert_precision_refusal(sql_endpoint.contexts["gateway"])
    assert sql_endpoint.driver.executions == []
    assert sql_endpoint.driver.editions == []


@pytest.mark.parametrize("sql,parameters,expected,required_sources", QUERY_CASES)
def test_recipient_refuses_coarse_query_evidence_under_its_local_precision_rule(
    sql_endpoint, monkeypatch, sql, parameters, expected, required_sources
):
    result = sql_endpoint.driver.execute_query(sql, parameters)
    assert result.reveal("support-console") == expected
    manifest = result.metadata()
    require_exact_source(sql_endpoint.resolvers["consumer"], monkeypatch)
    with pytest.raises(OperationDenied, match="refused; decision"):
        result.reveal("support-console")
    assert_precision_refusal(sql_endpoint.contexts["consumer"])
    with pytest.raises(OperationDenied, match="refused; decision"):
        result.open_for_processing("select", "polars")
    assert_precision_refusal(sql_endpoint.contexts["consumer"])
    assert result.publication.object.id == result.object_id
    assert manifest["lineage"]["row_support"] == "unknown"
