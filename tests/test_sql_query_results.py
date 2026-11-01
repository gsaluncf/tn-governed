"""SQL results retain source authority independently of projection shape."""

import sqlite3
from contextlib import ExitStack
from dataclasses import replace
from decimal import Decimal
from types import SimpleNamespace

import pytest
import tn
from tn.governed import GovernedError
from tn_polars.registry import LocalRegistry

from tn_governed.publications import PublicationStore
from tn_governed.values.catalog import AssignedRules, UnityGovernance, markdown
from tn_governed.values.evidence import EvidenceError, EvidenceRecorder
from tn_governed.values.primitives import VALUE_TYPE, Context
from tn_governed.values.provision import provision
from tn_governed.values.query import (
    CellLineage,
    Contributor,
    LineageProvider,
    QueryLineage,
    SQLFunction,
    SQLiteQuery,
    decode_sql,
    digest,
    encode_sql,
)
from tn_governed.values.sql import GovernedSQL, source_identity
from tn_governed.values.string import OperationDenied


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "source.sqlite"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE orders (id INTEGER, customer_id INTEGER, amount INTEGER);
            CREATE TABLE customers (id INTEGER, enabled INTEGER, label TEXT);
            INSERT INTO orders VALUES (1,10,4),(2,10,4),(3,20,9),(4,99,2);
            INSERT INTO customers VALUES (10,1,'same'),(10,1,'same'),(20,0,'other');
        """)
    return path


class CatalogTransport(LocalRegistry):
    catalog, schema = "query_results", "governance"

    def __init__(self, root):
        super().__init__(root)
        self.locations = {}

    def _ensure(self, path, body):
        if path == "/volumes":
            self.locations[body["name"]] = body["storage_location"]

    def _request(self, method, path):
        name = path.rsplit(".", 1)[-1]
        return {"storage_location": self.locations[name], "volume_id": name}


@pytest.fixture
def sql_endpoint(tmp_path, database):
    roles = ("catalog", "gateway", "consumer")
    paths = provision(tmp_path / "sessions", roles=roles, read_only_roles=())
    with ExitStack() as stack:
        sessions = {
            name: stack.enter_context(tn.Session.from_config(str(path)))
            for name, path in paths.items()
        }
        store = PublicationStore(tmp_path / "objects")
        transport = CatalogTransport(tmp_path / "registry")
        admin = sessions["catalog"].policy("experiment.administration")
        resolvers = {}
        for name, session in sessions.items():
            resolver = UnityGovernance(
                "http://unused",
                transport.catalog,
                session=session,
                authority=sessions["catalog"].did,
                administration=admin,
                store=store,
            )
            resolver.registry = transport
            resolvers[name] = resolver
        identity = source_identity(database)
        for table, columns in {
            "orders": {"id": "int", "customer_id": "int", "amount": "int"},
            "customers": {"id": "int", "enabled": "int", "label": "str"},
        }.items():
            resolvers["catalog"].publish_assignment(
                tmp_path / table,
                table=table,
                source_identity=identity,
                application="analytics",
                actors=["analyst"],
                purposes=["internal"],
                columns={
                    column: {
                        "kind": kind,
                        "markdown": markdown(column),
                        "rule": {
                            "sql_lineage": ["conservative", "exact"],
                            "additional_uses": [
                                {"application": "archive", "purpose": "audit", "operation": "read"},
                                {"application": table, "purpose": "internal", "operation": "read"},
                            ],
                        },
                    }
                    for column, kind in columns.items()
                },
            )
        contexts = {}
        for name in roles[1:]:
            rules = AssignedRules(
                resolvers[name],
                actor="analyst",
                application="analytics",
                purpose="internal",
                writers=[sessions["gateway"].did, sessions[name].did],
            )
            contexts[name] = Context(
                sessions[name],
                EvidenceRecorder(
                    sessions[name], store, sessions["catalog"].policy("experiment.evidence")
                ),
                rules,
                application="analytics",
                purpose="internal",
                actor="analyst",
                resolver=resolvers[name],
            )
        driver = GovernedSQL(
            database,
            gateway=contexts["gateway"],
            consumer=contexts["consumer"],
            edition_publisher=resolvers["catalog"],
            directory=tmp_path / "editions",
        )
        yield SimpleNamespace(
            driver=driver,
            resolvers=resolvers,
            contexts=contexts,
            store=store,
            paths=paths,
            stack=stack,
        )


JOIN = """SELECT o.amount * :factor AS total, c.label AS label
          FROM orders AS o JOIN customers AS c ON o.customer_id = c.id
          WHERE c.enabled = :enabled ORDER BY o.id, c.rowid"""


def test_engine_discovers_control_columns_without_running_functions(database):
    calls = []
    function = SQLFunction(
        "observe", 1, lambda value: calls.append(value) or value, authority="endpoint:accounting"
    )
    with SQLiteQuery(
        database,
        "SELECT observe(o.amount) FROM orders o JOIN customers c "
        "ON o.customer_id=c.id WHERE c.enabled=?",
        (1,),
        functions=(function,),
    ) as query:
        assert calls == []
        assert {
            ("orders", "amount"),
            ("orders", "customer_id"),
            ("customers", "id"),
            ("customers", "enabled"),
        } <= {(source.table, source.column) for source in query.dependencies}
        rows = query.execute()
        assert rows.rows == ((4,), (4,), (4,), (4,))
        assert calls == [4, 4, 4, 4]


def test_join_preserves_configured_decimal_conversion(tmp_path, monkeypatch):
    monkeypatch.setitem(sqlite3.converters, "DECIMAL_TEXT", lambda raw: Decimal(raw.decode()))
    database = tmp_path / "decimal.sqlite"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            "CREATE TABLE prices(id INTEGER, amount DECIMAL_TEXT);"
            "CREATE TABLE items(id INTEGER); INSERT INTO prices VALUES(1,'1.2300');"
            "INSERT INTO items VALUES(1);"
        )
    with SQLiteQuery(
        database,
        "SELECT p.amount FROM prices p JOIN items i ON p.id=i.id",
        detect_types=sqlite3.PARSE_DECLTYPES,
    ) as query:
        result = query.execute()
    value = result.rows[0][0]
    assert type(value) is Decimal
    assert decode_sql(encode_sql(value)).as_tuple() == Decimal("1.2300").as_tuple()
    assert result.schema[0]["storage_types"] == ["Decimal"]


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM orders RETURNING amount",
        "PRAGMA user_version",
        "ATTACH ':memory:' AS extra",
        "SELECT load_extension('x') FROM orders",
        "SELECT amount FROM orders; DELETE FROM orders",
    ],
)
def test_engine_denies_statements_outside_read_only_query_contract(database, sql):
    with pytest.raises((OperationDenied, sqlite3.Error)), SQLiteQuery(database, sql):
        pytest.fail("statement should not prepare")


def test_join_result_preserves_duplicate_rows_and_unprojected_policy(sql_endpoint):
    result = sql_endpoint.driver.execute(JOIN, {"factor": 3, "enabled": 1})
    assert result.reveal("support-console") == [(12, "same")] * 4
    manifest = result.metadata()
    assert manifest["lineage"]["precision"] == "conservative"
    assert manifest["lineage"]["row_support"] == "known"
    assert manifest["lineage"]["control_scope"] == "source-snapshot"
    sources = {(item["table"], item["column"]) for item in manifest["binding"]["sources"]}
    assert ("customers", "enabled") in sources
    assert ("orders", "customer_id") in sources
    policies = result.policies
    assert {policy.revision_id for policy in policies} == {
        sql_endpoint.resolvers["gateway"].assignments[item["assignment_id"]]["columns"][
            item["column"]
        ]["revision"]
        for item in manifest["binding"]["sources"]
    }
    assert len(result.fetchall()) == 4


def test_retained_query_ancestors_contain_rows_only_under_the_full_policy_union(
    sql_endpoint, monkeypatch
):
    retained = []
    put = sql_endpoint.store.put

    def retain(obj):
        if obj.object_type == VALUE_TYPE:
            retained.append(obj)
        return put(obj)

    monkeypatch.setattr(sql_endpoint.store, "put", retain)
    result = sql_endpoint.driver.execute_query(JOIN, {"factor": 3, "enabled": 1})
    required = {policy.revision_id for policy in result.policies}
    assert len(required) > 1
    with_rows = []
    for obj in retained:
        if "rows" not in obj.envelope.get("values", {}).get("field_hashes", {}):
            continue

        def inspect(ctx):
            assert {policy.revision_id for policy in ctx.policies} == required
            return True

        sql_endpoint.contexts["gateway"].session.governance(obj).accept(
            use=tn.UseContext("analytics", "internal", "inspect-claims"),
            groups=["values"],
            decide=inspect,
        )
        with_rows.append(obj.id)
    assert result.object_id in with_rows


def test_query_edition_grants_only_common_additional_uses(sql_endpoint):
    result = sql_endpoint.driver.execute_query(JOIN, {"factor": 3, "enabled": 1})
    record = sql_endpoint.contexts["consumer"].editions[result.object_id]
    uses = {(use.application, use.purpose, use.operation) for use in record.eligible_uses}
    assert ("archive", "audit", "read") in uses
    assert ("orders", "internal", "read") not in uses
    assert ("customers", "internal", "read") not in uses


@pytest.mark.parametrize(
    "query, expected",
    [
        (
            "SELECT o.id, c.label FROM orders o LEFT JOIN customers c ON o.customer_id=c.id "
            "WHERE o.id=4",
            [(4, None)],
        ),
        ("SELECT amount AS x, id AS x FROM orders WHERE id=1", [(4, 1)]),
        ("SELECT sum(amount), count(*) FROM orders", [(19, 4)]),
        (
            "SELECT amount, sum(amount) OVER (ORDER BY id) FROM orders ORDER BY id",
            [(4, 4), (4, 8), (9, 17), (2, 19)],
        ),
        ("SELECT amount FROM orders WHERE id < 0", []),
        ("SELECT CAST(amount AS BLOB) FROM orders WHERE id=1", [(b"4",)]),
    ],
)
def test_native_relation_represents_sql_shapes(sql_endpoint, query, expected):
    result = sql_endpoint.driver.execute_query(query)
    assert result.reveal("support-console") == expected
    assert result.metadata()["row_count"] == len(expected)
    if expected:
        cells = result.fetchall()
        assert cells[0][0].reveal("support-console") == expected[0][0]
    assert result.edition["source_object_id"] == result.object_id


def test_unknown_row_support_requires_every_signed_source_permission(sql_endpoint, monkeypatch):
    resolver = sql_endpoint.resolvers["gateway"]
    resolve = resolver.resolve_query

    def disallow(*args, **kwargs):
        resolution = resolve(*args, **kwargs)
        control = next(
            source
            for source in resolution.sources
            if source["table"] == "customers" and source["column"] == "enabled"
        )
        resolver.rules[control["revision_id"]].pop("sql_lineage", None)
        return resolution

    monkeypatch.setattr(resolver, "resolve_query", disallow)
    with pytest.raises(OperationDenied):
        sql_endpoint.driver.execute_query(JOIN, {"factor": 3, "enabled": 1})
    assert not sql_endpoint.driver.executions


def test_all_sources_resolve_before_user_function_runs(sql_endpoint):
    calls = []
    sql_endpoint.driver.functions = (
        SQLFunction(
            "observe",
            1,
            lambda value: calls.append(value) or value,
            authority="endpoint:accounting",
        ),
    )
    sql_endpoint.resolvers["gateway"].registry.locations.pop("source_customers")
    with pytest.raises(KeyError):
        sql_endpoint.driver.execute_query(
            "SELECT observe(o.amount) FROM orders o JOIN customers c ON o.customer_id=c.id"
        )
    assert calls == []


def test_changed_bound_parameters_and_schema_change_signed_binding(sql_endpoint):
    first = sql_endpoint.driver.execute_query("SELECT amount AS first FROM orders WHERE id=?", (1,))
    second = sql_endpoint.driver.execute_query(
        "SELECT amount AS first FROM orders WHERE id=?", (2,)
    )
    third = sql_endpoint.driver.execute_query(
        "SELECT amount AS second FROM orders WHERE id=?", (1,)
    )
    bindings = [result.metadata()["binding"] for result in (first, second, third)]
    assert bindings[0]["parameters"] != bindings[1]["parameters"]
    assert bindings[0]["output_schema"] != bindings[2]["output_schema"]
    assert (
        len(
            {
                digest({key: value for key, value in binding.items() if key != "query_id"})
                for binding in bindings
            }
        )
        == 3
    )


def test_cell_selection_is_authorized_before_values_are_opened(sql_endpoint, monkeypatch):
    result = sql_endpoint.driver.execute_query("SELECT amount, id FROM orders ORDER BY id")
    context = sql_endpoint.contexts["consumer"]
    evaluator = context.evaluator
    seen = []

    def evaluate(request):
        if request.operation == "reveal":
            seen.append(request.parameters[1])
        return evaluator(request)

    context.evaluator = evaluate
    receive = result._receive

    def opening(groups, operation):
        if "values" in groups:
            assert seen == [{"selection": "cell", "row": 0, "column": 1}]
        return receive(groups, operation)

    monkeypatch.setattr(result, "_receive", opening)
    assert result.fetchall()[0][1].reveal("support-console") == 1


def test_disclosure_rejects_signed_output_type_mismatch(sql_endpoint, monkeypatch):
    from tn_governed.values import query_result

    publish = query_result.publish_result

    def mismatched(context, rows, binding, lineage, **kwargs):
        binding = {
            **binding,
            "output_schema": [
                {**column, "storage_types": ["str"]} for column in binding["output_schema"]
            ],
        }
        return publish(context, rows, binding, lineage, **kwargs)

    monkeypatch.setattr(query_result, "publish_result", mismatched)
    result = sql_endpoint.driver.execute_query("SELECT amount FROM orders WHERE id=1")
    with pytest.raises(EvidenceError, match="schema"):
        result.reveal("support-console")


@pytest.mark.parametrize(
    "invalid",
    [
        {"kind": "int", "value": "not-an-integer"},
        {"kind": "null", "value": "not-null"},
        {"kind": "bytes", "value": "zz"},
        {"kind": "float", "value": "00"},
        {"kind": "str", "value": 4},
        {"kind": "int", "value": "04"},
    ],
)
def test_cell_reveal_validates_every_opened_encoding(sql_endpoint, monkeypatch, invalid):
    from tn_governed.values import query_result

    encode = query_result.encode_sql
    monkeypatch.setattr(
        query_result, "encode_sql", lambda value: invalid if value == 4 else encode(value)
    )
    result = sql_endpoint.driver.execute_query("SELECT amount, id FROM orders WHERE id=1")
    monkeypatch.setattr(query_result, "encode_sql", encode)
    cell = result.fetchall()[0][1]
    with pytest.raises(EvidenceError):
        cell.reveal("support-console")


def test_exact_mapping_requires_configured_validator_and_position_keys(sql_endpoint):
    seen = []

    def mapping(binding, result):
        return QueryLineage(
            "exact",
            tuple(
                CellLineage(row, 0, (Contributor("orders", "amount", (row + 1,)),))
                for row in range(len(result.rows))
            ),
        )

    def validate(binding, result, lineage):
        seen.append(binding["sql"])
        return len(lineage.cells) == len(result.rows)

    sql_endpoint.driver.lineage_provider = LineageProvider("catalog:rowids", mapping, validate)
    result = sql_endpoint.driver.execute_query("SELECT amount FROM orders ORDER BY id")
    assert result.reveal("support-console") == [(4,), (4,), (9,), (2,)]
    assert result.metadata()["lineage"]["precision"] == "exact"
    assert seen == ["SELECT amount FROM orders ORDER BY id"]
    assert (
        result.metadata()["lineage"]["cells"][0]["contributors"][0]["row_key"]
        != (result.metadata()["lineage"]["cells"][1]["contributors"][0]["row_key"])
    )


def test_provider_cannot_omit_positions_or_claim_unassigned_sources(sql_endpoint):
    def invalid(binding, result):
        return QueryLineage(
            "exact", (CellLineage(0, 0, (Contributor("elsewhere", "secret", (1,)),)),)
        )

    sql_endpoint.driver.lineage_provider = LineageProvider(
        "catalog:rowids", invalid, lambda *_: True
    )
    with pytest.raises(OperationDenied, match="lineage"):
        sql_endpoint.driver.execute_query("SELECT amount FROM orders ORDER BY id")
    assert not sql_endpoint.driver.editions


def test_failed_provider_validation_cannot_publish(sql_endpoint):
    provider = LineageProvider(
        "catalog:rowids", lambda *_: QueryLineage("exact", ()), lambda *_: False
    )
    sql_endpoint.driver.lineage_provider = provider
    with pytest.raises(OperationDenied, match="lineage"):
        sql_endpoint.driver.execute_query("SELECT amount FROM orders WHERE id < 0")
    assert not sql_endpoint.driver.editions


def test_snapshot_with_wal_content_is_not_a_database_file_assignment(database):
    with sqlite3.connect(database) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("INSERT INTO orders VALUES (5,10,6)")
        writer.commit()
        with (
            pytest.raises(OperationDenied, match="WAL"),
            SQLiteQuery(database, "SELECT amount FROM orders"),
        ):
            pytest.fail("WAL content is absent from the signed file snapshot")


def test_consumer_rechecks_authority_before_result_disclosure(sql_endpoint):
    result = sql_endpoint.driver.execute_query("SELECT sum(amount) FROM orders")
    resolver = sql_endpoint.resolvers["consumer"]
    resolver.trust = replace(resolver.trust, metadata=lambda _: False)
    with pytest.raises(GovernedError):
        result.reveal("support-console")


def test_processing_boundary_preserves_native_policy_and_query_lineage(sql_endpoint, monkeypatch):
    result = sql_endpoint.driver.execute_query(JOIN, {"factor": 3, "enabled": 1})
    context = sql_endpoint.contexts["consumer"]
    evaluator = context.evaluator
    decisions = []

    def evaluate(request):
        decisions.append(request)
        return evaluator(request)

    context.evaluator = evaluate
    admitted = result.open_for_processing("select", "polars")
    assert admitted.rows == ((12, "same"),) * 4
    assert {policy.revision_id for policy in admitted.data.policies} == {
        policy.revision_id for policy in result.policies
    }
    assert admitted.reference.object_id == result.object_id
    assert admitted.manifest == result.metadata()
    assert decisions[-1].destination == "polars"
    assert decisions[-1].parameters[1] == {"selection": "processing", "destination": "polars"}
    assert context.recorder.read(admitted.decision_id).body["kind"] == "Decision"


def test_transport_admits_without_publisher_store_or_online_registry(sql_endpoint, tmp_path):
    from tn_governed.values.query_result import GovernedQueryResult, QueryTransport

    result = sql_endpoint.driver.execute_query(JOIN, {"factor": 3, "enabled": 1})
    packet = QueryTransport.from_bytes(result.export().to_bytes())
    sql_endpoint.driver.database.unlink()
    original = sql_endpoint.contexts["consumer"]
    recipient_session = sql_endpoint.stack.enter_context(
        tn.Session.from_config(str(sql_endpoint.paths["consumer"]))
    )
    store = PublicationStore(tmp_path / "receiver")
    resolver = UnityGovernance(
        "http://offline",
        "offline",
        session=recipient_session,
        authority=original.resolver.authority,
        administration=original.resolver.administration,
        store=store,
    )
    resolver.registry._request = lambda *_: pytest.fail("portable admission must not call registry")
    evaluator = AssignedRules(
        resolver,
        actor="analyst",
        application="analytics",
        purpose="internal",
        writers=[sql_endpoint.contexts["gateway"].session.did],
    )
    receiver = Context(
        recipient_session,
        EvidenceRecorder(recipient_session, store, original.recorder.policy),
        evaluator,
        application="analytics",
        purpose="internal",
        actor="analyst",
        resolver=resolver,
    )
    received = GovernedQueryResult.receive(receiver, packet)
    assert received.reveal("support-console") == [(12, "same")] * 4
    assert receiver.catalog is not original.catalog
    assert receiver.policy_dag is not original.policy_dag
    assert receiver.recorder.head is not None


def test_portable_query_rejects_changed_contributor_source_list(sql_endpoint):
    from tn_governed.values.query_result import GovernedQueryResult

    packet = sql_endpoint.driver.execute_query(JOIN, {"factor": 3, "enabled": 1}).export()
    changed = replace(packet, sources=packet.sources[:-1])
    with pytest.raises((EvidenceError, OperationDenied, GovernedError)):
        GovernedQueryResult.receive(sql_endpoint.contexts["consumer"], changed)


@pytest.mark.parametrize("damage", ["missing", "duplicate", "source", "key"])
def test_recipient_rejects_invalid_signed_contributor_mappings(sql_endpoint, monkeypatch, damage):
    from copy import deepcopy

    from tn_governed.values import query_result

    publish = query_result.publish_result

    def malformed(context, rows, binding, lineage, **kwargs):
        lineage = deepcopy(lineage)
        if damage == "missing":
            lineage["cells"].pop()
        elif damage == "duplicate":
            lineage["cells"].append(lineage["cells"][0])
        elif damage == "source":
            lineage["cells"][0]["contributors"][0]["table"] = "unassigned"
        else:
            lineage["cells"][0]["contributors"][0]["row_key"] = [{"kind": "int", "value": "01"}]
        return publish(context, rows, binding, lineage, **kwargs)

    monkeypatch.setattr(query_result, "publish_result", malformed)
    with pytest.raises(EvidenceError, match="lineage"):
        sql_endpoint.driver.execute_query(JOIN, {"factor": 3, "enabled": 1})


def test_implicit_join_key_policy_is_checked_before_execution(sql_endpoint, monkeypatch):
    resolver = sql_endpoint.resolvers["gateway"]
    resolve = resolver.resolve_query

    def forbid_key(*args, **kwargs):
        resolution = resolve(*args, **kwargs)
        key = next(
            source
            for source in resolution.sources
            if source["table"] == "customers" and source["column"] == "id"
        )
        resolver.rules[key["revision_id"]]["operations"] = []
        return resolution

    monkeypatch.setattr(resolver, "resolve_query", forbid_key)
    with pytest.raises(OperationDenied):
        sql_endpoint.driver.execute_query("SELECT amount FROM orders JOIN customers USING(id)")
    assert sql_endpoint.driver.executions == []
