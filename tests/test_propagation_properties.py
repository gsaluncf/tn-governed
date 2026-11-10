"""Randomized propagation properties checked against independent oracles.

Each generator builds a governed computation and the same computation over plain
values. The oracle derives the expected policies and claims from the operands the
generator chose, and compares values with ordinary SQLite, Polars, and Python.
"""

import random
import sqlite3
from contextlib import ExitStack, closing
from dataclasses import dataclass
from types import SimpleNamespace

import polars as pl
import pytest
import tn
from test_polars_plans import admit, opened
from test_polars_plans import relation as relation
from test_sql_query_results import database as database
from test_sql_query_results import sql_endpoint as sql_endpoint
from tn_polars import PlanTransform
from tn_polars.registry import UnityCatalogRegistry

from experiments.paper_evaluation.frames import DataframeContext, DataframeGovernance
from tn_governed.native_objects import NativeObjects
from tn_governed.values.catalog import AssignedRules, markdown
from tn_governed.values.evidence import EvidenceRecorder
from tn_governed.values.provision import provision
from tn_governed.values.sql import GovernedSQL, source_identity

SCALAR_CASES = 40
SQL_CASES = 60
PLAN_CASES = 40
APPLICATION, PURPOSE = "analytics", "internal"


@pytest.fixture
def market(tmp_path, monkeypatch):
    """SQL cells with one policy per column, native keys, and a local catalog transport."""
    volumes = {}

    def request(self, method, path, payload=None):
        if path in {"/catalogs", "/schemas"}:
            return {}
        if method == "POST" and path == "/volumes":
            full = f"{payload['catalog_name']}.{payload['schema_name']}.{payload['name']}"
            volumes[full] = dict(payload)
            return volumes[full]
        return volumes[path.removeprefix("/volumes/")]

    monkeypatch.setattr(UnityCatalogRegistry, "_request", request)
    path = tmp_path / "market.sqlite"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE market_data (name TEXT NOT NULL, value INTEGER NOT NULL)")
        connection.executemany("INSERT INTO market_data VALUES (?, ?)",
                               [(f"ada-{i}", 10 + i) for i in range(6)])
        connection.commit()
    paths = provision(tmp_path / "sessions", roles=["catalog", "worker"])
    with ExitStack() as stack:
        sessions = {role: stack.enter_context(tn.Session.from_config(str(paths[role])))
                    for role in ("catalog", "worker")}
        store = stack.enter_context(NativeObjects())
        admin = sessions["catalog"].policy("experiment.administration")
        audit = sessions["catalog"].policy("experiment.evidence")

        def resolver(role):
            return DataframeGovernance("http://unused", "properties", session=sessions[role],
                                       authority=sessions["catalog"].did, administration=admin,
                                       store=store)

        publisher = resolver("catalog")
        publisher.publish_assignment(
            tmp_path / "assignment", table="market_data", source_identity=source_identity(path),
            application=APPLICATION, actors=["analyst"], purposes=[PURPOSE],
            columns={name: {"kind": kind, "markdown": markdown(name),
                           "rule": {"destinations": ["internal-console"]}}
                     for name, kind in (("name", "str"), ("value", "int"))})
        resolution = resolver("worker")
        rules = AssignedRules(resolution, actor="analyst", application=APPLICATION, purpose=PURPOSE,
                              writers=[sessions["worker"].did])
        context = DataframeContext(sessions["worker"], EvidenceRecorder(sessions["worker"], store, audit),
                                   rules, application=APPLICATION, purpose=PURPOSE, actor="analyst",
                                   resolver=resolution)
        driver = GovernedSQL(path, gateway=context, consumer=context, edition_publisher=publisher,
                             directory=tmp_path / "editions")
        rows = driver.execute("SELECT name, value FROM market_data LIMIT ?", (6,)).fetchall()
        yield SimpleNamespace(context=context, rows=rows)


@dataclass(frozen=True)
class Operand:
    governed: object
    plain: object
    policies: frozenset
    claims: frozenset


def revisions(context, value):
    data, _, _ = context._metadata(value)
    return frozenset(policy.revision_id for policy in data.policies)


def claim_ids(context, value):
    _, binding, _ = context._metadata(value)
    return frozenset(binding["claims"])


def leaves(market, generator):
    context, result = market.context, []
    for name, amount in market.rows:
        plain_name = name.reveal(context, destination="internal-console")
        plain_amount = amount.reveal(context, destination="internal-console")
        if generator.random() < 0.5:
            name = name.attest(f"Statement about {plain_name}.", context)
        result.append(Operand(name, plain_name, revisions(context, name), claim_ids(context, name)))
        result.append(Operand(amount, plain_amount, revisions(context, amount), claim_ids(context, amount)))
    return result


def combined(left, right, governed, plain):
    return Operand(governed, plain, left.policies | right.policies, left.claims | right.claims)


def extended(operand, governed, plain):
    return Operand(governed, plain, operand.policies, operand.claims)


def step_number(generator, left, right):
    if generator.random() < 0.3:
        literal = generator.randint(1, 9)
        return extended(left, left.governed + literal, left.plain + literal)
    choice = generator.choice(("add", "subtract", "multiply"))
    if choice == "add":
        return combined(left, right, left.governed + right.governed, left.plain + right.plain)
    if choice == "subtract":
        return combined(left, right, left.governed - right.governed, left.plain - right.plain)
    return combined(left, right, left.governed * right.governed, left.plain * right.plain)


def step_string(generator, left, right):
    choice = generator.choice(("upper", "slice", "literal", "concat"))
    if choice == "upper":
        return extended(left, left.governed.upper(), left.plain.upper())
    if choice == "slice":
        return extended(left, left.governed[:3], left.plain[:3])
    if choice == "literal":
        return extended(left, left.governed + "/x", left.plain + "/x")
    return combined(left, right, left.governed + right.governed, left.plain + right.plain)


def random_expression(generator, operands):
    numbers = [o for o in operands if type(o.plain) is int]
    strings = [o for o in operands if type(o.plain) is str]
    number, text = generator.choice(numbers), generator.choice(strings)
    for _ in range(generator.randint(1, 4)):
        number = step_number(generator, number, generator.choice(numbers))
        text = step_string(generator, text, generator.choice(strings))
    return combined(text, number, text.governed + number.governed.as_string(),
                    text.plain + str(number.plain))


def test_scalar_results_carry_the_policy_and_claim_union_of_their_operands(market):
    generator, context = random.Random(20261102), market.context
    with context:
        operands = leaves(market, generator)
        for _ in range(SCALAR_CASES):
            result = random_expression(generator, operands)
            assert result.governed.reveal(context, destination="internal-console") == result.plain
            assert revisions(context, result.governed) == result.policies
            assert claim_ids(context, result.governed) == result.claims


COLUMNS = {"orders": ("id", "customer_id", "amount"), "customers": ("id", "enabled", "label")}


def source_columns(metadata):
    return {(item["table"], item["column"]) for item in metadata["binding"]["sources"]}


def random_statement(generator):
    """Return SQL and the set of columns whose rules apply."""
    aggregate = generator.random() < 0.4
    used = {("orders", "amount")}
    predicate = ""
    join = ""
    if generator.random() < 0.6:
        join = " JOIN customers c ON o.customer_id = c.id"
        used |= {("orders", "customer_id"), ("customers", "id")}
        if generator.random() < 0.5:
            predicate = " WHERE c.enabled = 1"
            used.add(("customers", "enabled"))
    elif generator.random() < 0.5:
        predicate = " WHERE o.id > 1"
        used.add(("orders", "id"))
    if aggregate:
        group = generator.choice(("o.customer_id", "o.id"))
        used.add(("orders", group.split(".")[1]))
        sql = f"SELECT {group}, sum(o.amount * 2) AS total FROM orders o{join}{predicate} GROUP BY {group} ORDER BY 1"
    else:
        sql = f"SELECT o.amount + 1 AS total FROM orders o{join}{predicate} ORDER BY 1"
    if generator.random() < 0.3:
        return f"WITH shaped AS ({sql}) SELECT * FROM shaped", used
    return sql, used


def test_sql_results_retain_every_read_column_and_match_ordinary_sqlite(sql_endpoint, database):
    generator = random.Random(20261103)
    with closing(sqlite3.connect(database)) as plain:
        for _ in range(SQL_CASES):
            sql, used = random_statement(generator)
            result = sql_endpoint.driver.execute_query(sql)
            metadata = result.metadata()
            expected = plain.execute(sql).fetchall()
            assert result.reveal("support-console") == expected, sql
            assert used <= source_columns(metadata), sql
            assert len({p.revision_id for p in result.policies}) == len(source_columns(metadata))
            assert "lineage" not in metadata and "sql" not in metadata["binding"]


def random_plan(generator):
    """Return one Polars plan and whether it selects rows by a data-dependent rule."""
    steps, selective = [], False
    if generator.random() < 0.5:
        limit = generator.choice((1.0, 3.0, 5.0))
        steps.append(lambda frame, limit=limit: frame.filter(pl.col("amount") > limit))
        selective = True
    if generator.random() < 0.5:
        steps.append(lambda frame: frame.sort("amount", descending=True))
        selective = True
    factor = generator.randint(2, 5)
    steps.append(lambda frame, factor=factor: frame.with_columns(
        (pl.col("amount") * factor).alias("scaled")))
    if generator.random() < 0.5:
        steps.append(lambda frame: frame.group_by("group", maintain_order=True).agg(
            pl.col("scaled").sum()))
        selective = True

    def plan(frame):
        for step in steps:
            frame = step(frame)
        return frame

    return plan, selective


def test_polars_plans_match_ordinary_polars_and_retain_their_policies(relation):
    generator = random.Random(20261104)
    session = relation[0]
    plain = pl.DataFrame([{"id": 1, "group": "a", "amount": 2.0}, {"id": 2, "group": "a", "amount": 4.0},
                          {"id": 3, "group": "b", "amount": 7.0}])
    for index in range(PLAN_CASES):
        plan, selective = random_plan(generator)
        frame = admit(relation)
        governed = frame.transform(PlanTransform(f"random-{index}", "1", plan))
        publication = governed.release_tn(use=tn.UseContext("analytics", "portfolio_analysis", "compute"),
                                          to="internal", decide=lambda _: True)
        rows, audit = opened(session, publication)
        assert rows == plan(plain.lazy()).collect().to_dicts()
        assert set(audit["policies"]) == set(frame._tn.policies.revision_ids)
        assert not session.governance(publication).governance.sources
