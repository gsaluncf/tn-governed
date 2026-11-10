"""Relation-granular overhead on the market and TPC-H-derived workloads.

Each query runs through the governed path: authorized SQLite execution, one
signed relation publication, processing admission, governed Polars, and release.
Each recipient checks the policy set on the released result. The baseline uses the
same SQLite statement and Polars plan. Both outputs are compared outside the timer.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import statistics
import time
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from contextlib import ExitStack, closing
from multiprocessing import get_context
from pathlib import Path

import polars as pl
import tn
from tn_polars import Decision, EndpointEvaluator, PlanTransform, from_admitted_query
from tn_polars.authority import policy_identity
from tn_polars.registry import LocalRegistry

from tn_governed.native_objects import NativeObjects
from tn_governed.values.catalog import AssignedRules, UnityGovernance, markdown
from tn_governed.values.evidence import EvidenceRecorder
from tn_governed.values.primitives import Context
from tn_governed.values.provision import provision
from tn_governed.values.query_result import GovernedQueryResult, QueryTransport
from tn_governed.values.sql import GovernedSQL, source_identity

from .performance_stats import peak_memory_bytes, reset_peak_memory
from .tpch_data import QUERIES, SCHEMA, generate

USE = tn.UseContext("analytics", "internal", "select")
MARKET = {"market_data": {"name": "str", "value": "int"}}
MARKET_QUERY = "SELECT name, value FROM market_data"


class CatalogTransport(LocalRegistry):
    catalog, schema = "relation_study", "governance"

    def __init__(self, root):
        super().__init__(root)
        self.locations = {}

    def _ensure(self, path, body):
        if path == "/volumes":
            self.locations[body["name"]] = body["storage_location"]

    def _request(self, method, path):
        name = path.rsplit(".", 1)[-1]
        return {"storage_location": self.locations[name], "volume_id": name}


def market_database(path, rows):
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE market_data (name TEXT NOT NULL, value INTEGER NOT NULL)")
        connection.executemany(
            "INSERT INTO market_data VALUES (?, ?)",
            (("ACME" if i == 0 else f"ACME-{i}", 1250 + i) for i in range(rows)),
        )
        connection.commit()
    return path


def market_plan(source):
    return (source.filter(pl.col("value") >= 0).sort("name")
            .select((pl.col("value") + 250).sum().alias("amount")))


def ordering_plan(source):
    return source.sort(source.collect_schema().names()[0])


def column_definition(column, kind):
    return {"kind": kind, "markdown": markdown(column), "rule": {
        "additional_uses": [{"application": "archive", "purpose": "audit", "operation": "read"}],
    }}


def build_endpoint(stack, root, database, tables):
    roles = ("catalog", "gateway", "consumer", "recipient")
    paths = provision(root / "sessions", roles=roles, read_only_roles=())
    sessions = {n: stack.enter_context(tn.Session.from_config(str(p))) for n, p in paths.items()}
    store = stack.enter_context(NativeObjects())
    transport = CatalogTransport(root / "registry")
    admin = sessions["catalog"].policy("experiment.administration")
    resolvers = {}
    for name, session in sessions.items():
        resolver = UnityGovernance("http://unused", transport.catalog, session=session,
                                   authority=sessions["catalog"].did, administration=admin, store=store)
        resolver.registry = transport
        resolvers[name] = resolver
    identity = source_identity(database)
    for table, columns in tables.items():
        resolvers["catalog"].publish_assignment(
            root / "assignments" / table, table=table, source_identity=identity,
            application="analytics", actors=["analyst"], purposes=["internal"],
            columns={c: column_definition(c, k) for c, k in columns.items()})
    writers = [sessions["gateway"].did, sessions["consumer"].did]
    contexts = {}
    for name in roles[1:]:
        rules = AssignedRules(resolvers[name], actor="analyst", application="analytics",
                              purpose="internal", writers=writers)
        recorder = EvidenceRecorder(sessions[name], store, sessions["catalog"].policy("experiment.evidence"))
        contexts[name] = Context(sessions[name], recorder, rules, application="analytics",
                                 purpose="internal", actor="analyst", resolver=resolvers[name])
    driver = GovernedSQL(database, gateway=contexts["gateway"], consumer=contexts["consumer"],
                         edition_publisher=resolvers["catalog"], directory=root / "editions")
    return driver, contexts


def evaluators_for(policies):
    def decide(request):
        return Decision(request["use"]["purpose"] == "internal", "purpose",
                        "decision:" + request["operation"])
    return {policy_identity(p): EndpointEvaluator("analytics", "internal-use", "1", {}, decide)
            for p in policies}


def timed(timings, name, function):
    started = time.perf_counter()
    value = function()
    timings[name] = time.perf_counter() - started
    return value


def governed_query(driver, contexts, sql, plan):
    timings = {}
    result = timed(timings, "query_and_publication", lambda: driver.execute_query(sql))
    admitted = timed(timings, "admission", lambda: result.open_for_processing("select", "polars"))
    frame = timed(timings, "frame_construction", lambda: from_admitted_query(
        admitted, use=USE, evaluators=evaluators_for(admitted.data.policies)))
    frame = timed(timings, "governed_plan", lambda: frame.transform(PlanTransform("study", "1", plan)))
    publication = timed(timings, "release", lambda: frame.release_tn(
        use=USE, to="internal", decide=lambda _: True))
    processing = sum(timings.values())
    wire = timed(timings, "transport_export", lambda: result.export().to_bytes())
    timed(timings, "recipient_receipt", lambda: GovernedQueryResult.receive(
        contexts["consumer"], QueryTransport.from_bytes(wire)))
    required = {item["revision_id"] for item in result.metadata()["binding"]["sources"]}
    def accept(context):
        return {policy.revision_id for policy in context.policies} == required
    received = contexts["consumer"].session.receive(publication, use=USE, groups=["values"], decide=accept)
    return ({"timings_seconds": timings, "processing_seconds": processing,
             "wire_bytes": len(wire), "released_bytes": len(publication.forward()),
             "output_rows": result.metadata()["row_count"], "policies": len(required)},
            received.get("rows", group="values"))


def plain_query(database, sql, plan):
    timings = {}
    with closing(sqlite3.connect(database)) as connection:
        cursor = timed(timings, "query", lambda: connection.execute(sql))
        rows = timed(timings, "fetch", cursor.fetchall)
        names = [item[0] for item in cursor.description]
    frame = timed(timings, "frame_construction", lambda: pl.DataFrame(
        [dict(zip(names, row, strict=True)) for row in rows], infer_schema_length=None,
        schema={name: pl.Null for name in names} if not rows else None).lazy())
    output = timed(timings, "plan", lambda: plan(frame).collect())
    return {"timings_seconds": timings, "processing_seconds": sum(timings.values()),
            "output_rows": len(rows)}, output.to_dicts()


def run_case(root, label, database, tables, name, sql, plan, repetition):
    mode = "governed"
    directory = root / "cases" / f"{label}-{name}-{mode}-{repetition}"
    directory.mkdir(parents=True)
    reset_peak_memory()
    with ExitStack() as stack:
        driver, contexts = build_endpoint(stack, directory, database, tables)
        governed, actual = governed_query(driver, contexts, sql, plan)
    peak = peak_memory_bytes()
    plain, expected = plain_query(database, sql, plan)
    if actual != expected:
        raise ValueError("governed relation differs from the plain result")
    shutil.rmtree(directory)
    print(label, name, mode, repetition, round(governed["processing_seconds"], 3),
          round(plain["processing_seconds"], 3), flush=True)
    return {"workload": label, "query": name, "mode": mode, "repetition": repetition,
            "governed": governed, "plain": plain, "peak_rss_bytes": peak}


def isolated_case(*arguments):
    """Run one case in its own process so exhausted memory is a recorded outcome."""
    with ProcessPoolExecutor(1, mp_context=get_context("spawn")) as pool:
        try:
            return pool.submit(run_case, *arguments).result()
        except BrokenProcessPool:
            return None


def run_workload(root, label, database, tables, queries, plan, repetitions):
    outcomes, exhausted = [], set()
    for repetition in range(repetitions):
        for name, sql in queries.items():
            if name in exhausted:
                continue
            result = isolated_case(root, label, database, tables, name, sql, plan, repetition)
            if result is None:
                exhausted.add(name)
                print(label, name, repetition, "process-killed", flush=True)
                result = {"workload": label, "query": name, "mode": "governed",
                          "repetition": repetition, "failure": "process-killed"}
            outcomes.append(result)
    return outcomes


def summarize(outcomes):
    groups = {}
    summary = []
    for item in outcomes:
        if "failure" in item:
            summary.append({key: item[key] for key in ("workload", "query", "mode", "failure")})
        else:
            groups.setdefault((item["workload"], item["query"], item["mode"]), []).append(item)
    for (workload, query, mode), items in groups.items():
        governed = statistics.median(i["governed"]["processing_seconds"] for i in items)
        plain = statistics.median(i["plain"]["processing_seconds"] for i in items)
        summary.append({"workload": workload, "query": query, "mode": mode, "n": len(items),
                        "governed_median_seconds": governed, "plain_median_seconds": plain,
                        "ratio": governed / plain if plain else None,
                        "wire_bytes": items[0]["governed"]["wire_bytes"],
                        "released_bytes": items[0]["governed"]["released_bytes"],
                        "output_rows": items[0]["governed"]["output_rows"],
                        "policies": items[0]["governed"]["policies"],
                        "peak_rss_bytes": max(i["peak_rss_bytes"] or 0 for i in items)})
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--market-rows", type=int, nargs="*", default=[1000, 10000, 100000])
    parser.add_argument("--scale-factors", type=float, nargs="*", default=[0.01, 0.1])
    parser.add_argument("--queries", nargs="*", default=sorted(QUERIES))
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args()
    root = args.run_directory.resolve()
    root.mkdir(parents=True, exist_ok=True)
    outcomes = []

    def save():
        (root / "results.json").write_text(json.dumps(
            {"outcomes": outcomes, "summary": summarize(outcomes)}, indent=2), encoding="utf-8")

    for rows in args.market_rows:
        database = market_database(root / f"market-{rows}.sqlite", rows)
        outcomes += run_workload(root, f"market-{rows}", database, MARKET, {"sum": MARKET_QUERY},
                                 market_plan, args.repetitions)
        database.unlink()
        save()
    for scale in args.scale_factors:
        database = root / f"tpch-{scale}.sqlite"
        started = time.perf_counter()
        generate(database, scale)
        print("generated", scale, round(time.perf_counter() - started, 1), flush=True)
        outcomes += run_workload(root, f"tpch-sf{scale}", database, SCHEMA,
                                 {name: QUERIES[name] for name in args.queries}, ordering_plan,
                                 args.repetitions)
        database.unlink()
        save()


if __name__ == "__main__":
    raise SystemExit(main())
