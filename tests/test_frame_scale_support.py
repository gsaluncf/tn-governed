"""Exact contributors remain compact across independently published SQL batches."""

import json
from collections import defaultdict
from types import SimpleNamespace

import polars as pl
import pytest
from tn_polars.audit import _support_record
from tn_polars.support import Support

from experiments.pvldb_evaluation.frames import _row_support


def test_origin_union_preserves_first_occurrence_and_distinct_coordinates():
    from tn_governed.values.primitives import unique_origins

    first = {"publication": "one", "row": 1, "column": "price",
             "snapshot": {"tables": ["market"], "epoch": 1}}
    equal = {"snapshot": {"epoch": 1.0, "tables": ["market"]}, "column": "price",
             "row": True, "publication": "one"}
    other_row = {**first, "row": 2}
    other_column = {**first, "column": "name"}
    other_publication = {**first, "publication": "two"}
    inputs = [first, other_row, equal, other_column, other_publication, dict(first)]
    union = unique_origins(inputs)
    assert union == [first, other_row, other_column, other_publication]
    assert union[0] is first
    assert first == equal


def batched_cells(count, batch_size=64):
    return [
        {"row": row, "column": column, "source_row": row % batch_size,
         "source_object_id": f"{column}-{row // batch_size}"}
        for row in range(count) for column in ("name", "value")
    ]


def sources_by_column(cells):
    return {
        column: frozenset(cell["source_object_id"] for cell in cells if cell["column"] == column)
        for column in ("name", "value")
    }


def test_batched_cells_use_policy_groups_and_retain_exact_rows():
    count = 193
    cells = batched_cells(count)
    source_sets = sources_by_column(cells)
    policies = SimpleNamespace(_entries={
        name: SimpleNamespace(source_ids=sources) for name, sources in source_sets.items()
    })
    lazy = pl.DataFrame({"name": [f"company-{i}" for i in range(count)],
                         "value": list(range(count))}).lazy()
    support = _row_support(lazy, cells, policies, count)
    assert len(support.ids) == 2
    selected = support.apply(support.frame.filter(pl.col("value") % 3 == 1).sort("name"))
    aggregate = selected.aggregate([], [pl.col("value").sum().alias("total")])
    materialized = aggregate.frame.collect()
    record = _support_record(aggregate, materialized)
    expected = defaultdict(list, {cell["source_object_id"]: [] for cell in cells})
    for cell in cells:
        if cell["row"] % 3 == 1:
            source = cell["source_object_id"]
            expected[source].append(f"{source}::{cell['source_row']}")
    assert record["rows"] == [{source: sorted(rows) for source, rows in expected.items()}]
    assert record["policy_sources"] == {key: sorted(value) for key, value in source_sets.items()}
    assert all(facts["group_sizes"] == [64] for facts in record["policy_facts"].values())
    assert materialized["total"].item() == sum(i for i in range(count) if i % 3 == 1)


def mixed_support():
    lazy = pl.DataFrame({"key": ["a", "a", "b", "b"], "amount": [2, 3, 5, 7]}).lazy()
    contributors = [(row, source, row % 2) for row, sources in enumerate(
        [("one", "two"), ("three",), ("one",), ("two", "three")]) for source in sources]
    policies = {"alpha": frozenset({"one", "three"}),
                "beta": frozenset({"two", "three"})}
    return Support.from_contributors(lazy, contributors, policies, row_count=4)


def test_grouped_mixed_policies_count_qualified_rows():
    support = mixed_support().aggregate([pl.col("key")], [pl.col("amount").sum()])
    materialized = support.frame.collect().sort("key")
    record = _support_record(support, materialized)
    assert record["rows"] == [
        {"one": ["one::0"], "two": ["two::0"], "three": ["three::1"]},
        {"one": ["one::0"], "two": ["two::1"], "three": ["three::1"]},
    ]
    assert record["policy_facts"]["alpha"]["group_sizes"] == [2, 2]
    assert record["policy_facts"]["beta"]["group_sizes"] == [2, 2]


def test_window_and_join_preserve_source_qualified_duplicates():
    support = mixed_support()
    windowed = support.windowed([pl.col("amount").sum().over("key").alias("total")])
    assert windowed is not None
    window_rows = _support_record(windowed, windowed.frame.collect())["rows"]
    assert window_rows[0] == window_rows[1]
    assert window_rows[2] == window_rows[3]
    joined = support.joined(support, ["key"], "inner")
    aggregate = joined.aggregate([], [pl.col("amount").sum()])
    record = _support_record(aggregate, aggregate.frame.collect())
    assert record["rows"] == [{"one": ["one::0"], "two": ["two::0", "two::1"],
                                "three": ["three::1"]}]
    assert record["policy_facts"]["alpha"]["group_sizes"] == [2]
    assert record["policy_facts"]["beta"]["group_sizes"] == [3]


def test_join_counts_partial_membership_in_a_packed_column():
    left = Support.from_contributors(
        pl.DataFrame({"key": ["x", "x"], "value": [2, 3]}).lazy(),
        [(0, "one", 0), (1, "two", 0)], {"alpha": {"one", "two"}}, row_count=2,
    )
    right = Support.from_contributors(
        pl.DataFrame({"key": ["x"]}).lazy(), [(0, "one", 0)],
        {"beta": {"one"}}, row_count=1,
    )
    joined = left.joined(right, ["key"], "inner")
    aggregate = joined.aggregate([], [pl.col("value").sum()])
    record = _support_record(aggregate, aggregate.frame.collect())
    assert record["rows"] == [{"one": ["one::0"], "two": ["two::0"]}]
    assert record["policy_facts"]["alpha"]["group_sizes"] == [2]
    assert record["policy_facts"]["beta"]["group_sizes"] == [1]


@pytest.mark.parametrize("contributor", [(-1, "one", 0), (1, "one", 0),
                                         (0, "one::two", 0), (0, "one", -1)])
def test_contributor_coordinates_are_validated(contributor):
    with pytest.raises(ValueError):
        Support.from_contributors(pl.DataFrame({"value": [1]}).lazy(), [contributor],
                                  {"policy": frozenset({"one"})}, row_count=1)


def test_native_batched_audit_preserves_policies_claims_and_cell_coordinates(tmp_path, monkeypatch):
    from tn_polars.registry import UnityCatalogRegistry

    from experiments.pvldb_evaluation.run import run_case

    volumes = {}

    def request(self, method, path, payload=None):
        if path in {"/catalogs", "/schemas"}:
            return {}
        if method == "POST" and path == "/volumes":
            full = f"{payload['catalog_name']}.{payload['schema_name']}.{payload['name']}"
            volumes[full] = dict(payload)
            return volumes[full]
        if method == "GET" and path.startswith("/volumes/"):
            return volumes[path.removeprefix("/volumes/")]
        raise AssertionError((method, path))

    monkeypatch.setattr(UnityCatalogRegistry, "_request", request)
    root = tmp_path / "case"
    result = run_case(root, "primitive", rows=65, claim=True)
    assert result["completed"] and result["verified"], result
    run = json.loads((root / "run.json").read_text())
    facts = run["evaluation"]["dataframe"][0]
    audit = facts["audit"]
    assert len(audit["policies"]) == 2
    graph = json.loads((root / "dag.json").read_text())
    nodes = {node["id"].partition("#")[0]: node for node in graph["nodes"]}
    original = nodes[run["outputs"]["attested_name"]["reference"]["object_id"]]["claims"]
    assert len(original) == 1
    for label in ("dataframe_result", "model_input"):
        assert nodes[run["outputs"][label]["reference"]["object_id"]]["claims"] == original
    assert len(facts["input_references"]) == 130
    expected = defaultdict(set)
    for cell in facts["source_cells"]:
        source = cell["source_object_id"]
        expected[source].add(f"{source}::{cell['source_row']}")
    assert len(expected) == 4
    assert audit["support"]["rows"] == [
        {source: sorted(rows) for source, rows in expected.items()}
    ]
    assert all(facts["group_sizes"] == [65]
               for facts in audit["support"]["policy_facts"].values())
