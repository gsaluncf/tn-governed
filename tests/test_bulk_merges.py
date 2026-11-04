"""Bulk merges and shared batch facts keep the results of one-at-a-time forms."""

import json
from pathlib import Path

import pytest
import tn
from tn_polars.audit import AuditTrail, _member_ranges, _valid_members

from tn_governed.publications import PublicationStore, object_digest, sync_writes, write_once
from tn_governed.values.verify import cache_bound, report_graph
from tn_governed.values.manifests import BATCH_SCHEMA, SCHEMA, BatchBindings, signed_manifest

POLICY = """## finance.account
### instruction
Retain source attribution.
### use_for
Internal calculation.
### do_not_use_for
Unapproved disclosure.
### consequences
Review.
### on_violation_or_error
Refuse.
"""


def test_include_all_matches_repeated_include():
    with tn.Session(POLICY, groups=["values"]) as session:
        def make(value):
            return session.create({"value": value}, session.policy("finance.account"), group="values")

        others = [make(number) for number in range(5)]
        base = make(100)
        repeated, bulk = base.copy(), base.copy()
        for other in others:
            repeated.include(other)
        bulk.include_all(others)
        assert [source.object_id for source in bulk.sources] == [
            source.object_id for source in repeated.sources]
        assert len(bulk.policies) == len(repeated.policies)


def test_include_all_without_inputs_changes_no_reference():
    with tn.Session(POLICY, groups=["values"]) as session:
        data = session.create({"value": 1}, session.policy("finance.account"), group="values")
        before = [source.object_id for source in data.sources]
        data.include_all([])
        assert [source.object_id for source in data.sources] == before


def test_audit_merge_keeps_each_event_once_and_recomputes_heads():
    base = AuditTrail().append("source", {"source_id": "a"})
    left = base.append("operation", {"name": "left"})
    right = base.append("operation", {"name": "right"})
    other = AuditTrail().append("source", {"source_id": "b"})
    merged = left.merge(right, other)
    identities = [event["id"] for event in merged.records()]
    assert len(identities) == len(set(identities)) == 4
    assert set(merged.heads) == {*left.heads, *right.heads, *other.heads}
    assert merged.records() == left.merge(right).merge(other).records()


def test_long_member_lists_become_canonical_ranges():
    tokens = [f"s::{row}" for row in (*range(10, 80), 90)]
    ranges = _member_ranges(tokens)
    assert ranges == {"ranges": [[10, 79], [90, 90]]}
    assert _valid_members("s", ranges)
    assert _member_ranges(tokens[:63]) == tokens[:63]


@pytest.mark.parametrize("ranges", [
    [[10, 79], [80, 90]],          # adjacent runs have one shorter form
    [[90, 100], [10, 79]],         # out of order
    [[10, 79], [70, 90]],          # overlap
    [[5, 4], [10, 79]],            # empty run
    [[-1, 70]],                    # negative row
    [[1, 10]],                     # short lists stay plain
    [[1.5, 70]],                   # not a row ordinal
])
def test_noncanonical_ranges_are_refused(ranges):
    assert not _valid_members("s", {"ranges": ranges})


def test_batch_manifest_expands_to_the_same_field_binding():
    scope = {"table": "t", "column": "c", "query_id": "q", "assignment_id": "a"}
    bindings = BatchBindings({"decision_id": "d", "source": scope},
                             {"value_7": {"row": 7, "declared": {"kind": "int"}}})
    source = {**scope, "row": 7}
    assert list(bindings) == ["value_7"] and len(bindings) == 1
    assert bindings["value_7"] == {"claims": [], "parents": [], "decision_id": "d",
                                   "declared": {"kind": "int"}, "origins": [source],
                                   "source": source}
    with pytest.raises(KeyError):
        bindings["value_8"]


def test_signed_manifest_reads_both_forms():
    class Data:
        def __init__(self, manifest):
            self.manifest = manifest

        def get(self, name, *, group):
            assert (name, group) == ("manifest", "evidence")
            return self.manifest

    single = {"schema": SCHEMA, "bindings": {"value": {}}}
    assert signed_manifest(Data(single)) is single
    batch = {"schema": BATCH_SCHEMA, "batch": {"decision_id": "d", "source": {}},
             "cells": {"value_0": {"row": 0, "declared": {}}}}
    expanded = signed_manifest(Data(batch))
    assert expanded["schema"] == BATCH_SCHEMA and list(expanded["bindings"]) == ["value_0"]


def test_object_digest_refuses_every_malformed_identity_with_value_error():
    identity = "sha256:" + "a" * 64
    assert object_digest(identity) == "a" * 64
    for malformed in (["sha256:"], 42, None, "sha256:" + "A" * 64, identity + "0"):
        with pytest.raises(ValueError):
            object_digest(malformed)


def test_verification_caches_hold_every_publication_of_a_large_run():
    class Store:
        def __init__(self, count):
            self.count = count

        def publication_sizes(self):
            return {f"sha256:{index:064x}": 1 for index in range(self.count)}

    assert cache_bound(Store(3)) == 128
    assert cache_bound(Store(1000)) == 2000


def test_report_graph_keeps_cells_up_to_its_limit_and_groups_them_above_it():
    def cell(identity, publication, row):
        return {"id": identity, "object_id": publication, "kind": "source", "operation": "select",
                "policy_revisions": ["r"], "source": {"column": "amount", "row": row}}
    nodes = [cell("c0", "p0", 0), cell("c1", "p0", 1), cell("c2", "p1", 0),
             {"id": "d", "kind": "derived", "operation": "sum", "source": None}]
    edges = [{"parent": parent, "child": "d", "operation": "sum"} for parent in ("c0", "c1", "c2")]
    assert report_graph(nodes, edges, [], None)["nodes"] == nodes
    assert report_graph(nodes, edges, [], 3)["nodes"] == nodes
    grouped = report_graph(nodes, edges, [], 2)
    assert {node["id"]: node.get("cells") for node in grouped["nodes"]} == {"d": None, "p0": 2, "p1": 1}
    assert grouped["edges"] == [{"parent": "p0", "child": "d", "operation": "sum"},
                                {"parent": "p1", "child": "d", "operation": "sum"}]


def test_group_commit_writes_each_file_once_and_keeps_immutability(tmp_path):
    path = tmp_path / "group" / "one.bin"
    write_once(path, b"same", sync=False)
    write_once(path, b"same", sync=False)
    sync_writes([path])
    assert path.read_bytes() == b"same"
    with pytest.raises(ValueError):
        write_once(path, b"other", sync=False)


def test_group_commit_store_round_trips_a_publication(tmp_path):
    with tn.Session(POLICY, groups=["values"]) as session:
        snapshot = session.create(
            {"value": 3}, session.policy("finance.account"), group="values").snapshot
        store = PublicationStore(tmp_path, group_commit=True)
        identity = store.put(snapshot)
        store.commit()
        index = json.loads(Path(tmp_path, "index", identity[7:] + ".json").read_text())
        assert index["object_id"] == identity
        assert store.read(identity).forward() == snapshot.forward()
