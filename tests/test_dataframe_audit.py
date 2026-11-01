"""Signed dataframe audits bind execution evidence to inputs and released rows."""

from copy import deepcopy

import pytest
from test_native_calculation_path import POLARS_RELEASE, POLARS_USE
from test_native_calculation_path import setup as setup

from tn_governed.polars_stage import prepare_wealth_calculation


def joined_frame(setup):
    wealth, calendar = setup.editions()
    frame = prepare_wealth_calculation(
        setup.built[0].source.wire,
        setup.built[1].source.wire,
        wealth_edition=wealth,
        calendar_edition=calendar,
        session=setup.polars,
        use=POLARS_USE,
        decide_receive=lambda _: True,
    )
    return frame, (wealth, calendar)


def test_audit_trail_branches_without_shared_mutation():
    from tn_polars.audit import AuditTrail

    detail = {"parameters": {"columns": ["balance"]}}
    original = AuditTrail().append("operation", detail)
    left = original.append("operation", {"name": "head", "count": 2})
    right = original.append("operation", {"name": "head", "count": 5})
    detail["parameters"]["columns"].append("secret")
    merged = left.merge(right)
    assert len(original.records()) == 1
    assert original.records()[0]["details"]["parameters"]["columns"] == ["balance"]
    assert len(merged.records()) == 3
    assert set(merged.heads) == set(left.heads + right.heads)
    exported = merged.records()
    exported[0]["details"].clear()
    assert merged.records()[0]["details"]


def test_join_release_carries_verified_execution_audit(setup):
    from tn_polars.audit import open_audited_frame

    frame, editions = joined_frame(setup)
    publication = frame.release_tn(use=POLARS_RELEASE, to="calculation", decide=lambda _: True)
    expected_artifacts = {
        artifact.policy_revision: artifact
        for edition in editions
        for artifact in edition.selection.record.evaluator_artifacts
    }
    evaluators = {
        revision: entry.evaluator()
        for edition in editions
        for revision, entry in edition.entries.items()
    }
    audit = open_audited_frame(
        publication,
        session=setup.polars,
        use=POLARS_USE,
        decide=lambda _: True,
        expected_artifacts=expected_artifacts,
        evaluator_for=lambda revision: evaluators[revision],
    )
    assert set(audit["inputs"]) == {edition.selection.source_object_id for edition in editions}
    assert audit["output"]["row_count"] == 4
    assert audit["support"]["known"] is True
    assert len(audit["support"]["rows"]) == 4
    operations = [
        event["details"]["name"] for event in audit["events"] if event["kind"] == "operation"
    ]
    assert "join" in operations and "sort" in operations and "select" in operations
    join = next(
        event["details"]
        for event in audit["events"]
        if event["kind"] == "operation" and event["details"]["name"] == "join"
    )
    assert join["parameters"]["left"] != join["parameters"]["right"]
    decisions = [
        event["details"] for event in audit["events"] if event["kind"] == "policy-decision"
    ]
    assert {item["request"]["operation"] for item in decisions} >= {"load", "join", "release"}
    assert all(item["allow"] is True for item in decisions)


def test_audit_rejects_modified_plan_rows_or_source_set(setup):
    from tn_polars.audit import AuditError, open_audited_frame, verify_audit

    frame, _ = joined_frame(setup)
    publication = frame.release_tn(use=POLARS_RELEASE, to="calculation", decide=lambda _: True)
    audit = open_audited_frame(
        publication, session=setup.polars, use=POLARS_USE, decide=lambda _: True
    )
    opened = setup.polars.receive(
        publication, use=POLARS_USE, groups=["finance"], decide=lambda _: True
    )
    rows = deepcopy(opened.get("rows", group="finance"))
    changed = deepcopy(audit)
    changed["events"][0]["details"]["source_id"] = "sha256:" + "0" * 64
    with pytest.raises(AuditError, match="digest"):
        verify_audit(changed, rows=rows)
    rows[0]["wealth"] += 1
    with pytest.raises(AuditError, match="output"):
        verify_audit(audit, rows=rows)
    with pytest.raises(AuditError, match="source"):
        verify_audit(audit, expected_sources=[])


def test_release_does_not_append_decisions_to_sibling_frame(setup):
    from tn_polars.audit import open_audited_frame

    frame, _ = joined_frame(setup)
    before = frame._tn.policies.audit.records()
    first = frame.release_tn(use=POLARS_RELEASE, to="calculation", decide=lambda _: True)
    second = frame.release_tn(use=POLARS_RELEASE, to="calculation", decide=lambda _: True)
    assert frame._tn.policies.audit.records() == before
    left = open_audited_frame(first, session=setup.polars, use=POLARS_USE, decide=lambda _: True)
    right = open_audited_frame(second, session=setup.polars, use=POLARS_USE, decide=lambda _: True)
    assert left == right


def test_window_expression_records_unknown_contributor_support(setup):
    import polars as pl
    from tn_polars.audit import open_audited_frame

    frame, _ = joined_frame(setup)
    window = frame.select(
        pl.col("wealth").sum().over("observed_at", order_by="wealth").alias("wealth")
    )
    publication = window.release_tn(use=POLARS_RELEASE, to="calculation", decide=lambda _: True)
    record = open_audited_frame(
        publication, session=setup.polars, use=POLARS_USE, decide=lambda _: True
    )
    assert record["support"]["known"] is False
    assert record["support"]["rows"] is None
    operations = [event["details"] for event in record["events"] if event["kind"] == "operation"]
    expression = operations[-2]["parameters"]["expressions"][0]
    assert expression["format"] == "tn.polars-expr.v1"
    assert "Over" in str(expression["expression"])


def test_row_binding_distinguishes_types_and_nested_user_objects():
    from decimal import Decimal

    from tn_polars.audit import rows_digest

    values = [1, 1.0, Decimal("1"), "1", ["int", "1"], {"int": "1"}, None, False]
    assert len({rows_digest([{"value": value}]) for value in values}) == len(values)
    assert rows_digest([{"a": 1, "b": 2}]) == rows_digest([{"b": 2, "a": 1}])


@pytest.mark.parametrize("part", ["output", "support"])
def test_rehashed_output_and_support_cannot_reuse_release_authorization(setup, part):
    from tn_polars.audit import AuditError, _digest, open_audited_frame, verify_audit

    frame, _ = joined_frame(setup)
    publication = frame.release_tn(use=POLARS_RELEASE, to="calculation", decide=lambda _: True)
    record = open_audited_frame(
        publication, session=setup.polars, use=POLARS_USE, decide=lambda _: True
    )
    changed = deepcopy(record)
    if part == "output":
        changed["output"]["columns"]["wealth"] = []
    else:
        changed["support"]["known"] = False
        changed["support"]["rows"] = None
    changed["id"] = _digest({key: value for key, value in changed.items() if key != "id"})
    with pytest.raises(AuditError, match="release differs"):
        verify_audit(changed)


def test_operations_after_release_require_another_authorization(setup):
    from tn_polars.audit import AuditError, _digest, open_audited_frame, verify_audit

    frame, _ = joined_frame(setup)
    publication = frame.release_tn(use=POLARS_RELEASE, to="calculation", decide=lambda _: True)
    record = open_audited_frame(
        publication, session=setup.polars, use=POLARS_USE, decide=lambda _: True
    )
    changed = deepcopy(record)
    body = {
        "kind": "operation",
        "parents": changed["heads"],
        "details": {"name": "head", "parameters": {"count": 1}},
    }
    event = {"id": _digest(body), **body}
    changed["events"].append(event)
    changed["heads"] = [event["id"]]
    changed["id"] = _digest({key: value for key, value in changed.items() if key != "id"})
    with pytest.raises(AuditError, match="terminal release"):
        verify_audit(changed)


@pytest.mark.parametrize("part", ["lineage", "precision"])
def test_final_policy_request_must_agree_with_rehashed_release_facts(setup, part):
    from tn_polars.audit import AuditError, _digest, open_audited_frame, verify_audit

    frame, _ = joined_frame(setup)
    publication = frame.release_tn(use=POLARS_RELEASE, to="calculation", decide=lambda _: True)
    changed = deepcopy(
        open_audited_frame(publication, session=setup.polars, use=POLARS_USE, decide=lambda _: True)
    )
    if part == "lineage":
        changed["output"]["columns"]["wealth"] = []
    else:
        changed["support"].update(known=False, shape_known=False, rows=None)
    terminal = changed["events"][-1]
    terminal["details"]["parameters"].update(
        output_digest=_digest(changed["output"]), support_digest=_digest(changed["support"])
    )
    terminal["id"] = _digest({key: value for key, value in terminal.items() if key != "id"})
    changed["heads"] = [terminal["id"]]
    changed["id"] = _digest({key: value for key, value in changed.items() if key != "id"})
    with pytest.raises(AuditError, match="lineage|precision"):
        verify_audit(changed)


def test_python_function_audit_does_not_carry_serialized_closure():
    import json

    import polars as pl
    from tn_polars.audit import expression_record

    captured = "private captured contents" * 100
    expression = pl.col("value").map_elements(
        lambda value: value + len(captured), return_dtype=pl.Int64
    )
    record = expression_record(expression)
    assert record["input_columns"] == ["value"]
    assert len(record["opaque_functions"]) == 1
    assert "AnonymousFunction" not in json.dumps(record)
    assert "OpaqueFunction" in json.dumps(record)
    assert len(json.dumps(record)) < len(expression.meta.serialize(format="json"))
