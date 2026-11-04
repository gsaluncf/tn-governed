"""Packed reference lists keep the exact list and stay canonical."""

import json

import pytest

from tn_governed.values.references import (
    MINIMUM_PACKED,
    pack_references,
    pack_source_cells,
    unpack_references,
    unpack_source_cells,
)


def reference(object_id, field, group="values"):
    return {"object_id": object_id, "group": group, "field": field}


def interleaved(rows):
    """Two columns read row by row from two publications, as a dataframe load does."""
    return [reference(name, f"value_{row}") for row in range(rows) for name in ("names", "values")]


def test_short_lists_stay_plain():
    references = interleaved(3)
    assert pack_references(references) == references
    assert unpack_references(references) == references


def test_interleaved_columns_pack_to_one_run_per_publication():
    references = interleaved(256)
    packed = pack_references(references)
    assert len(packed["runs"]) == 2
    assert {run["stride"] for run in packed["runs"]} == {2}
    assert unpack_references(packed) == references
    assert len(json.dumps(packed)) < len(json.dumps(references)) / 50


@pytest.mark.parametrize("references", [
    [reference("a", f"value_{row}") for row in reversed(range(MINIMUM_PACKED))],
    [reference("a", "value_1"), reference("a", "value_1")] * MINIMUM_PACKED,
    [reference("a", "value"), reference("b", "rows")] * MINIMUM_PACKED,
    [reference("a", "value_007"), reference("a", "value_7")] * MINIMUM_PACKED,
    [reference("a", "value_0", "values"), reference("a", "value_0", "evidence")] * MINIMUM_PACKED,
    [reference(f"object-{index}", "value") for index in range(MINIMUM_PACKED)],
])
def test_any_list_round_trips_in_order(references):
    assert unpack_references(pack_references(references)) == references


def test_equal_lists_pack_equally_and_different_lists_differently():
    references = interleaved(128)
    changed = [*references[:-1], reference("other", "value_127")]
    assert pack_references(references) == pack_references(list(references))
    assert pack_references(references) != pack_references(changed)


@pytest.mark.parametrize("change", [
    lambda packed: packed["runs"].pop(),
    lambda packed: packed["runs"][0].update(position=1),
    lambda packed: packed["runs"][0].update(length=packed["runs"][0]["length"] + 1),
    lambda packed: packed.update(count=packed["count"] + 1),
    lambda packed: packed.update(schema="other"),
    lambda packed: packed["runs"].extend(packed["runs"][:1]),
])
def test_altered_runs_are_refused(change):
    packed = pack_references(interleaved(128))
    change(packed)
    with pytest.raises(ValueError):
        unpack_references(packed)


def test_a_valid_but_split_encoding_is_refused():
    references = [reference("a", f"value_{row}") for row in range(MINIMUM_PACKED)]
    packed = pack_references(references)
    run = packed["runs"][0]
    packed["runs"] = [{**run, "length": 10}, {**run, "number": 10, "position": 10, "length": run["length"] - 10}]
    with pytest.raises(ValueError, match="canonical"):
        unpack_references(packed)


def cells(rows):
    return [
        {"row": row, "column": column, "source_row": row, "reference": reference(column, f"value_{row}"),
         "source_object_id": column, "edition_record_id": "edition-" + column, "root": column + "::x"}
        for row in range(rows) for column in ("name", "value")
    ]


def test_source_cells_round_trip_with_their_references():
    original = cells(128)
    packed = pack_source_cells(original)
    assert len(packed["runs"]) == 2
    assert unpack_source_cells(packed, [cell["reference"] for cell in original]) == original


def test_source_cells_stay_plain_when_short():
    original = cells(3)
    assert pack_source_cells(original) == original
