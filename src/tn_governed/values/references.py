"""Long signed lists stored as arithmetic runs.

A dataframe reads thousands of cells from a few publications. Stored as runs, the
records about it grow with publications rather than cells. Packing is deterministic,
so two equal lists have equal packed forms and compare without being expanded.
"""

from __future__ import annotations

import re

REFERENCE_RUNS = "tn.reference-runs.v1"
CELL_RUNS = "tn.source-cell-runs.v1"
MINIMUM_PACKED = 64
_NUMBERED = re.compile(r"(.*?)(0|[1-9][0-9]*)")
_RUN_FIELDS = ("position", "length", "stride")
_REFERENCE_KEYS = ("object_id", "group", "prefix")
_CELL_KEYS = ("column", "source_object_id", "edition_record_id", "root")
_CELL_COUNTERS = ("row", "source_row")


def _continues(run, item, position, counters):
    return (
        all(item[name] is not None and item[name] == run[name] + run["length"] for name in counters)
        and (run["length"] == 1 or position == run["position"] + run["length"] * run["stride"])
    )


def _pack(items, constants, counters):
    runs, latest = [], {}
    for position, item in enumerate(items):
        key = tuple(item[name] for name in constants)
        run = latest.get(key)
        if run is not None and _continues(run, item, position, counters):
            if run["length"] == 1:
                run["stride"] = position - run["position"]
            run["length"] += 1
        else:
            latest[key] = {**item, "position": position, "length": 1, "stride": 1}
            runs.append(latest[key])
    return runs


def _expanded(run, index, counters):
    item = {name: value for name, value in run.items() if name not in _RUN_FIELDS}
    for name in counters:
        if item[name] is not None:
            item[name] += index
    return item


def _unpack(packed, schema, counters):
    if not isinstance(packed, dict) or packed.get("schema") != schema:
        raise ValueError("unrecognized packed list")
    items = [None] * packed["count"]
    for run in packed["runs"]:
        for index in range(run["length"]):
            position = run["position"] + index * run["stride"]
            if not 0 <= position < len(items) or items[position] is not None:
                raise ValueError("packed runs overlap or leave the list")
            items[position] = _expanded(run, index, counters)
    if any(item is None for item in items):
        raise ValueError("packed runs leave a gap")
    return items


def _numbered(reference):
    match = _NUMBERED.fullmatch(reference["field"])
    prefix, number = (match[1], int(match[2])) if match else (reference["field"], None)
    return {"object_id": reference["object_id"], "group": reference["group"],
            "prefix": prefix, "number": number}


def pack_references(references):
    """Keep a short list as it is and encode a long one as runs per publication group."""
    references = list(references)
    if len(references) < MINIMUM_PACKED:
        return references
    runs = _pack([_numbered(reference) for reference in references], _REFERENCE_KEYS, ("number",))
    return {"schema": REFERENCE_RUNS, "count": len(references), "runs": runs}


def unpack_references(value):
    """Return the exact reference list; a non-canonical encoding is refused."""
    if isinstance(value, list):
        return value
    references = [
        {"object_id": item["object_id"], "group": item["group"],
         "field": item["prefix"] + ("" if item["number"] is None else str(item["number"]))}
        for item in _unpack(value, REFERENCE_RUNS, ("number",))
    ]
    if pack_references(references) != value:
        raise ValueError("packed references are not canonical")
    return references


def pack_source_cells(cells):
    """Encode per-cell source positions; each cell's reference comes from the input list."""
    if len(cells) < MINIMUM_PACKED:
        return cells
    bare = [{name: value for name, value in cell.items() if name != "reference"} for cell in cells]
    return {"schema": CELL_RUNS, "count": len(cells), "runs": _pack(bare, _CELL_KEYS, _CELL_COUNTERS)}


def unpack_source_cells(value, references):
    if isinstance(value, list):
        return value
    cells = _unpack(value, CELL_RUNS, _CELL_COUNTERS)
    if len(cells) != len(references):
        raise ValueError("source cells and input references differ in length")
    return [{**cell, "reference": reference} for cell, reference in zip(cells, references, strict=True)]
