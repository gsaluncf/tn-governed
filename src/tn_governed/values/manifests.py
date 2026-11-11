"""Signed manifests of primitive publications and the source origins they carry."""

from collections.abc import Mapping

SCHEMA = "tn.primitive-bindings.v1"
BATCH_SCHEMA = "tn.primitive-batch.v1"
POLICY_SCHEMA = "tn.primitive-policy.v1"
SHARED_POLICY_SCHEMA = "tn.primitive-policy-shared.v1"
COLUMN_POLICY_SCHEMA = "tn.primitive-policy-columns.v1"
SCHEMAS = (SCHEMA, BATCH_SCHEMA, POLICY_SCHEMA, SHARED_POLICY_SCHEMA, COLUMN_POLICY_SCHEMA)


def _origin_key(value):
    if isinstance(value, dict):
        return (dict, frozenset((key, _origin_key(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return (type(value), tuple(_origin_key(item) for item in value))
    return (None, value)


def _scope_key(scope):
    try:
        return frozenset(scope.items())
    except TypeError:
        return _origin_key(scope)


def result_names(details, reference, envelope):
    """Match a Result naming one field, or a source publication that holds this field."""
    commitment = envelope[reference.group]["field_hashes"].get(reference.field)
    if commitment is None:
        return False
    if details.get("output") == {"object_id": reference.object_id, "group": reference.group}:
        return True
    return details.get("output") == reference.to_dict() and details.get("field_commitment") == commitment


def _merged_ranges(ranges):
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def unique_origins(origins):
    """Merge origins that differ only in row, in first-seen scope order.

    One row keeps its exact source form. Several rows become inclusive ``rows`` ranges.
    """
    scopes = {}
    for origin in origins:
        scope = {key: item for key, item in origin.items() if key not in ("row", "rows")}
        rows = [[origin["row"]] * 2] if "row" in origin else origin.get("rows", [])
        scopes.setdefault(_scope_key(scope), (scope, []))[1].extend(rows)
    result = []
    for scope, ranges in scopes.values():
        merged = _merged_ranges(ranges)
        if len(merged) == 1 and merged[0][0] == merged[0][1]:
            result.append({**scope, "row": merged[0][0]})
        else:
            result.append({**scope, "rows": merged} if merged else scope)
    return result


class BatchBindings(Mapping):
    """Field bindings of a source batch, expanded on demand from its shared facts."""

    def __init__(self, batch, cells):
        self._batch, self._cells = batch, cells

    def __getitem__(self, field):
        cell = self._cells[field]
        source = {**self._batch["source"], "row": cell["row"]}
        return {"claims": [], "parents": [], "decision_id": self._batch["decision_id"],
                "declared": cell["declared"], "origins": [source], "source": source}

    def get(self, field, default=None):
        return self[field] if field in self._cells else default

    def __iter__(self):
        return iter(self._cells)

    def __len__(self):
        return len(self._cells)


class SharedPolicyBindings(Mapping):
    """Policy bindings whose facts common to every cell are signed once, expanded on demand.

    Each expanded binding equals the per-cell binding of a ``POLICY_SCHEMA`` manifest.
    """

    def __init__(self, shared, cells):
        self._shared, self._cells = shared, cells

    @property
    def shared(self):
        return self._shared

    def declared(self, field):
        """The declared facts of one cell, without building its whole binding."""
        return {**self._shared["declared"], **self._cells[field]}

    def __getitem__(self, field):
        return {"declared": {**self._shared["declared"], **self._cells[field]},
                "claims": list(self._shared["claims"]), "actions": list(self._shared["actions"])}

    def get(self, field, default=None):
        return self[field] if field in self._cells else default

    def __iter__(self):
        return iter(self._cells)

    def __len__(self):
        return len(self._cells)


class ColumnBindings(Mapping):
    """Policy bindings stored as signed columns: shared facts once, each other fact as one array.

    Every cell keeps its own field. Each expanded binding equals the per-cell binding of a
    ``POLICY_SCHEMA`` manifest.
    """

    def __init__(self, shared, fields, facts):
        self._shared, self._fields, self._facts = shared, fields, facts
        self._bindings = None

    @property
    def shared(self):
        return self._shared

    def _expanded(self):
        """Expand every cell's binding once; the signed columns are immutable."""
        if self._bindings is None:
            common, keys = self._shared["declared"], list(self._facts)
            claims, actions = self._shared["claims"], self._shared["actions"]
            rows = zip(*(self._facts[key] for key in keys)) if keys else [()] * len(self._fields)
            self._bindings = {field: {"declared": {**common, **dict(zip(keys, row))},
                                      "claims": claims, "actions": actions}
                              for field, row in zip(self._fields, rows, strict=True)}
        return self._bindings

    def declared(self, field):
        return self._expanded()[field]["declared"]

    @property
    def fields(self):
        return self._fields

    def column(self, key):
        """One declared fact for every field, in field order."""
        if key in self._shared["declared"]:
            return [self._shared["declared"][key]] * len(self._fields)
        return self._facts[key]

    def fact_names(self):
        return [*self._shared["declared"], *(key for key in self._facts if key not in self._shared["declared"])]

    def __getitem__(self, field):
        return self._expanded()[field]

    def __contains__(self, field):
        return field in self._expanded()

    def get(self, field, default=None):
        return self._expanded().get(field, default)

    def __iter__(self):
        return iter(self._fields)

    def __len__(self):
        return len(self._fields)


def column_manifest_from_columns(fields, columns, claims, actions):
    """The manifest ``column_manifest_from_facts`` builds, from facts already held as columns."""
    size = len(fields)
    common = {key: column[0] for key, column in columns.items() if column.count(column[0]) == size}
    return {"schema": COLUMN_POLICY_SCHEMA,
            "shared": {"declared": common, "claims": claims, "actions": actions}, "fields": list(fields),
            "facts": {key: columns[key] for key in sorted(columns) if key not in common}}


def column_manifest_from_facts(facts, claims, actions):
    """The manifest ``column_policy_manifest`` builds, computed from the facts directly.

    None when the cells' fact names differ.
    """
    fields, cells = list(facts), list(facts.values())
    keys = list(cells[0])
    if any(cell.keys() != cells[0].keys() for cell in cells):
        return None
    columns = {key: [cell[key] for cell in cells] for key in keys}
    common = {key: column[0] for key, column in columns.items() if column.count(column[0]) == len(column)}
    return {"schema": COLUMN_POLICY_SCHEMA,
            "shared": {"declared": common, "claims": claims, "actions": actions}, "fields": fields,
            "facts": {key: columns[key] for key in sorted(keys) if key not in common}}


def column_policy_manifest(bindings):
    """Shared facts once and each remaining fact as one column; None if the cells' shapes differ."""
    shared = shared_policy_manifest(bindings)
    if shared is None:
        return None
    cells = shared["cells"]
    keys = set(next(iter(cells.values())))
    if any(set(cell) != keys for cell in cells.values()):
        return None
    fields = list(cells)
    return {"schema": COLUMN_POLICY_SCHEMA, "shared": shared["shared"], "fields": fields,
            "facts": {key: [cells[field][key] for field in fields] for key in sorted(keys)}}


def shared_policy_manifest(bindings):
    """Store the facts every cell shares once; None when the cells' support differs."""
    first = next(iter(bindings.values()))
    claims, actions = first["claims"], first["actions"]
    if any(b["claims"] != claims or b["actions"] != actions for b in bindings.values()):
        return None
    common = dict(first["declared"])
    for binding in bindings.values():
        common = {key: value for key, value in common.items() if binding["declared"].get(key) == value}
    cells = {field: {key: value for key, value in binding["declared"].items() if key not in common}
             for field, binding in bindings.items()}
    return {"schema": SHARED_POLICY_SCHEMA,
            "shared": {"declared": common, "claims": claims, "actions": actions}, "cells": cells}


def signed_manifest(data):
    """Read a publication's signed manifest with its schema and field bindings.

    A batch manifest keeps its signed schema; its bindings expand on demand from the shared facts.
    A shared policy manifest reads as the policy manifest it compresses.
    """
    manifest = data.get("manifest", group="evidence")
    if isinstance(manifest, dict) and manifest.get("schema") == BATCH_SCHEMA:
        return {"schema": BATCH_SCHEMA, "bindings": BatchBindings(manifest["batch"], manifest["cells"])}
    if isinstance(manifest, dict) and manifest.get("schema") == SHARED_POLICY_SCHEMA:
        return {"schema": POLICY_SCHEMA, "bindings": SharedPolicyBindings(manifest["shared"], manifest["cells"])}
    if isinstance(manifest, dict) and manifest.get("schema") == COLUMN_POLICY_SCHEMA:
        fields, facts = manifest["fields"], manifest["facts"]
        if (not isinstance(fields, list) or len(set(fields)) != len(fields) or not isinstance(facts, dict)
                or any(not isinstance(column, list) or len(column) != len(fields) for column in facts.values())):
            from .evidence import EvidenceError
            raise EvidenceError("malformed signed column manifest")
        return {"schema": POLICY_SCHEMA, "bindings": ColumnBindings(manifest["shared"], fields, facts)}
    return manifest


def origin_rows(origins):
    """Count the source rows named by merged origins."""
    return sum(1 if "row" in origin else sum(end - start + 1 for start, end in origin.get("rows", []))
               for origin in origins)
