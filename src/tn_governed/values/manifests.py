"""Signed manifests of primitive publications and the source origins they carry."""

from collections.abc import Mapping

SCHEMA = "tn.primitive-bindings.v1"
BATCH_SCHEMA = "tn.primitive-batch.v1"
SCHEMAS = (SCHEMA, BATCH_SCHEMA)


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


def signed_manifest(data):
    """Read a publication's signed manifest with its schema and field bindings.

    A batch manifest keeps its signed schema; its bindings expand on demand from the shared facts.
    """
    manifest = data.get("manifest", group="evidence")
    if isinstance(manifest, dict) and manifest.get("schema") == BATCH_SCHEMA:
        return {"schema": BATCH_SCHEMA, "bindings": BatchBindings(manifest["batch"], manifest["cells"])}
    return manifest


def origin_rows(origins):
    """Count the source rows named by merged origins."""
    return sum(1 if "row" in origin else sum(end - start + 1 for start, end in origin.get("rows", []))
               for origin in origins)
