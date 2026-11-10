"""Offline verification of the fixed SQL/dataframe calculation and OPA evidence.

The original primitive verifier checks the complete record/claim/publication DAG.
This additional reader checks the dataframe-specific signed observations, loads
the exact evaluator bytes bound by source editions, and independently calculates
the expected result from the retained SQLite snapshot.
"""

from collections import Counter
from contextlib import closing
from dataclasses import dataclass
from decimal import Decimal, localcontext
import hashlib
import json
from pathlib import Path
import sqlite3
import zipfile

import tn
from tn_polars.opa import OpaWasmEvaluator

from tn_governed.publications import write_once
from tn_governed.values.collection import pauses_collection
from tn_governed.values.evidence import require
from tn_governed.values.holders import holder
from tn_governed.values.manifests import POLICY_SCHEMA, SCHEMAS, signed_manifest
from tn_governed.values.metadata import describe
from tn_governed.values.numeric_codec import decode, encode, record_value
from tn_governed.values.primitives import VALUE_TYPE
from tn_governed.values.references import unpack_references, unpack_source_cells
from tn_governed.values.retained_run import POLICY_RUN_SCHEMA, contracted, open_retained_run
from tn_governed.values.verify_report import GRAPH_CELL_LIMIT


_STAGES = ("load", "filter", "sort", "with_columns", "select", "release")
_PLAN = [
    {"operation": "filter", "column": "value", "comparison": ">=", "literal": 0},
    {"operation": "sort", "columns": ["name"], "descending": False},
    {"operation": "with_columns", "column": "value", "operator": "+", "literal": 250, "output": "adjusted"},
    {"operation": "select", "aggregate": "sum", "column": "adjusted", "output": "amount"},
]
_FILES = {
    "compiled_policy.json": "compiled_policy_sha256", "profile.json": "profile_sha256",
    "policy.wasm": "wasm_sha256", "data.json": "data_sha256",
}
_NUMERIC_TYPES = {"int": int, "float": float, "Decimal": Decimal}
_DEFAULT_NUMERIC = {"kind": "int", "dtype": "Int64"}


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _commitment_report(commitments, limit):
    """List commitments for a small input; above ``limit``, give their count and digest."""
    if limit is None or len(commitments) <= limit:
        return commitments
    digest = hashlib.sha256()
    for item in commitments:
        reference = item["reference"]
        digest.update(f"{reference['object_id']}/{reference['group']}/{reference['field']}="
                      f"{item['field_commitment']}\n".encode("ascii"))
    return {"count": len(commitments), "sha256": digest.hexdigest()}


def _artifact_facts(artifact):
    return {name: getattr(artifact, name) for name in ("policy_revision", *_FILES.values())}


def _bundle_members(marker, names):
    """Read transport files independently of the application's bundle adapter."""
    if marker.name == "bundle.zip":
        require(not (marker.parent / "bundle.json").exists(), "conflicting edition bundle formats")
        with zipfile.ZipFile(marker) as archive:
            infos = archive.infolist()
            require(len(infos) == len({item.filename for item in infos}), "duplicate archive members")
            require(all(item.compress_type == zipfile.ZIP_STORED for item in infos),
                    "edition archive contains compressed members")
            return {name: archive.read(name) for name in names}
    require(not (marker.parent / "bundle.zip").exists(), "conflicting edition bundle formats")
    return {name: (marker.parent / name).read_bytes() for name in names}


@pauses_collection
def verify_frame(root, *, graph_cell_limit=GRAPH_CELL_LIMIT):
    """Verify a completed fixed-plan dataframe result without accessing Unity."""
    with open_retained_run(root) as retained:
        if retained.run["schema"] == POLICY_RUN_SCHEMA:
            summary = _verify_policy_frame(retained)
        else:
            summary = _verify_frame(retained, graph_cell_limit)
    document = record_value(summary)
    write_once(retained.root / "frame-verification.json", json.dumps(document).encode())
    return document


def _verify_policy_frame(retained):
    run = retained.run
    assignment = retained.assignment()
    numeric = numeric_profile(assignment)
    entries = run["evaluation"]["dataframe"]
    require(isinstance(entries, list) and len(entries) == 1, "expected one dataframe publication")
    facts = entries[0]
    handle = run["outputs"]["dataframe_result"]["reference"]
    require(facts.get("schema") == "tn.paper-dataframe.v2" and facts.get("output_reference") == handle
            and handle["group"] == "values" and handle["field"] == "value",
            "evaluation output differs from the dataframe publication")
    dag, _ = retained.policy_dag(assignment)
    policies, _ = _frame_policies(retained, dag, assignment)
    require(facts.get("policies") == sorted(policies) and facts.get("numeric_profile") == numeric.profile
            and facts.get("output_schema") == {"amount": numeric.profile["dtype"]},
            "dataframe policy or type differs from its source assignment")
    use = tn.UseContext(run["request"]["application"], run["request"]["purpose"], "verify")
    catalog, editions = retained.admit_editions(dag, assignment, use)
    expected_editions = {edition.id for edition in editions}
    def accept(ctx):
        return (ctx.writer in retained.writers and ctx.object_type == VALUE_TYPE and ctx.use_context == use
                and {p.revision_id for p in ctx.policies} == set(policies) and contracted(ctx.policies, policies)
                and {binding.edition_record_id for binding in ctx.governance.dataset_bindings} == expected_editions
                and catalog.accepts(ctx, dag))
    obj = retained.object(handle["object_id"])
    data = retained.session.receive(obj, use=use, groups=["values", "evidence"], decide=accept)
    manifest = signed_manifest(data)
    require(manifest["schema"] == POLICY_SCHEMA, "missing signed dataframe policy binding")
    value = decode(data.get(handle["field"], group=handle["group"]), numeric.kind)
    rows = ReferenceRows.load(retained.root, assignment, facts, run)
    require(value == rows.expected_amount(numeric)
            and manifest["bindings"][handle["field"]]["declared"] == describe(value),
            "published dataframe amount differs from the reference calculation")
    return {"schema": "tn.paper-frame-verification.v2", "source_rows": rows.count,
            "policy_revisions": sorted(policies), "output_reference": handle,
            "value_matches_reference": True}


def _verify_frame(retained, graph_cell_limit):
    run = retained.run
    use = tn.UseContext(run["request"]["application"], run["request"]["purpose"], "verify")
    assignment = retained.assignment()
    require(assignment["table"] == "market_data", "dataframe assignment refers to another SQL snapshot")
    numeric = numeric_profile(assignment)
    dag, _policy_edges = retained.policy_dag(assignment)
    policies, policy_columns = _frame_policies(retained, dag, assignment)
    catalog, editions = retained.admit_editions(dag, assignment, use)
    artifacts = _evaluator_artifacts(editions)
    records, by_id = retained.records()
    result, decision, facts = _frame_result(run, records, by_id, use, assignment, numeric)
    reader = FrameReader(retained, policies, catalog, dag, use, editions, numeric.kind)
    rows = ReferenceRows.load(retained.root, assignment, facts, run)
    expected_amount = rows.expected_amount(numeric)
    references, input_commitments = _check_cells(facts, rows, reader, editions, numeric, run["assignment_id"])
    evaluators, artifact_hashes = _load_evaluators(retained, editions, facts, artifacts, policies, numeric.schema)
    _replay_opa(facts, policies, policy_columns, evaluators, use, len(rows.filtered))
    _check_audit(facts, expected_amount, references, artifacts, evaluators)
    outputs = _check_outputs(run, reader, facts, result, expected_amount, numeric.type)
    return {"schema": "tn.paper-frame-verification.v1", "network_used": False,
            "result_record_id": result.id, "decision_record_id": decision.id, "observer": retained.session.did,
            "verify_use": {"application": use.application, "purpose": use.purpose, "operation": use.operation},
            "source_snapshot_sha256": rows.snapshot_hash, "source_rows": rows.count,
            "filtered_rows": len(rows.filtered), "opa_decisions_replayed": len(facts["opa_decisions"]),
            "policy_revisions": sorted(policies), "stages_per_policy": list(_STAGES),
            "input_commitments": _commitment_report(input_commitments, graph_cell_limit),
            "output_commitments": outputs, "artifact_sha256": artifact_hashes,
            "verifier_source_sha256": _digest(Path(__file__).read_bytes())}


@dataclass(frozen=True)
class NumericProfile:
    """The signed SQL numeric kind and the dataframe profile every source contract agrees on."""

    kind: str
    type: type
    profile: dict

    @property
    def schema(self):
        return {"name": "String", "value": self.profile["dtype"]}


def numeric_profile(assignment):
    kind = assignment["columns"]["value"]["kind"]
    require(kind in _NUMERIC_TYPES, "unsupported SQL numeric type")
    profile = assignment["columns"]["value"]["rule"].get("dataframe_numeric", _DEFAULT_NUMERIC)
    if kind == "Decimal":
        precision, scale = profile.get("precision"), profile.get("scale")
        require(type(precision) is int and type(scale) is int and 0 <= scale <= precision <= 38
                and precision > 0, "invalid signed Decimal precision or scale")
        expected = {"kind": "Decimal", "precision": precision, "scale": scale,
                    "dtype": f"Decimal(precision={precision}, scale={scale})"}
    else:
        expected = {"kind": kind, "dtype": {"int": "Int64", "float": "Float64"}[kind]}
    require(profile == expected, "numeric profile contradicts the signed SQL kind")
    for field in assignment["columns"].values():
        require(field["rule"].get("dataframe_numeric", _DEFAULT_NUMERIC) == profile,
                "source contracts disagree about dataframe numeric type")
    return NumericProfile(kind, _NUMERIC_TYPES[kind], profile)


def _frame_policies(retained, dag, assignment):
    """Both source columns' contracts; each must grant the dataframe operation."""
    for column, field in assignment["columns"].items():
        require(column in {"name", "value"} and "dataframe_calculate" in field["rule"]["operations"],
                "dataframe operation is absent from a contributing assignment")
    policies = retained.select_policies(dag, assignment)
    policy_columns = {field["revision"]: column for column, field in assignment["columns"].items()}
    require(set(policy_columns.values()) == {"name", "value"}, "fixed calculation needs both source contracts")
    return policies, policy_columns


def _evaluator_artifacts(editions):
    """Each policy's one signed evaluator set; every edition carries a complete set."""
    artifacts = {}
    for edition in editions:
        required = {item.revision_id for item in edition.contracts}
        require({item.policy_revision for item in edition.evaluator_artifacts} == required,
                "edition lacks a complete signed evaluator set")
        for artifact in edition.evaluator_artifacts:
            value = _artifact_facts(artifact)
            require(artifacts.get(artifact.policy_revision, value) == value,
                    "one policy has conflicting signed evaluator sets")
            artifacts[artifact.policy_revision] = value
    return artifacts


def _frame_result(run, records, by_id, use, assignment, numeric):
    """The one dataframe Result, its permit, and signed facts that match the fixed plan."""
    frame_results = [record for record in records if record.body["kind"] == "Result"
                     and record.body["operation"] == "dataframe_calculate"]
    require(len(frame_results) == 1, "expected one completed dataframe Result")
    result = frame_results[0]
    facts = result.body["details"]["dataframe"]
    decision = by_id[result.body["details"]["decision_id"]]
    require(decision.body["kind"] == "Decision" and decision.body["details"]["permitted"] is True,
            "dataframe Result has no completed permit")
    require(facts["schema"] == "tn.paper-dataframe.v1" and facts["plan"] == _PLAN,
            "dataframe evidence is not the fixed evaluated plan")
    require(decision.body["details"]["parameters"] == [_PLAN],
            "dataframe Result plan differs from the authorized operation parameters")
    require(facts["input_references"] == result.body["inputs"] == decision.body["inputs"],
            "dataframe facts changed the protected inputs")
    require(result.body["application"] == use.application and result.body["purpose"] == use.purpose,
            "dataframe evidence refers to another request context")
    if "dataframe_numeric" in assignment["columns"]["value"]["rule"]:
        require(facts.get("numeric_profile") == numeric.profile and facts.get("input_schema") == numeric.schema
                and facts.get("output_schema") == {"amount": numeric.profile["dtype"]},
                "signed execution schema differs from the assigned numeric profile")
    _check_export(run, result, decision, facts)
    return result, decision, facts


def _check_export(run, result, decision, facts):
    expected = {**facts, "decision_id": decision.id, "result_id": result.id,
                "output_reference": result.body["details"]["output"]}
    require(run["evaluation"]["dataframe"] == [expected],
            "exported dataframe observations differ from the signed Result")
    handle = run["outputs"]["dataframe_result"]
    require(handle["result_id"] == result.id and handle["reference"] == result.body["details"]["output"],
            "dataframe output handle differs from its signed Result")


class FrameReader:
    """Cached admission and opening of value publications under the verifier's use."""

    def __init__(self, retained, policies, catalog, dag, use, editions, numeric_kind):
        self.retained, self.policies, self.catalog, self.dag, self.use = retained, policies, catalog, dag, use
        self.by_source = {edition.source_object_id: edition for edition in editions}
        self.numeric_kind = numeric_kind
        self.open_publication = retained.cached(self._open_publication)

    def accepts_value(self, ctx):
        return (ctx.writer in self.retained.writers and ctx.object_type == VALUE_TYPE and bool(ctx.policies)
                and contracted(ctx.policies, self.policies) and ctx.use_context == self.use
                and (not ctx.governance.dataset_bindings or self.catalog.accepts(ctx, self.dag)))

    def ancestor(self, identity):
        obj = self.retained.object(identity)
        view = self.retained.governance(identity)
        require(obj.writer in self.retained.writers and obj.object_type == VALUE_TYPE
                and contracted(view.governance.policies, self.policies),
                "native ancestor has an unrecognized writer or contract")
        return view

    def _open_publication(self, identity):
        obj = self.retained.object(identity)
        tn.LineageVerifier(max_objects=65536, max_depth=256).verify(
            self.retained.governance(identity), self.catalog, self.dag, self.ancestor)
        edition = self.by_source.get(obj.id)
        selection = (self.catalog.select(edition.dataset, edition.edition, edition.id, self.use)
                     if edition is not None else None)
        data = self.retained.session.receive(obj, use=self.use, groups=["values", "evidence"],
                                             selection=selection, decide=self.accepts_value)
        manifest = signed_manifest(data)
        require(manifest["schema"] in SCHEMAS, "unknown primitive binding schema")
        return (holder(obj, "values").envelope["values"]["field_hashes"], tuple(data.dataset_bindings),
                manifest, data.get(None, group="values"))

    def open_value(self, reference):
        require(reference["group"] == "values", "unexpected business group")
        commitments, dataset_bindings, manifest, payloads = self.open_publication(reference["object_id"])
        binding = manifest["bindings"][reference["field"]]
        payload = payloads[reference["field"]]
        require(type(payload) is str, "primitive wire payload is not a string")
        kind = binding["declared"]["kind"]
        require(kind in {"str", self.numeric_kind}, "unsupported primitive kind")
        value = decode(payload, kind)
        require(encode(value) == payload and describe(value) == binding["declared"],
                "numeric encoding or declared facts differ from the opened value")
        return commitments, dataset_bindings, binding, value


@dataclass(frozen=True)
class ReferenceRows:
    """The retained SQLite rows the reference calculation reads, and their filtered, sorted subset."""

    snapshot_hash: str
    count: int
    selected: list
    filtered: list

    @classmethod
    def load(cls, root, assignment, facts, run):
        database = root / "market.sqlite"
        snapshot_hash = _digest(database.read_bytes())
        require(snapshot_hash == assignment["source"]["snapshot_sha256"],
                "retained SQLite snapshot differs from signed assignment")
        count = facts["source_row_count"]
        require(type(count) is int and count > 0 and count == run["evaluation"]["rows"], "source row count differs")
        sqlite3.register_converter("DECIMAL_TEXT", lambda raw: Decimal(raw.decode("ascii")))
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True,
                                     detect_types=sqlite3.PARSE_DECLTYPES)) as connection:
            connection.execute("PRAGMA query_only = ON")
            selected = connection.execute("SELECT name, value FROM market_data LIMIT ?", (count,)).fetchall()
        require(_digest(database.read_bytes()) == snapshot_hash and len(selected) == count,
                "SQL reference calculation changed the snapshot or row count")
        filtered = sorted((row for row in selected if row[1] >= 0), key=lambda row: row[0])
        return cls(snapshot_hash, count, selected, filtered)

    def expected_amount(self, numeric):
        with localcontext() as decimal_context:
            decimal_context.prec = max(50, 40 + len(str(self.count)))
            amount = sum((row[1] + 250 for row in self.filtered), numeric.type(0))
            if numeric.kind == "Decimal":
                amount = amount.quantize(Decimal(1).scaleb(-numeric.profile["scale"]))
        return amount


def _check_cells(facts, rows, reader, editions, numeric, assignment_id):
    """Every input cell opens to its retained SQL value under its exact source edition."""
    editions_by_id = {edition.id: edition for edition in editions}
    input_roots, commitments_out, retained_editions = {"name": set(), "value": set()}, [], {}
    references = unpack_references(facts["input_references"])
    cells = unpack_source_cells(facts["source_cells"], references)
    require(len(cells) == 2 * rows.count and len(references) == 2 * rows.count,
            "dataframe omitted or duplicated an input cell")
    for index, cell in enumerate(cells):
        column, row = ("name" if index % 2 == 0 else "value"), index // 2
        reference = references[index]
        require(cell["row"] == row and cell["column"] == column and cell["reference"] == reference,
                "dataframe cell position differs from signed inputs")
        commitments, dataset_bindings, binding, value = reader.open_value(reference)
        require(value == rows.selected[row][index % 2]
                and type(value) is (str if column == "name" else numeric.type),
                "governed cell differs from the retained SQL value")
        edition = _cell_edition(cell, column, row, binding, dataset_bindings, editions_by_id,
                                rows.snapshot_hash, assignment_id)
        input_roots[column].add(cell["root"])
        retained_editions[edition.id] = {"dataset": edition.dataset, "edition": edition.edition,
            "record_id": edition.id, "source_object_id": edition.source_object_id,
            "contracts": [contract.revision_id for contract in edition.contracts]}
        commitments_out.append({"reference": reference, "field_commitment": commitments[reference["field"]]})
    _check_lineage_facts(facts, input_roots, retained_editions)
    return references, commitments_out


def _cell_edition(cell, column, row, binding, dataset_bindings, editions, snapshot_hash, assignment_id):
    """The cell's one original source, which must be its signed SQL origin under its exact edition."""
    require(len(dataset_bindings) == 1 and len(binding["origins"]) == 1, "input cell has ambiguous original source")
    source, native_binding = binding["origins"][0], dataset_bindings[0]
    edition = editions[native_binding.edition_record_id]
    require(source["column"] == column and source["row"] == row and source["table"] == "market_data"
            and source["snapshot_sha256"] == snapshot_hash and source["assignment_id"] == assignment_id,
            "input origin differs from its signed SQL assignment")
    require(cell["source_object_id"] == edition.source_object_id == native_binding.source_object_id
            and cell["edition_record_id"] == edition.id, "dataframe cell substituted an edition")
    require(cell["root"] == edition.source_object_id + "::" + column,
            "column lineage root differs from exact source publication")
    return edition


def _check_lineage_facts(facts, input_roots, retained_editions):
    require(facts["source_editions"] == list(retained_editions.values()),
            "frame edition observations differ from native records")
    require(facts["input_columns"] == {name: sorted(roots) for name, roots in input_roots.items()},
            "input column lineage omits source roots")
    require(facts["output_columns"] == {"amount": sorted(input_roots["value"])}
            and facts["row_selection_sources"] == sorted(input_roots["name"] | input_roots["value"]),
            "aggregate or row-selection lineage differs from filter/sort dependencies")


def _load_evaluators(retained, editions, facts, artifacts, policies, schema):
    """Load each edition's bundled evaluator bytes; every file matches its signed digest."""
    bundles = _bundle_locators(retained.root)
    require({item["policy_revision"]: item for item in facts["policy_artifacts"]} == artifacts,
            "signed dataframe artifact observations differ from source editions")
    evaluators, artifact_hashes = {}, {}
    for edition in editions:
        marker = bundles[edition.id]
        names = [f"evaluators/{artifact.policy_revision[7:]}/{name}"
                 for artifact in edition.evaluator_artifacts for name in _FILES]
        members = _bundle_members(marker, ["edition.tn", *names])
        require(members["edition.tn"] == retained.store.get(edition.id),
                "bundle edition differs from retained native wire")
        for artifact in edition.evaluator_artifacts:
            payload = _artifact_payload(retained.root, marker, members, artifact, artifact_hashes)
            _check_evaluator_metadata(payload, policies[artifact.policy_revision], schema)
            if artifact.policy_revision not in evaluators:
                evaluators[artifact.policy_revision] = OpaWasmEvaluator.from_bytes(
                    payload["policy.wasm"], payload["data.json"])
    return evaluators, artifact_hashes


def _bundle_locators(root):
    """Immutable bundles, located by their indexed native edition identities."""
    bundles = {}
    for path in [*(root / "editions").glob("*/*/bundle.json"), *(root / "editions").glob("*/*/bundle.zip")]:
        locator = json.loads(_bundle_members(path, ["bundle.json"])["bundle.json"])
        require(locator["record_id"] not in bundles, "duplicate edition bundle locator")
        bundles[locator["record_id"]] = path
    return bundles


def _artifact_payload(root, marker, members, artifact, artifact_hashes):
    prefix = f"evaluators/{artifact.policy_revision[7:]}/"
    payload = {name: members[prefix + name] for name in _FILES}
    for name, attribute in _FILES.items():
        actual = _digest(payload[name])
        require(actual == getattr(artifact, attribute), "evaluator artifact differs from its signed edition")
        location = (marker.relative_to(root).as_posix() + "!/" + prefix + name if marker.name == "bundle.zip"
                    else (marker.parent / prefix / name).relative_to(root).as_posix())
        artifact_hashes[location] = actual
    return payload


def _check_evaluator_metadata(payload, policy, schema):
    compiled, profile = json.loads(payload["compiled_policy.json"]), json.loads(payload["profile.json"])
    require(compiled["policy_ref"] == policy.policy_ref
            and compiled["fields"] == {"name": "internal", "value": "internal"}
            and profile["dtypes"] == schema,
            "evaluator metadata differs from the fixed source schema or contract")


def _replay_opa(facts, policies, policy_columns, evaluators, use, filtered_rows):
    """Replay every signed OPA decision offline; each stage covers every contributing contract."""
    require(len(facts["opa_decisions"]) == len(_STAGES) * len(policies), "missing or additional OPA decisions")
    observed = Counter()
    for index, recorded in enumerate(facts["opa_decisions"]):
        request, stage = recorded["request"], _STAGES[index // len(policies)]
        revision = request["policy_revision"]
        require(revision in policies and request["operation"] == stage,
                "OPA stage order or contributing contract differs")
        observed[stage, revision] += 1
        _check_opa_request(request, stage, policy_columns[revision], policies[revision], use, filtered_rows)
        actual = evaluators[revision].decide(request)
        require(recorded["allow"] is True and actual.allow is True
                and actual.decision_id == recorded["decision_id"] and actual.reason == recorded["reason"],
                "offline OPA replay differs from the signed operation observation")
    require(observed == Counter((stage, revision) for stage in _STAGES for revision in policies),
            "not every contributing contract covered every dataframe stage")


def _check_opa_request(request, stage, local_column, policy, use, filtered_rows):
    """One stage's request names its column and row dependencies, use, and aggregate support."""
    fields = {"name": "name", "value": "value"}
    if stage == "with_columns":
        fields["adjusted"] = "value"
    elif stage in {"select", "release"}:
        fields = {"amount": "value"}
    expected_columns = [{"name": name, "sources": [source] if source == local_column else [],
                         "classification": "internal" if source == local_column else "public"}
                        for name, source in fields.items()]
    row_dependencies = set() if stage == "load" else {"value"} if stage == "filter" else {"name", "value"}
    require(request["columns"] == expected_columns
            and request["row_selection_sources"] == ([local_column] if local_column in row_dependencies else []),
            "OPA request omitted or changed its column/row dependencies")
    require(request["policy_ref"] == policy.policy_ref
            and request["audience"] == ("governed-runtime" if stage == "release" else use.application)
            and request["use"] == {"application": use.application, "purpose": use.purpose,
                                   "operation": "dataframe_calculate"},
            "OPA request changed the accepted application use or destination")
    expected_support = ({"known": True, "aggregated": True, "group_sizes": [filtered_rows], "output_rows": 1}
                        if stage == "release" else {"known": False})
    require(request["aggregate_support"] == expected_support,
            "OPA aggregate support differs from the retained source rows")


def _check_audit(facts, expected_amount, references, artifacts, evaluators):
    if "audit" not in facts:
        return
    from tn_polars.audit import verify_audit

    verify_audit(facts["audit"], rows=[{"amount": expected_amount}],
                 expected_sources={item["object_id"] for item in references},
                 expected_artifacts=artifacts, evaluator_for=lambda revision: evaluators[revision])
    require(facts["audit"]["input_references"] == facts["input_references"],
            "dataframe audit input references differ from the signed Result")


def _check_outputs(run, reader, facts, result, expected_amount, numeric_type):
    """Both encrypted outputs open to the independently calculated amount."""
    outputs = {}
    for label, expected in (("dataframe_result", expected_amount),
                            ("amount", expected_amount + run["evaluation"]["depth"])):
        reference = run["outputs"][label]["reference"]
        commitments, _dataset_bindings, _binding, value = reader.open_value(reference)
        require(type(value) is numeric_type and value == expected,
                "encrypted numeric result differs from independent reference calculation")
        outputs[label] = {"reference": reference, "value": value,
                          "field_commitment": commitments[reference["field"]]}
    require(facts["output"] == {"column": "amount", "value": record_value(expected_amount)},
            "signed dataframe output differs from its encrypted value")
    require(result.body["details"]["field_commitment"] == outputs["dataframe_result"]["field_commitment"],
            "dataframe Result field commitment differs from native output")
    return outputs
