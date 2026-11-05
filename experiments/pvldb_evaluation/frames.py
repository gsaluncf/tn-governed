"""SQL cells through governed Polars to one governed numeric result.

This adapter implements one protected ``dataframe_calculate`` call. Intermediate
lazy frames retain separate native copies with the contributing contracts.
Catalog admission and OPA checks precede data access. Polars tracks the source
rows and columns, and the context publishes the numeric result with signed records.
"""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
from uuid import uuid4

import polars as pl
import tn
from tn_polars.build import build_opa_wasm
from tn_polars.frame import GovernedLazyFrame
from tn_polars.opa import OpaModuleCache
from tn_polars.policy import CompiledPolicy
from tn_polars.registry import write_edition_bundle
from tn_governed.values.collection import pauses_collection
from tn_polars.tn_boundary import PolicySet, TnBoundary, root_name

from tn_governed.unity import FinanceEditionRequest, resolve_finance_editions
from tn_governed.values.catalog import ReceivedEdition, UnityGovernance, markdown
from tn_governed.values.evidence import EvidenceError
from tn_governed.values.numeric import TNNumeric
from tn_governed.values.numeric_codec import KINDS
from .numeric_profile import numeric_profile, polars_dtype, build_frame, check_fixed_plan_range
from tn_governed.values.primitives import Context, OPERATIONS
from tn_governed.values.string import OperationDenied, TNString, _active


OPERATION = "dataframe_calculate"
FRAME_OPERATIONS = ("load", "filter", "sort", "with_columns", "select", "release")
ARTIFACT_NAMES = ("compiled_policy.json", "profile.json", "policy.wasm", "data.json")


class DataframeGovernance(UnityGovernance):
    """Issue the experiment's source assignments and signed OPA artifact sets."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._frame_artifacts = {}

    def publish_assignment(self, directory, *, columns=None, decimal_precision=38, decimal_scale=None, **kwargs):
        columns = deepcopy(columns) if columns is not None else {
            "name": {"kind": "str", "markdown": markdown("name")},
            "value": {"kind": "int", "markdown": markdown("value")},
        }
        if set(columns) != {"name", "value"}:
            raise ValueError("this dataframe workload requires the name/value source schema")
        if columns["name"]["kind"] != "str":
            raise TypeError("name must be a string column")
        profile = numeric_profile(columns["value"]["kind"], decimal_precision, decimal_scale)
        for definition in columns.values():
            rule = definition.setdefault("rule", {})
            rule["dataframe_numeric"] = profile
            rule["operations"] = sorted(set(rule.get("operations", OPERATIONS)) | {OPERATION})
        return super().publish_assignment(directory, columns=columns, **kwargs)

    def _evaluator_artifacts(self, policy, application, profile):
        key = (policy.revision_id, application, json.dumps(profile, sort_keys=True))
        if key not in self._frame_artifacts:
            compiled = CompiledPolicy.from_dict({
                "schema": "tn.polars-policy.v1", "policy_ref": policy.policy_ref,
                "fields": {"name": "internal", "value": "internal"},
                "release": {"public": {"allow_aggregates": False, "min_group_size": 2}},
            })
            with tempfile.TemporaryDirectory(prefix="tn-pvldb-evaluator-") as temporary:
                build = Path(temporary)
                build_opa_wasm(compiled, build, operations=FRAME_OPERATIONS,
                               audiences={application: "internal", "governed-runtime": "internal"})
                files = {
                    "compiled_policy.json": json.dumps(compiled.to_dict(), sort_keys=True).encode(),
                    "profile.json": json.dumps({"dtypes": {"name": "String", "value": profile["dtype"]}},
                                               sort_keys=True).encode(),
                    "policy.wasm": (build / "policy.wasm").read_bytes(),
                    "data.json": (build / "data.json").read_bytes(),
                }
            artifacts = tn.EvaluatorArtifactSet(policy.revision_id, *(
                hashlib.sha256(files[name]).hexdigest() for name in ARTIFACT_NAMES))
            self._frame_artifacts[key] = artifacts, files
        return self._frame_artifacts[key]

    def publish_edition(self, value, *, policy, source, directory, application, purpose, register=True):
        obj = tn.GovernedObject.read(io.BytesIO(self.store.get(value.reference.object_id)))
        dataset = source["table"] + "." + source["column"]
        edition = source["query_id"] + "-" + str(source["row"])
        uses = [tn.UseContext(application, purpose, op)
                for op in sorted(OPERATIONS | {OPERATION, "inspect-claims", "verify"})]
        assignment = self.assignments[source["assignment_id"]]
        rule = assignment["columns"][source["column"]]["rule"]
        uses.extend(tn.UseContext(**use) for use in rule.get("additional_uses", []))
        artifacts, files = self._evaluator_artifacts(policy, application, rule["dataframe_numeric"])
        draft = tn.DatasetEditionDraft(dataset, edition, obj, ["values", "evidence"],
            [tn.ContractBinding(policy.revision_id, dataset)], uses, source["assignment_id"], [artifacts])
        record_obj = self.session.seal(draft.into_draft(self.administration))
        record = tn.DatasetEdition.from_opened(self._open(record_obj, "dataset_edition"))
        self.store.put(record_obj)
        bundle = write_edition_bundle(directory, dataset=dataset, edition=edition, record_id=record.id,
            edition_wire=record_obj.forward(),
            revision_wires=[(r, self.store.get(r)) for r in assignment["revisions"]],
            evaluators={policy.revision_id: files}, packed=True)
        # Source assignment publication and resolution have established this catalog and schema.
        if register:
            self.registry.register_edition(dataset, edition, record.id, bundle, create_namespace=False)
        return {"dataset": dataset, "edition": edition, "record_id": record.id,
                "source_object_id": obj.id}

    def admit_edition(self, info, context, *, transport=None):
        request = FinanceEditionRequest(info["dataset"], info["edition"], info["record_id"],
            tn.UseContext(context.application, context.purpose, "inspect-claims"))
        resolved = resolve_finance_editions([request], catalog_session=context.session,
            policy_dag=self.policy_dag, trust=self.trust,
            registry=self.registry if transport is None else ReceivedEdition(info, transport),
            catalog=context.catalog, metadata_store=self.store)[0]
        context.editions[info["source_object_id"]] = resolved.selection.record
        context.frame_editions[info["source_object_id"]] = resolved
        return resolved.selection


class DataframeContext(Context):
    """Keeps measurements for the local evaluation run."""

    def __init__(self, *args, **kwargs):
        self.frame_editions = {}
        self.frame_runs = []
        super().__init__(*args, **kwargs)


def _checked_edition(context, data, column, use, module_cache, selected):
    """Check one publication's original edition, once for all its cells in a column."""
    bindings = data.dataset_bindings
    if len(bindings) != 1:
        raise EvidenceError("each input cell must retain exactly one original SQL edition")
    binding = bindings[0]
    resolved = context.frame_editions.get(binding.source_object_id)
    if resolved is None:
        raise EvidenceError("the cell's original evaluator edition was not resolved")
    record = resolved.selection.record
    if (record.id != binding.edition_record_id or record.dataset != binding.dataset
            or record.edition != binding.edition or not record.dataset.endswith("." + column)):
        raise EvidenceError("cell position differs from its signed source edition")
    if record.id not in selected:
        context.catalog.verify_binding(binding, context.policy_dag)
        selection = context.catalog.select(record.dataset, record.edition, record.id, use)
        selected[record.id] = PolicySet.for_selection(resolved.entries, selection, module_cache=module_cache)
    return {"dataset": record.dataset, "edition": record.edition, "record_id": record.id,
            "source_object_id": record.source_object_id,
            "contracts": [item.revision_id for item in record.contracts]}


def _select_policies(context, metadata, use):
    module_cache = OpaModuleCache()
    sources = {"name": set(), "value": set()}
    selected, checked = {}, set()
    for index, (data, _, _) in enumerate(metadata):
        column = "name" if index % 2 == 0 else "value"
        key = (data.snapshot.id, column)
        if key not in checked:
            edition = _checked_edition(context, data, column, use, module_cache, selected)
            sources[column].add(root_name(edition["source_object_id"], column))
            checked.add(key)
    first, *others = selected.values()
    return first.include_all(others), sources


@pauses_collection
def dataframe_calculate(context, rows):
    """Filter, sort, add 250, and sum SQL cells inside one governed operation.

    ``rows`` contains (TNString, TNNumeric) pairs. Payloads open only after source
    assignments, signed evaluator artifacts, and OPA load admission succeed.
    The result carries the applicable contracts, original claims, and action receipts.
    """
    if not isinstance(context, DataframeContext) or _active.get() is not context:
        raise OperationDenied("dataframe calculation requires its active DataframeContext")
    rows = tuple(rows)
    if not rows or any(len(row) != 2 or not isinstance(row[0], TNString)
                       or not isinstance(row[1], TNNumeric) for row in rows):
        raise TypeError("dataframe calculation requires nonempty governed name/value rows")
    values = tuple(value for row in rows for value in row)
    call_id = uuid4().hex
    request, metadata, decision = context._prepare(OPERATION, values, None, (), call_id)
    try:
        use = tn.UseContext(context.application, context.purpose, OPERATION)
        policies, sources = _select_policies(context, metadata, use)
        policies.validate_contracts(request)
        profiles = [context.resolver.rules[p.revision_id]["dataframe_numeric"] for p in request.policies]
        profile = profiles[0]
        polars_dtype(profile)
        if any(p != profile for p in profiles):
            raise EvidenceError("contributing contracts declare conflicting numeric profiles")
        expected_schema = {"name": "String", "value": profile["dtype"]}
        if any(entry.dtypes != expected_schema for entry in policies._entries.values()):
            raise EvidenceError("signed evaluator schema differs from the source assignment")
        if any(binding["declared"]["kind"] != ("str" if i % 2 == 0 else profile["kind"])
               for i, (_, binding, _) in enumerate(metadata)):
            raise EvidenceError("input primitive kind differs from the signed dataframe profile")
        # All artifact verification and the OPA load decision precede this open.
        policies.decide("load", context.application, sources, set(), use)
        opened = context._open_values(request, values, metadata=metadata)
        frame_rows = [{"name": opened[i][1], "value": opened[i + 1][1]}
                      for i in range(0, len(opened), 2)]
        loaded = build_frame(frame_rows, profile)
        check_fixed_plan_range(loaded, profile)
        lazy = loaded.lazy()
        policies.pin(lazy)
        first = next(iter(policies._entries.values()))
        frame = GovernedLazyFrame(lazy, first.policy, {}, first.evaluator, sources=sources,
            tn_boundary=TnBoundary(opened[0][0], policies, use, "values", "rows"), ordinary_rows=True)
        result = (frame.filter(pl.col("value") >= 0).sort("name")
                  .with_columns((pl.col("value") + 250).alias("adjusted")))
        result = result.select(pl.col("adjusted").sum().alias("amount"))
        materialized, support = result._materialize()
        policies.decide("release", "governed-runtime", result.sources, result.row_sources, use,
                        aggregate_support=support)
        amount = materialized.select("amount").item()
        if type(amount) is not KINDS[profile["kind"]]:
            raise TypeError("dataframe result changed the signed numeric kind")
        if str(materialized.schema["amount"]) != profile["dtype"]:
            raise TypeError("dataframe result changed the signed numeric storage type")
        output = context.publish_value(amount, request=request, metadata=metadata, actions=(decision,))
        context.frame_runs.append({"schema": "tn.pvldb-dataframe.v2", "source_row_count": len(rows),
            "numeric_profile": profile, "policies": list(policies.revision_ids),
            "output_schema": {"amount": str(materialized.schema["amount"])},
            "output_reference": output.reference.to_dict()})
        return output
    except Exception as exc:
        context._append("Failure", request, call_id,
            {"decision_id": decision, "error_type": type(exc).__name__})
        raise
