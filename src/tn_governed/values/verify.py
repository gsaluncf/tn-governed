"""Offline verification of retained native TN publications and evidence.

The configured observer checks governance without opening primitive payloads.
A retained model report is opened under its recipient use. The run manifest
supplies trusted identities and record-chain checkpoints. No publisher or
Java connection is needed. Cryptography verifies attribution and bindings;
it does not establish the truth of a computation.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

import tn

from .collection import pauses_collection
from .evidence import EvidenceRecorder, require
from .holders import holder
from .manifests import SCHEMAS, signed_manifest
from .primitives import Context, TNNumeric, TNString, VALUE_TYPE, ValueReference
from .retained_run import INSPECT, POLICY_RUN_SCHEMA, contracted, open_retained_run
from .verify_calls import AssignmentTerms, check_calls, verify_recorded_permits
from .verify_graph import IncarnationGraph, SqlSources, ref_key, results_by_field
from .verify_report import GRAPH_CELL_LIMIT, report_graph, write_reports

_VERIFIER_SOURCES = ("retained_run.py", "verify.py", "verify_calls.py", "verify_graph.py",
                     "verify_model.py", "verify_report.py")
_SCOPE = ("Native signatures/integrity; record ordering; source assignments; discharged monitoring; "
          "claim and contract retention; native edition and lineage verification. No source primitive "
          "payload opened, and no assertion that a signature proves computation truth.")
_MODEL_SCOPE = (" Model verification additionally admits and opens the signed report under the enrolled "
                "recipient's declared use; source primitive payloads remain closed.")


@pauses_collection
def verify(root, *, graph_cell_limit=GRAPH_CELL_LIMIT):
    with open_retained_run(root) as retained:
        if retained.run["schema"] == POLICY_RUN_SCHEMA:
            summary = _verify_policies(retained)
            (retained.root / "verification.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
            return summary
        summary, graph = _verify(retained, graph_cell_limit)
    write_reports(retained.root, summary, graph)
    return summary


def _verify_policies(retained):
    """Open each named output under the observer's accepted rules and inspect its signed field."""
    run = retained.run
    assignment = retained.assignment()
    dag, _ = retained.policy_dag(assignment)
    policies = retained.select_policies(dag, assignment)
    application, purpose = (run["request"][key] for key in ("application", "purpose"))
    catalog, editions = retained.admit_editions(dag, assignment, tn.UseContext(application, purpose, "inspect-claims"))
    records, by_id = retained.records()
    rules = {field["revision"]: field["rule"] for field in assignment["columns"].values()}
    verify_recorded_permits(records, by_id, AssignmentTerms(retained.authority, rules, policies))
    observer = Context(retained.session, EvidenceRecorder(retained.session, retained.store, retained.audit),
                       None, application=application, purpose=purpose, actor="observer",
                       metadata_accept=lambda c: c.writer in retained.writers and c.object_type == VALUE_TYPE
                       and bool(c.policies) and contracted(c.policies, policies))
    observer.catalog, observer.policy_dag = catalog, dag
    observer.editions = {edition.source_object_id: edition for edition in editions}
    outputs, nodes, bindings = {}, {}, {}
    for name, handle in run["outputs"].items():
        ref = ValueReference(**handle["reference"])
        cls = {"TNString": TNString, "TNNumeric": TNNumeric}[handle["kind"]]
        value = cls(ref, handle["decision_id"], handle["result_id"], metadata_provider=observer.string_metadata)
        data, binding, claims = observer._metadata(value)
        require(all(claim.id in by_id for claim in claims), "claim is absent from the signed evidence")
        require(all(identity in by_id for identity in binding.get("actions", ())), "action evidence is absent")
        key = ref_key(handle["reference"])
        nodes[key] = outputs[name] = {
            "id": ref.object_id, "reference": ref.to_dict(), "kind": binding["declared"]["kind"],
            "policy_revisions": sorted(policy.revision_id for policy in data.policies),
            "policy_names": sorted(policy.policy_ref for policy in data.policies),
            "claim_statements": sorted(claim.statement for claim in claims),
            "claims": [claim.id for claim in claims], "actions": binding.get("actions", []),
        }
        bindings[key] = binding
    if run.get("evaluation", {}).get("mode") in {"primitive", "explicit"}:
        # Known market-report fixture: both assigned columns govern the aggregate and brief.
        # Compare the published rules directly to the signed assignment.
        for name in ("dataframe_result", "amount", "model_input"):
            if name in outputs:
                require(set(outputs[name]["policy_revisions"]) == set(policies),
                        f"{name} omitted an assigned policy")
                if run["evaluation"]["claim"] and "attested_name" in outputs:
                    original = outputs["attested_name"]["claims"]
                    require(original and set(original) <= set(outputs[name]["claims"]),
                            f"{name} omitted an original claim")
    summary = {"schema": "tn.policy-verification.v2", "outputs": outputs, "observer": retained.session.did,
               "record_count": len(records), "record_kinds": dict(Counter(record.body["kind"] for record in records)),
               "source_editions": len(editions), "policy_revisions": len(dag), "failures": _failures(records)}
    if run.get("model"):
        from .verify_model import verify_model
        summary["model"] = verify_model(retained.root, run, records, by_id, rules, nodes, bindings, retained.store,
                                        catalog, dag, retained.governance, retained.session.governance_hash_key)
    return summary


def _verify(retained, graph_cell_limit):
    run = retained.run
    assignment = retained.assignment()
    dag, policy_edges = retained.policy_dag(assignment)
    rules = {field["revision"]: field["rule"] for field in assignment["columns"].values()}
    terms = AssignmentTerms(retained.authority, rules, retained.select_policies(dag, assignment))
    source_use = tn.UseContext(run["request"]["application"], run["request"]["purpose"], "inspect-claims")
    catalog, editions = retained.admit_editions(dag, assignment, source_use)
    source_editions = {edition.source_object_id: edition for edition in editions}
    records, by_id = retained.records()
    calls = check_calls(records, by_id, terms)
    reader = ValueReader(retained, terms.policies, catalog, dag)
    results = results_by_field(records, reader.evidence)
    sources = SqlSources(assignment, run["assignment_id"], source_editions, calls.sql_reads)
    graph = IncarnationGraph(retained, sources, results, by_id, reader.evidence, reader.commitments)
    graph.visit_all()
    summary = {"schema": "tn.primitive-verification.v1", "network_used": False,
               "observer": retained.session.did, "record_count": len(records),
               "record_kinds": dict(Counter(r.body["kind"] for r in records)),
               "incarnations": len(graph.nodes), "derivation_edges": len(graph.edges),
               "source_editions": len(source_editions), "policy_revisions": len(dag),
               "policy_edges": policy_edges, "refusals": calls.refusals, "failures": _failures(records),
               "native_lineage": _check_outputs(run, results, graph, reader.lineage),
               "verifier_source_sha256": _source_digests(), "scope": _SCOPE}
    if run.get("model"):
        from .verify_model import verify_model
        summary["model"] = verify_model(retained.root, run, records, by_id, rules, graph.nodes, graph.bindings,
                                        retained.store, catalog, dag, reader.view,
                                        retained.session.governance_hash_key)
        summary["scope"] += _MODEL_SCOPE
    return summary, report_graph(list(graph.nodes.values()), graph.edges, policy_edges, graph_cell_limit)


class ValueReader:
    """Cached reads of value publications admitted under the assignment's selected contracts."""

    def __init__(self, retained, policies, catalog, dag):
        self.retained, self.policies, self.catalog, self.dag = retained, policies, catalog, dag
        self.view = retained.cached(self._view)
        self.evidence = retained.cached(self._evidence)
        self.commitments = retained.cached(self._commitments)
        self.lineage = retained.cached(self._lineage)

    def accepts_value(self, ctx):
        return (ctx.writer in self.retained.writers and ctx.object_type == VALUE_TYPE and bool(ctx.policies)
                and contracted(ctx.policies, self.policies))

    def _view(self, identity):
        obj = self.retained.object(identity)
        require(obj.writer in self.retained.writers and obj.object_type == VALUE_TYPE,
                "unrecognized ancestor publisher/type")
        result = self.retained.governance(identity)
        require(contracted(result.governance.policies, self.policies), "ancestor substituted a contract")
        return result

    def _evidence(self, identity):
        working = self.retained.session.receive(self.retained.object(identity), use=tn.UseContext(*INSPECT),
                                                groups=["evidence"], decide=self.accepts_value)
        manifest = signed_manifest(working)
        require(manifest["schema"] in SCHEMAS, "unknown primitive manifest")
        return manifest, {p.revision_id for p in working.policies}

    def _commitments(self, identity, group):
        return holder(self.retained.object(identity), group).envelope[group]["field_hashes"]

    def _lineage(self, identity):
        return tn.LineageVerifier(max_objects=65536, max_depth=256).verify(
            self.view(identity), self.catalog, self.dag, self.view)


def _check_outputs(run, results, graph, lineage):
    """Each exported handle cites its own field's evidence; its native lineage is verified."""
    native_lineage = {}
    for name, handle in run["outputs"].items():
        key = ref_key(handle["reference"])
        require(results[key].id == handle["result_id"] and graph.nodes[key]["decision_id"] == handle["decision_id"],
                "exported handle cites different operation evidence")
        checked = lineage(key[0])
        native_lineage[name] = {"object_ids": checked.object_ids, "source_object_ids": checked.source_object_ids}
    return native_lineage


def _failures(records):
    return [{"decision_id": r.body["details"]["decision_id"], "operation": r.body["operation"],
             "error_type": r.body["details"]["error_type"], "writer": r.writer}
            for r in records if r.body["kind"] == "Failure"]


def _source_digests():
    here = Path(__file__).parent
    return {name: hashlib.sha256((here / name).read_bytes()).hexdigest()
            for name in _VERIFIER_SOURCES if (here / name).exists()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("--graph-cell-limit", type=int, default=GRAPH_CELL_LIMIT,
                        help="source cells above which dag.json has one node per source publication")
    arguments = parser.parse_args()
    verify(arguments.run_directory, graph_cell_limit=arguments.graph_cell_limit)
