"""The primitive incarnation graph, walked from every signed Result back to its SQL sources.

Each node is one native field. A derivative must keep its parents' governance, claims,
and source origins; a source must follow its authorized SQL read under the signed
column assignment.
"""

from json.encoder import encode_basestring_ascii as json_string

from .evidence import require
from .references import unpack_references
from .manifests import unique_origins


def ref_key(reference):
    return reference["object_id"], reference["group"], reference["field"]


def reference_node_id(key):
    """Identify a field without conflating siblings in the same publication."""
    if key[1:] == ("values", "value"):
        return key[0]
    return f"{key[0]}#[{json_string(key[1])},{json_string(key[2])}]"


def results_by_field(records, evidence):
    """Each native field's one signed Result; a whole-publication Result covers every binding."""
    results = {}
    for record in records:
        if record.body["kind"] == "Result":
            output = record.body["details"]["output"]
            fields = (output["field"],) if "field" in output else evidence(output["object_id"])[0]["bindings"]
            for field in fields:
                key = output["object_id"], output["group"], field
                require(key not in results, "more than one Result for an incarnation")
                results[key] = record
    return results


class IncarnationGraph:
    """Nodes, edges, and signed bindings of every field reached from a Result."""

    def __init__(self, retained, sources, results, by_id, evidence, commitments):
        self.retained, self.sources, self.results, self.by_id = retained, sources, results, by_id
        self.evidence, self.commitments = evidence, commitments
        self.nodes, self.edges, self.bindings = {}, [], {}
        self._visited, self._visiting = set(), set()

    def visit_all(self):
        for key in self.results:
            self.visit(key)

    def visit(self, key):
        if key in self._visited:
            return
        require(key not in self._visiting, "cycle in primitive incarnation graph")
        self._visiting.add(key)
        record, decision, binding, actual_policies = self._signed_binding(key)
        whole_publication = "field" not in record.body["details"]["output"]
        commitment = self.commitments(key[0], key[1]).get(key[2])
        require(commitment is not None
                and (whole_publication or record.body["details"]["field_commitment"] == commitment),
                "Result does not bind the exact native field commitment")
        parent_claims = self._check_parents(key, record, decision, binding, actual_policies)
        if not binding["parents"]:
            self.sources.check(key, record, binding, actual_policies, decision, whole_publication)
        self._check_claims(record, binding, parent_claims)
        self.nodes[key] = _node(key, record, decision, binding, actual_policies,
                                self.retained.object(key[0]).writer)
        self.bindings[key] = binding
        self._visiting.remove(key)
        self._visited.add(key)

    def _signed_binding(self, key):
        """The field's Result, its Decision, and the publication's signed binding that agrees with both."""
        record = self.results.get(key)
        require(record is not None, "missing signed Result for a primitive parent")
        rb, rd = record.body, record.body["details"]
        decision = self.by_id[rd["decision_id"]]
        require(record.writer == self.retained.object(key[0]).writer,
                "Result is not from the incarnation's publisher")
        manifest, actual_policies = self.evidence(key[0])
        binding = manifest["bindings"][key[2]]
        require(binding["decision_id"] == decision.id and binding["parents"] == rb["inputs"]
                and binding["claims"] == rd["claims"], "signed binding disagrees with Result")
        transition = rd["transition"]
        require(transition["governed_inputs"] == binding["parents"]
                and transition["retained_claims"] == binding["claims"],
                "result transition changed its contributing references")
        for literal in transition["literal_inputs"]:
            require(literal["claims"] == [], "literal invents a claimant")
        return record, decision, binding, actual_policies

    def _check_parents(self, key, record, decision, binding, actual_policies):
        """Visit each parent; a derivative keeps their governance, claims, and origins."""
        parent_policies, parent_claims = set(), set()
        parents = unpack_references(binding["parents"]) if binding["parents"] else []
        for parent in parents:
            pk = ref_key(parent)
            self.visit(pk)
            parent_policies.update(self.nodes[pk]["policy_revisions"])
            parent_claims.update(self.bindings[pk]["claims"])
            self.edges.append({"parent": reference_node_id(pk), "child": reference_node_id(key),
                               "operation": record.body["operation"]})
        dd = decision.body["details"]
        require(parent_claims <= set(binding["claims"]), "a derivative dropped a contributing claim")
        require(parent_claims == set(dd["considered_claims"]),
                "Decision did not consider the complete set of contributing claims")
        if parents:
            origins = unique_origins(origin for parent in parents
                                     for origin in self.bindings[ref_key(parent)]["origins"])
            require(parent_policies == actual_policies and origins == binding["origins"],
                    "a derivative changed contributing governance or source origins")
            require(parent_policies == {p["revision"] for p in dd["policies"]},
                    "Decision did not evaluate the complete contributing governance")
        return parent_claims

    def _check_claims(self, record, binding, parent_claims):
        """Every claim is signed; a new one names its original subjects and issuer."""
        rb = record.body
        for identity in binding["claims"]:
            claim = self.by_id.get(identity)
            require(claim is not None and claim.body["kind"] == "Claim", "unverifiable contributing claim")
            statement = claim.body["details"].get("statement")
            require(isinstance(statement, str) and bool(statement.strip()), "claim has no statement")
            if identity not in parent_claims:
                require(rb["operation"] == "attest" and claim.body["call_id"] == rb["call_id"]
                        and claim.writer == record.writer and claim.body["inputs"] == binding["parents"],
                        "new claim does not identify its original subjects and issuer")


def _node(key, record, decision, binding, actual_policies, writer):
    return {"id": reference_node_id(key), "object_id": key[0], "group": key[1], "field": key[2],
            "reference": {"object_id": key[0], "group": key[1], "field": key[2]},
            "kind": binding["declared"]["kind"], "operation": record.body["operation"],
            "writer": writer, "decision_id": decision.id, "result_id": record.id,
            "policy_revisions": sorted(actual_policies), "claims": binding["claims"],
            "source": binding["source"]}


class SqlSources:
    """Checks that each source field follows its authorized SQL read under the signed assignment."""

    def __init__(self, assignment, assignment_id, source_editions, sql_reads):
        self.assignment, self.assignment_id = assignment, assignment_id
        self.source_editions, self.sql_reads = source_editions, sql_reads
        self._scopes = {}

    def check(self, key, record, binding, actual_policies, decision, whole_publication):
        source = binding["source"]
        require(source is not None and binding["origins"] == [source],
                "source primitive lacks its signed SQL origin or edition")
        shared = frozenset((name, item) for name, item in source.items() if name != "row")
        scope_key = key[0], record.id, whole_publication or source.get("row"), shared
        if scope_key not in self._scopes:
            self._scopes[scope_key] = self._check_scope(
                key, record, source, actual_policies, decision, whole_publication)
        field, row_count = self._scopes[scope_key]
        require(binding["declared"]["kind"] == field["kind"],
                "SQL source was hydrated under the wrong column assignment")
        require(type(source["row"]) is int and 0 <= source["row"] < row_count,
                "source primitive has an invalid SQL row ordinal")
        require(key[1] == "values" and key[2] in {"value", "value_" + str(source["row"])},
                "source primitive SQL field differs from its signed row ordinal")

    def _check_scope(self, key, record, source, actual_policies, decision, whole_publication):
        """Facts every SQL cell of one publication, Result, and source scope share."""
        rb, rd = record.body, record.body["details"]
        assignment = self.assignment
        scope = ({name: item for name, item in source.items() if name != "row"}
                 if whole_publication else source)
        require(rd["source"] == scope and key[0] in self.source_editions,
                "source primitive lacks its signed SQL origin or edition")
        require(self.source_editions[key[0]].dataset == source["table"] + "." + source["column"],
                "source edition does not identify the assigned SQL column")
        field = assignment["columns"][source["column"]]
        require(actual_policies == {field["revision"]} and source["assignment_id"] == self.assignment_id
                and source["snapshot_sha256"] == assignment["source"]["snapshot_sha256"]
                and source["table"] == assignment["table"],
                "SQL source was hydrated under the wrong column assignment")
        require(actual_policies <= {p["revision"] for p in decision.body["details"]["policies"]},
                "SQL cell's policy was not included in its query Decision")
        reads = self.sql_reads[rb["context_id"], rb["call_id"]]
        require(len(reads) == 1 and reads[0].body["sequence"] < rb["sequence"]
                and reads[0].body["details"]["query_id"] == source["query_id"]
                and reads[0].body["details"]["source"] == assignment["source"]
                and reads[0].body["details"]["assignment_id"] == self.assignment_id,
                "source publication does not follow its authorized SQL read")
        row_count = reads[0].body["details"]["row_count"]
        require(type(row_count) is int, "source primitive has an invalid SQL row ordinal")
        return field, row_count
