"""A retained primitive run, opened once for offline verification.

The run manifest names the trusted authority, the writers, the observer, and the
record-chain checkpoints. The authority's administration records (the source
assignment, its policy revisions, and the source editions) are admitted here for
every verifier. Each cache belongs to one verification pass and is cleared on exit.
"""

from contextlib import ExitStack, contextmanager
from functools import lru_cache
import json
from pathlib import Path

import tn
from tn_governed.publications import open_publication_store

from .evidence import require, verify_tape
from .provision import POLICY

RUN_SCHEMA = "tn.primitive-run.v1"
POLICY_RUN_SCHEMA = "tn.policy-run.v2"
ASSIGNMENT_SCHEMA = "tn.sql-assignment.v1"
# Administration and evidence records are read under this use.
INSPECT = ("offline-verifier", "inspect-evidence", "read")


def cache_bound(store):
    """Entries for one verification run: at least 128, and two per retained publication.

    Every key names a publication of the run, so a run never evicts what it reads again.
    """
    return max(128, 2 * len(store.publication_sizes()))


def contracted(policies, selected):
    """Every policy is one of the assignment's selected contracts, unchanged."""
    return all(p.revision_id in selected and p.matches_contract(selected[p.revision_id]) for p in policies)


@contextmanager
def open_retained_run(root):
    """Open the run at `root` under its configured observer; every cache clears on exit."""
    root = Path(root).resolve()
    run = json.loads((root / "run.json").read_text())
    require(run["schema"] in (RUN_SCHEMA, POLICY_RUN_SCHEMA), "unknown run manifest")
    store = open_publication_store(root / "publications", read_only=True)
    with store, tn.Session.from_config(str(root / run["observer_config"])) as session, ExitStack() as caches:
        yield RetainedRun(root, run, store, session, caches)


class RetainedRun:
    """The manifest, store, observer session, and bounded caches of one verification pass."""

    def __init__(self, root, run, store, session, caches):
        self.root, self.run, self.store, self.session = root, run, store, session
        self.authority, self.writers = run["authority"], set(run["writers"])
        self._caches, self._bound = caches, cache_bound(store)
        self.object = self.cached(self._read)
        self.governance = self.cached(self._governance)
        self.admin, self.audit = self._contracts()

    def cached(self, function):
        """`function` memoized for this pass; its entries are cleared when the run closes."""
        result = lru_cache(maxsize=self._bound)(function)
        self._caches.callback(result.cache_clear)
        return result

    def _read(self, identity):
        obj = self.store.read(identity)
        require(obj.id == identity, "retained native publication identity differs")
        return obj

    def _governance(self, identity):
        return self.session.governance(self.object(identity))

    def _contracts(self):
        admin, audit = (
            tn.Governance.from_markdown(self.authority, POLICY, ".tn/config/agents.md", name)
            for name in ("experiment.administration", "experiment.evidence"))
        require(admin.fields == self.run["administration_policy"] and audit.fields == self.run["audit_policy"],
                "checkpoint governance differs from the configured reader contract")
        return admin, audit

    def accepts_admin(self, ctx):
        return (ctx.writer == self.authority and len(ctx.policies) == 1
                and ctx.governance.matches_contract(self.admin))

    def open_admin(self, identity, group):
        """Open one administration record under the authority's administration contract."""
        admitted = self.governance(identity).accept(
            use=tn.UseContext(*INSPECT), groups=[group], decide=self.accepts_admin)
        return self.session.open(admitted, [group])

    def assignment(self):
        """The signed source assignment this run was hydrated under."""
        data = self.session.receive(self.object(self.run["assignment_id"]), use=tn.UseContext(*INSPECT),
                                    groups=["catalog_cfg"], decide=self.accepts_admin)
        assignment = data.get("assignment", group="catalog_cfg")
        require(assignment["schema"] == ASSIGNMENT_SCHEMA and assignment["source"] == self.run["source"],
                "source assignment does not match the retained run")
        return assignment

    def policy_dag(self, assignment):
        """Admit the assignment's policy revisions; return the DAG and its parent edges."""
        dag, edges = tn.PolicyDag(), []
        for identity in assignment["revisions"]:
            revision = tn.PolicyRevision.from_opened(self.open_admin(identity, "policy_revision"))
            dag.admit(revision, lambda item, parent: item.writer == self.authority)
            edges.extend({"parent": parent.revision_id, "child": revision.id, "relation": str(parent.relation)}
                         for parent in revision.parents)
        return dag, edges

    def select_policies(self, dag, assignment):
        """Each assigned column's contract, selected from the DAG by its signed scope."""
        return {field["revision"]: dag.select(field["revision"], field["scope"],
                                              lambda item: item.writer == self.authority)
                for field in assignment["columns"].values()}

    def admit_editions(self, dag, assignment, use):
        """Admit every source edition the run names; each is checked against its source publication."""
        catalog, editions = tn.DatasetCatalog(), []
        for info in self.run["source_editions"]:
            edition = tn.DatasetEdition.from_opened(self.open_admin(info["record_id"], "dataset_edition"))
            require((edition.dataset, edition.edition, edition.source_object_id)
                    == (info["dataset"], info["edition"], info["source_object_id"]), "edition index substitution")
            require(edition.grant_ref == self.run["assignment_id"] and edition.source_writer in self.writers,
                    "source edition has an unrecognized assignment or writer")
            catalog.admit(edition, dag, lambda record: record.writer == self.authority)
            selected = catalog.select(edition.dataset, edition.edition, edition.id, use)
            if self.run["schema"] == RUN_SCHEMA:
                selected.verify_source(self.governance(edition.source_object_id), use, ["values", "evidence"])
            editions.append(edition)
        return catalog, editions

    def records(self):
        """Every retained record chain, verified to its checkpoint head; identities are unique."""
        records, by_id = [], {}
        for checkpoint in self.run["tapes"].values():
            require(checkpoint["writer"] in self.writers, "unrecognized recorder writer")
            files = sorted((self.root / checkpoint["path"]).glob("*.tn"))
            require(len(files) == checkpoint["count"], "record count differs from retained checkpoint")
            for record in verify_tape([path.read_bytes() for path in files], session=self.session,
                                      policy=self.audit, expected_writer=checkpoint["writer"],
                                      expected_context=checkpoint["context_id"], expected_head=checkpoint["head"]):
                require(record.id not in by_id, "duplicate evidence record across record chains")
                by_id[record.id] = record
                records.append(record)
        return records, by_id
