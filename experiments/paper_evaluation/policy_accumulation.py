"""Measure retained governance after filtering and combining signed SQL inputs.

Catalog locations are resolved locally. Policy verification, encryption, signatures,
OPA evaluation, dataframe execution, and disclosure use the application code.
"""

import argparse
import base64
import json
import sqlite3
from contextlib import ExitStack, closing
from pathlib import Path

import tn

from tn_governed.native_objects import NativeObjects
from tn_governed.values.catalog import AssignedRules, markdown
from tn_governed.values.evidence import EvidenceRecorder, verify_tape
from tn_governed.values.provision import provision
from tn_governed.values.sql import GovernedSQL, source_identity
from tn_governed.values.string import OperationDenied

from .frames import DataframeContext, DataframeGovernance, dataframe_calculate

APPLICATION = "analysis"
PURPOSE = "internal"
CLAIM = "This company name identifies an input to the internal calculation."
CASES = (
    (16, 0, 1),
    (16, 8, 1),
    (16, 16, 1),
    (64, 32, 1),
    (16, 8, 2),
    (16, 8, 4),
)


class LocalCatalog:
    """Resolve signed assignment and edition bundles without a network service."""

    def __init__(self):
        self.volumes = {}

    def request(self, method, path, payload=None):
        if path in {"/catalogs", "/schemas"}:
            return {}
        if method == "POST" and path == "/volumes":
            identity = ".".join(payload[key] for key in ("catalog_name", "schema_name", "name"))
            self.volumes[identity] = dict(payload)
            return self.volumes[identity]
        if method == "GET" and path.startswith("/volumes/"):
            return self.volumes[path.removeprefix("/volumes/")]
        raise ValueError(f"unsupported catalog request: {method} {path}")


class _AccumulationCase:
    """One filtered, combined calculation over signed SQL sources, and the governance it retains."""

    def __init__(self, directory, rows, survivors, sources):
        if rows < 1 or not 0 <= survivors <= rows or sources < 1 or rows % sources:
            raise ValueError("rows must divide into nonempty sources and bound the survivor count")
        self.root, self.rows, self.survivors, self.sources = Path(directory), rows, survivors, sources
        self.source_rows = rows // sources
        self.restricted = sources - 1 if sources > 1 else None
        self.database = self.root / "input.sqlite"

    def run(self):
        """Calculate once, check the retained governance, and write the case's evidence."""
        self.root.mkdir(parents=True, exist_ok=False)
        self._write_sources()
        paths = provision(self.root / "sessions", roles=("catalog", "gateway", "worker"))
        with ExitStack() as stack:
            self._open(stack, paths)
            result = self._calculate()
            self._check_attribution(result)
            disclosures = self._disclose(result)
            repeated = self._check_repeated(result)
            self._retain()
            summary = self._summary(result, disclosures, repeated)
            self._write(summary)
            return summary

    def _write_sources(self):
        with closing(sqlite3.connect(self.database)) as connection:
            for source in range(self.sources):
                table = f"source_{source}"
                connection.execute(f"CREATE TABLE {table} (name TEXT NOT NULL, value INTEGER NOT NULL)")
                connection.executemany(f"INSERT INTO {table} VALUES (?, ?)", [
                    ("Company", 1 if source * self.source_rows + index < self.survivors else -1)
                    for index in range(self.source_rows)
                ])
            connection.commit()

    def _open(self, stack, paths):
        """Open the sessions, publish each source's assignment, and build the SQL driver."""
        self.sessions = {
            role: stack.enter_context(tn.Session.from_config(str(path)))
            for role, path in paths.items()
        }
        self.authority = self.sessions["catalog"]
        administration = self.authority.policy("experiment.administration")
        self.audit_policy = self.authority.policy("experiment.evidence")
        self.store = NativeObjects()
        resolvers = self._resolvers(administration)
        self._publish_assignments(resolvers["catalog"])
        self.contexts = {role: self._context(role, resolvers[role]) for role in ("gateway", "worker")}
        self.context = self.contexts["worker"]
        self.driver = GovernedSQL(
            self.database, gateway=self.contexts["gateway"], consumer=self.context,
            edition_publisher=resolvers["catalog"], directory=self.root / "editions",
        )

    def _resolvers(self, administration):
        local_catalog = LocalCatalog()
        resolvers = {}
        for role, session in self.sessions.items():
            resolver = DataframeGovernance(
                "http://unused", "accumulation", session=session, authority=self.authority.did,
                administration=administration, store=self.store,
            )
            resolver.registry._request = local_catalog.request
            resolvers[role] = resolver
        return resolvers

    def _publish_assignments(self, publisher):
        """Every source reaches the review console; all but the restricted one reach analysis."""
        for source in range(self.sources):
            destinations = ["review-console"]
            if source != self.restricted:
                destinations.append("analysis-console")
            columns = {column: {
                "kind": kind, "markdown": markdown(column),
                "rule": {"destinations": destinations},
            } for column, kind in (("name", "str"), ("value", "int"))}
            publisher.publish_assignment(
                self.root / f"assignment-{source}", table=f"source_{source}",
                source_identity=source_identity(self.database), application=APPLICATION,
                actors=["analyst"], purposes=[PURPOSE], columns=columns,
            )

    def _context(self, role, resolver):
        rules = AssignedRules(
            resolver, actor="analyst", application=APPLICATION, purpose=PURPOSE,
            writers=[self.sessions["gateway"].did, self.sessions["worker"].did],
        )
        return DataframeContext(
            self.sessions[role], EvidenceRecorder(self.sessions[role], self.store, self.audit_policy),
            rules, application=APPLICATION, purpose=PURPOSE, actor="analyst", resolver=resolver,
        )

    def _calculate(self):
        """Query each source, attach the test claim, and run the governed dataframe."""
        context, frame_rows = self.context, []
        for source in range(self.sources):
            frame_rows.extend(self.driver.execute(
                f"SELECT name, value FROM source_{source} LIMIT ?", (self.source_rows,),
            ).fetchall())
        self.original = frame_rows[-1][0]
        with context:
            annotated = self.original.attest(CLAIM, context)
            self.source_claim = context._metadata(annotated)[2][0]
            frame_rows[-1] = (annotated, frame_rows[-1][1])
            input_metadata = context._metadata_many(tuple(
                value for row in frame_rows for value in row))
            self.input_revisions = {policy.revision_id for data, _, _ in input_metadata
                                    for policy in data.policies}
            return dataframe_calculate(context, frame_rows)

    def _check_attribution(self, result):
        """Check original claim identity and every contract required by the input assignments."""
        self.data, _, self.claims = self.context._metadata(result)
        self.wire = result.publication.object.forward()
        self.facts = self.context.frame_runs[-1]
        claims = self.claims
        assert len(claims) == 1 and claims[0] == self.source_claim
        assert claims[0].subjects == (self.original.reference,)
        assert claims[0].issuer == self.sessions["worker"].did
        assert len(self.data.policies) == 2 * self.sources
        assert {policy.revision_id for policy in self.data.policies} == self.input_revisions

    def _disclose(self, result):
        """Reveal to each console, counting content opens; a refused console opens nothing."""
        context, opened = self.context, []
        open_values = context._open_values

        def observe_open(*args):
            opened.append(args[0].destination)
            return open_values(*args)

        context._open_values = observe_open
        disclosures = {}
        try:
            for destination in ("analysis-console", "review-console"):
                before = len(opened)
                try:
                    value = result.reveal(context, destination=destination)
                    disclosures[destination] = {"outcome": "permitted", "value": value}
                except OperationDenied:
                    disclosures[destination] = {"outcome": "refused"}
                disclosures[destination]["content_opens"] = len(opened) - before
        finally:
            context._open_values = open_values
        expected = {"outcome": "permitted", "value": self.survivors * 251, "content_opens": 1}
        assert disclosures["review-console"] == expected
        assert disclosures["analysis-console"] == (expected if self.restricted is None else
                                                  {"outcome": "refused", "content_opens": 0})
        return disclosures

    def _check_repeated(self, result):
        """Adding the result to itself preserves its policies and original claim."""
        with self.context:
            repeated = result + result
        data, _, claims = self.context._metadata(repeated)
        assert {p.revision_id for p in data.policies} == {p.revision_id for p in self.data.policies}
        assert claims == self.claims
        value = repeated.reveal(self.context, destination="review-console")
        assert value == self.survivors * 502
        return {"policy_count": len(data.policies), "claim_count": len(claims), "value": value}

    def _retain(self):
        self.store.export(self.root / "publications")
        for role, ctx in self.contexts.items():
            verify_tape(
                ctx.recorder.records(), session=self.authority, policy=self.audit_policy,
                expected_writer=ctx.session.did, expected_context=ctx.recorder.context_id,
                expected_head=ctx.recorder.head,
            )
            ctx.recorder.export(self.root / "records" / role)

    def _summary(self, result, disclosures, repeated):
        data, claims = self.data, self.claims
        envelope = json.loads(self.wire)
        return {
            "rows": self.rows, "survivors": self.survivors, "sources": self.sources,
            "input_policy_revisions": sorted(self.input_revisions),
            "policy_revisions": sorted(p.revision_id for p in data.policies),
            "policy_count": len(data.policies), "claim_count": len(claims),
            "claim_id": claims[0].id, "claim_issuer": claims[0].issuer,
            "claim_subjects": [item.to_dict() for item in claims[0].subjects],
            "result_reference": result.reference.to_dict(),
            "output_wire_bytes": len(self.wire),
            "encrypted_governance_bytes": len(
                base64.b64decode(envelope["tn.agents"]["ciphertext"])),
            "encrypted_evidence_bytes": len(base64.b64decode(envelope["evidence"]["ciphertext"])),
            "restricted_source": self.restricted,
            "disclosures": disclosures,
            "repeated_input": repeated,
        }

    def _write(self, summary):
        (self.root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        (self.root / "dataframe.json").write_text(json.dumps(self.facts, indent=2), encoding="utf-8")


def run_case(directory, *, rows, survivors, sources):
    """Retain each source's policies while varying selection and source count."""
    return _AccumulationCase(directory, rows, survivors, sources).run()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", required=True, type=Path)
    args = parser.parse_args()
    args.run_directory.mkdir(parents=True, exist_ok=False)
    summaries = [run_case(
        args.run_directory / f"rows-{rows}-survivors-{survivors}-sources-{sources}",
        rows=rows, survivors=survivors, sources=sources,
    ) for rows, survivors, sources in CASES]
    (args.run_directory / "summary.json").write_text(
        json.dumps(summaries, indent=2), encoding="utf-8",
    )
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
