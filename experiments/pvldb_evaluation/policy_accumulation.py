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
from unittest.mock import patch

import tn
from tn_polars.support import Support

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


def run_case(directory, *, rows, survivors, sources):
    """Retain each source's policies while varying selection and source count."""
    if rows < 1 or not 0 <= survivors <= rows or sources < 1 or rows % sources:
        raise ValueError("rows must divide into nonempty sources and bound the survivor count")
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=False)
    database = root / "input.sqlite"
    source_rows = rows // sources
    with closing(sqlite3.connect(database)) as connection:
        for source in range(sources):
            table = f"source_{source}"
            connection.execute(f"CREATE TABLE {table} (name TEXT NOT NULL, value INTEGER NOT NULL)")
            connection.executemany(f"INSERT INTO {table} VALUES (?, ?)", [
                ("Company", 1 if source * source_rows + index < survivors else -1)
                for index in range(source_rows)
            ])
        connection.commit()
    paths = provision(root / "sessions", roles=("catalog", "gateway", "worker"))
    local_catalog = LocalCatalog()
    with ExitStack() as stack:
        sessions = {
            role: stack.enter_context(tn.Session.from_config(str(path)))
            for role, path in paths.items()
        }
        authority = sessions["catalog"]
        administration = authority.policy("experiment.administration")
        audit_policy = authority.policy("experiment.evidence")
        store = NativeObjects()
        resolvers = {}
        for role, session in sessions.items():
            resolver = DataframeGovernance(
                "http://unused", "accumulation", session=session, authority=authority.did,
                administration=administration, store=store,
            )
            resolver.registry._request = local_catalog.request
            resolvers[role] = resolver
        publisher = resolvers["catalog"]
        restricted_source = sources - 1 if sources > 1 else None
        for source in range(sources):
            destinations = ["review-console"]
            if source != restricted_source:
                destinations.append("analysis-console")
            columns = {column: {
                "kind": kind, "markdown": markdown(column),
                "rule": {"destinations": destinations},
            } for column, kind in (("name", "str"), ("value", "int"))}
            publisher.publish_assignment(
                root / f"assignment-{source}", table=f"source_{source}",
                source_identity=source_identity(database), application=APPLICATION,
                actors=["analyst"], purposes=[PURPOSE], columns=columns,
            )
        contexts = {}
        for role in ("gateway", "worker"):
            rules = AssignedRules(
                resolvers[role], actor="analyst", application=APPLICATION, purpose=PURPOSE,
                writers=[sessions["gateway"].did, sessions["worker"].did],
            )
            contexts[role] = DataframeContext(
                sessions[role], EvidenceRecorder(sessions[role], store, audit_policy), rules,
                application=APPLICATION, purpose=PURPOSE, actor="analyst", resolver=resolvers[role],
            )
        context = contexts["worker"]
        driver = GovernedSQL(
            database, gateway=contexts["gateway"], consumer=context,
            edition_publisher=publisher, directory=root / "editions",
        )
        frame_rows = []
        for source in range(sources):
            frame_rows.extend(driver.execute(
                f"SELECT name, value FROM source_{source} LIMIT ?", (source_rows,),
            ).fetchall())
        original = frame_rows[-1][0]
        original_binding = context._metadata(original)[1]
        claimed_member = (
            f"{original.reference.object_id}::{original_binding['origins'][0]['row']}"
        )
        support_observations = []
        support_facts = Support.facts

        def observe_support(support, materialized, policy_ids=None):
            facts = support_facts(support, materialized, policy_ids)
            members = {}
            for row in support.row_members(materialized):
                for identity, tokens in row.items():
                    members.setdefault(identity, set()).update(tokens)
            members = {identity: sorted(tokens) for identity, tokens in members.items()}
            support_observations.append({
                "policy_ids": sorted(policy_ids or ()), "members": members, "facts": facts,
            })
            return facts

        with context:
            annotated = original.attest(CLAIM, context)
            source_claim = context._metadata(annotated)[2][0]
            frame_rows[-1] = (annotated, frame_rows[-1][1])
            input_metadata = context._metadata_many(tuple(
                value for row in frame_rows for value in row))
            input_revisions = {policy.revision_id for data, _, _ in input_metadata
                               for policy in data.policies}
            with patch.object(Support, "facts", observe_support):
                result = dataframe_calculate(context, frame_rows)
        data, binding, claims = context._metadata(result)
        wire = store.get(result.reference.object_id)
        envelope = json.loads(wire)
        facts = context.frame_runs[-1]
        release_decisions = [entry for entry in facts["opa_decisions"]
                             if entry["request"]["operation"] == "release"]
        members = support_observations[0]["members"]
        assert all(observed["members"] == members for observed in support_observations)
        policy_sources = {}
        source_tables = {}
        for edition in facts["source_editions"]:
            source_tables[edition["source_object_id"]] = edition["dataset"].rsplit(".", 1)[0]
            for revision in edition["contracts"]:
                policy_sources.setdefault(revision, set()).add(edition["source_object_id"])
        for entry in release_decisions:
            revision = entry["request"]["policy_revision"]
            policy_members = {member for source in policy_sources[revision]
                              for member in members[source]}
            assert entry["request"]["aggregate_support"]["group_sizes"] == [len(policy_members)]
        selected_rows = [cell for cell in facts["source_cells"] if cell["column"] == "value"
                         and f"{cell['source_object_id']}::{cell['source_row']}"
                         in members[cell["source_object_id"]]]
        observed_survivors = len(selected_rows)
        assert observed_survivors == survivors
        assert {cell["row"] for cell in selected_rows} == set(range(survivors))
        claimed_row_survived = claimed_member in members[original.reference.object_id]
        restricted_survivors = sum(
            source_tables[cell["source_object_id"]] == f"source_{restricted_source}"
            for cell in selected_rows
        ) if restricted_source is not None else None
        assert len(claims) == 1 and claims[0] == source_claim
        assert claims[0].subjects == (original.reference,)
        assert claims[0].issuer == sessions["worker"].did
        assert binding["parents"] == [value.reference.to_dict()
                                      for row in frame_rows for value in row]
        assert len(data.policies) == 2 * sources
        assert {policy.revision_id for policy in data.policies} == input_revisions

        opened = []
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
        assert disclosures["review-console"]["value"] == survivors * 251
        if restricted_source is not None:
            assert disclosures["analysis-console"] == {"outcome": "refused", "content_opens": 0}

        with context:
            repeated = result + result
        repeated_data, repeated_binding, repeated_claims = context._metadata(repeated)
        revisions = {p.revision_id for p in data.policies}
        assert {p.revision_id for p in repeated_data.policies} == revisions
        assert repeated_claims == claims
        assert repeated_binding["parents"] == [result.reference.to_dict()] * 2
        assert repeated.reveal(context, destination="review-console") == survivors * 502
        store.export(root / "publications")
        for role, ctx in contexts.items():
            verify_tape(
                ctx.recorder.records(), session=authority, policy=audit_policy,
                expected_writer=ctx.session.did, expected_context=ctx.recorder.context_id,
                expected_head=ctx.recorder.head,
            )
            ctx.recorder.export(root / "records" / role)
        summary = {
            "rows": rows, "survivors": observed_survivors, "sources": sources,
            "input_policy_revisions": sorted(input_revisions),
            "policy_revisions": sorted(p.revision_id for p in data.policies),
            "policy_count": len(data.policies), "input_reference_count": len(binding["parents"]),
            "origin_count": len(binding["origins"]), "claim_count": len(claims),
            "claim_id": claims[0].id, "claim_issuer": claims[0].issuer,
            "claim_subjects": [item.to_dict() for item in claims[0].subjects],
            "claimed_row_survived": claimed_row_survived,
            "result_reference": result.reference.to_dict(), "result_id": result.result_id,
            "output_wire_bytes": len(wire),
            "encrypted_governance_bytes": len(
                base64.b64decode(envelope["tn.agents"]["ciphertext"])),
            "encrypted_evidence_bytes": len(base64.b64decode(envelope["evidence"]["ciphertext"])),
            "opa_decision_count": len(facts["opa_decisions"]),
            "aggregate_support": [entry["request"]["aggregate_support"]
                                  for entry in release_decisions],
            "aggregate_membership": members,
            "restricted_source": restricted_source,
            "restricted_source_survivors": restricted_survivors,
            "disclosures": disclosures,
            "repeated_input": {"policy_count": len(repeated_data.policies),
                               "claim_count": len(repeated_claims),
                               "direct_input_count": len(repeated_binding["parents"]),
                               "distinct_input_count": len({
                                   json.dumps(item, sort_keys=True)
                                   for item in repeated_binding["parents"]})},
        }
        (root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        (root / "dataframe.json").write_text(json.dumps(facts, indent=2), encoding="utf-8")
        (root / "support-observations.json").write_text(
            json.dumps(support_observations, indent=2), encoding="utf-8",
        )
        return summary


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
