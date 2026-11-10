"""Polars and OPA orchestration around Rust-owned TN working objects.

Revision resolution and artifact verification belong to the dataset resolver.
This boundary never reconstructs governance or creates an accepted selection.
"""

from copy import deepcopy
from dataclasses import dataclass, replace
import hashlib
import json
from types import MappingProxyType

import polars as pl

from .admission import SchemaPinViolation, _pin_dtypes, _pin_message
from .policy import CompiledPolicy
from .release import PolicyDenied


def _check_use(use):
    from tn.governed import UseContext
    if not isinstance(use, UseContext):
        raise TypeError("the TN boundary requires a native UseContext for use")


def root_name(source_id, column):
    return f"{source_id}::{column}"


def _refusal(message):
    return PolicyDenied(message + ". Data governance must review the edition's evaluator artifacts; "
                        "platform ops must correct routing or the requested operation.")


@dataclass(frozen=True)
class _PolicyEntry:
    policy: CompiledPolicy
    evaluator: object
    artifacts: object
    source_ids: frozenset
    dtypes: dict | None


def _merged_entry(current, entry):
    """Check two evaluators for one signed revision and keep the first with both field sets."""
    if current.artifacts != entry.artifacts:
        raise _refusal("Conflicting evaluator artifacts for the same signed revision")
    policy = current.policy
    if current.policy.to_dict() != entry.policy.to_dict():
        local = (isinstance(current.artifacts, dict)
                 and current.artifacts.get("kind") == "endpoint-evaluator")
        if (not local or current.policy.release != entry.policy.release
                or any(current.policy.fields[name] != entry.policy.fields[name]
                       for name in current.policy.fields.keys() & entry.policy.fields.keys())):
            raise _refusal("Conflicting evaluator profiles for the same signed revision")
        policy = CompiledPolicy(current.policy.schema, current.policy.policy_ref,
            current.policy.fields | entry.policy.fields, current.policy.release)
    return replace(current, policy=policy)


class PolicySet:
    """All contributing evaluators, keyed by exact native policy revision."""

    def __init__(self, entries):
        self._entries = MappingProxyType(dict(entries))
        self.actions = ()
        self.claims = ()

    @classmethod
    def for_selection(cls, entries, selection, *, module_cache=None):
        from tn.governed import DatasetSelection, EvaluatorArtifactSet
        if not isinstance(selection, DatasetSelection):
            raise TypeError("TN frame loading requires an accepted native DatasetSelection")
        required = {binding.revision_id for binding in selection.record.contracts}
        expected = {item.policy_revision: item for item in selection.record.evaluator_artifacts}
        if set(expected) != required or set(entries) != required:
            raise _refusal("Every selected contract needs exactly one verified evaluator")
        accepted = {}
        for revision, entry in entries.items():
            artifacts = getattr(entry, "verified_artifacts", None)
            if (getattr(entry, "revision_id", None) != revision
                    or not isinstance(artifacts, EvaluatorArtifactSet)
                    or artifacts != expected[revision]):
                raise _refusal("Evaluator digests do not match the selected signed edition")
            # The resolver's factory rechecks parsed policy/profile consistency
            # and loads precisely the artifact bytes it has verified.
            compiled_bytes = entry.compiled_policy_bytes
            profile_bytes = entry.profile_bytes
            if (hashlib.sha256(compiled_bytes).hexdigest() != artifacts.compiled_policy_sha256
                    or hashlib.sha256(profile_bytes).hexdigest() != artifacts.profile_sha256):
                raise _refusal("Compiled policy or profile bytes differ from the approved edition")
            policy = CompiledPolicy.from_dict(json.loads(compiled_bytes))
            profile = json.loads(profile_bytes)
            evaluator = (entry.evaluator() if module_cache is None
                         else entry.evaluator(module_cache=module_cache))
            accepted[revision] = _PolicyEntry(policy, evaluator, artifacts,
                frozenset({selection.source_object_id}), deepcopy(profile.get("dtypes")))
        return cls(accepted)

    @property
    def revision_ids(self):
        return tuple(sorted(self._entries))

    def copy(self):
        result = PolicySet(self._entries)
        result.actions = self.actions
        result.claims = self.claims
        return result

    def include(self, other):
        return self.include_all((other,))

    def include_all(self, others):
        """Merge several policy sets with one pass over their entries, events and claims."""
        others = tuple(others)
        merged, sources = dict(self._entries), {}
        for other in others:
            for revision, entry in other._entries.items():
                if revision in merged:
                    sources.setdefault(revision, set(merged[revision].source_ids)).update(entry.source_ids)
                    entry = _merged_entry(merged[revision], entry)
                merged[revision] = entry
        for revision, members in sources.items():
            merged[revision] = replace(merged[revision], source_ids=frozenset(members))
        result = PolicySet(merged)
        result.actions = tuple(dict.fromkeys(action for item in (self, *others) for action in item.actions))
        claims = {item["id"]: item for item in self.claims}
        for item in (item for other in others for item in other.claims):
            if item["id"] in claims and claims[item["id"]] != item:
                raise _refusal("Claim identity has conflicting attributed records")
            claims[item["id"]] = item
        result.claims = tuple(claims[key] for key in sorted(claims))
        return result

    def validate_contracts(self, context):
        from .authority import policy_identity
        actual = {policy_identity(policy): policy for policy in context.policies}
        if set(actual) != set(self._entries):
            raise _refusal("The source's complete contract set differs from its evaluators")
        for revision, entry in self._entries.items():
            if actual[revision].policy_ref != entry.policy.policy_ref:
                raise _refusal("Compiled evaluator and native accepted policy reference differ")

    def pin(self, frame):
        schema = frame.collect_schema()
        arrived = set(schema.names())
        for entry in self._entries.values():
            declared = set(entry.policy.fields)
            if arrived != declared:
                raise SchemaPinViolation(_pin_message(sorted(arrived - declared), sorted(declared - arrived)))
            if entry.dtypes:
                _pin_dtypes(schema, entry.dtypes)

    @staticmethod
    def _local_roots(entry, roots):
        return {column for root in roots for source, separator, column in [root.partition("::")]
                if separator and source in entry.source_ids}

    @staticmethod
    def _level(entry, roots):
        levels = {entry.policy.level(name) for name in roots}
        if levels - {"public", "internal"}:
            return "confidential"
        return "internal" if "internal" in levels else "public"

    def classification(self, roots):
        levels = [self._level(entry, self._local_roots(entry, roots))
                  for entry in self._entries.values()]
        return "confidential" if "confidential" in levels else "internal" if "internal" in levels else "public"

    def decide(self, operation, audience, sources, row_sources, use, *, aggregate_support=None, parameters=None):
        decisions = []
        for revision, entry in self._entries.items():
            columns = []
            for name, roots in sources.items():
                local = self._local_roots(entry, roots)
                columns.append({"name": name, "sources": sorted(local),
                                "classification": self._level(entry, local)})
            request = {
                "policy_ref": entry.policy.policy_ref, "policy_revision": revision,
                "operation": operation, "audience": audience, "columns": columns,
                "row_selection_sources": sorted(self._local_roots(entry, row_sources)),
                "aggregate_support": aggregate_support or {"known": False},
                "use": {"application": use.application, "purpose": use.purpose,
                        "operation": use.operation},
            }
            if parameters is not None:
                request["parameters"] = deepcopy(parameters)
            if self.actions:
                request["actions"] = list(self.actions)
            if self.claims:
                request["claims"] = deepcopy(list(self.claims))
            decision = entry.evaluator.decide(request)
            if type(decision.allow) is not bool or not decision.allow:
                raise _refusal(f"Contract {revision} refused {operation}: {decision.reason}")
            decisions.append(decision)
        return decisions


class TnBoundary:
    """Admitted governance for a working frame. Polars owns the business rows."""

    def __init__(self, data, policies, use, group, rows_field, output_type=None, *,
                 metadata_group=None, inputs=()):
        self.use, self.group, self.rows_field = use, group, rows_field
        self.output_type = output_type or data.object_type
        self.metadata_group = metadata_group
        self.policies = policies.copy()
        self.data = data.policy_output(self.output_type, {group: {}}, inputs=inputs)

    def include(self, other):
        if self.use != other.use:
            raise _refusal("Joined TN inputs require the same admitted application use")
        return TnBoundary(self.data, self.policies.include(other.policies), self.use,
                          self.group, self.rows_field, self.output_type,
                          metadata_group=self.metadata_group or other.metadata_group, inputs=(other.data,))


def load_from_tn(wire, *, session, use, selection, policies, decide, group="finance",
                 rows_field="rows", verify_claim=None):
    import tn
    from .frame import GovernedLazyFrame
    from .relations import _admit_metadata, _claims, _get
    _check_use(use)
    policy_set = PolicySet.for_selection(policies, selection)
    obj = wire if isinstance(wire, tn.GovernedObject) else tn.GovernedObject.parse(wire)
    descriptor = _admit_metadata(session, obj, group, use, decide, policy_set, verify_claim)
    # Schema is known from verified evaluator profiles before any business open.
    declared = set().union(*(set(entry.policy.fields) for entry in policy_set._entries.values()))
    sources = {name: {root_name(selection.source_object_id, name)} for name in declared}

    def accept(context):
        policy_set.validate_contracts(context)
        policy_set.decide("load", use.application, sources, set(), use)
        return decide(context)

    data = session.receive(wire, use=use, groups=[group], selection=selection, decide=accept)
    if descriptor is not None and _get(data, "tn_polars_governance", group) != descriptor:
        raise _refusal("Frame metadata differs from the signed business field")
    carried_claims = _claims(data, [group], verify_claim)
    if carried_claims:
        combined = {item["id"]: item for item in policy_set.claims}
        combined.update({item["id"]: item for item in carried_claims})
        policy_set.claims = tuple(combined.values())
        policy_set.decide("load", use.application, sources, set(), use)
    # Native mutable containers are projected only after receive succeeded.
    rows = deepcopy(data.get(rows_field, group=group))
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise _refusal(f"The admitted {group}.{rows_field} field must contain row objects")
    frame = pl.DataFrame(rows).lazy()
    policy_set.pin(frame)
    first = next(iter(policy_set._entries.values()))
    return GovernedLazyFrame(frame, first.policy, {}, first.evaluator, sources=sources,
        tn_boundary=TnBoundary(data, policy_set, use, group, rows_field,
                               metadata_group=obj.manifest_group or ("evidence" if "evidence" in obj.envelope else None)),
        ordinary_rows=(_get(data, "tn_polars_governance", group) is None
                       and _get(data, "tn_polars_audit", group) is None))


def release_tn(frame, *, use, to, decide, object_type=None, group=None, rows_field=None,
               metadata_group=None):
    _check_use(use)
    boundary = frame._tn
    if boundary is None:
        raise _refusal("A TN release requires a frame loaded through native TN admission")
    group = group or boundary.group
    rows_field = rows_field or boundary.rows_field
    if rows_field in {"tn_polars_governance", "tn_polars_audit", "tn_polars_lineage", "tn_polars_claims"}:
        raise _refusal("The output rows field is reserved for governance metadata")
    materialized, support = frame._materialize()
    policies = boundary.policies
    policies.decide("release", to, frame.sources, frame.row_sources, use,
                    aggregate_support=support)
    metadata = {"schema": "tn.polars-governance.v2", "group": group, "rows_field": rows_field,
                "policies": list(policies.revision_ids), "claims": [claim["id"] for claim in policies.claims],
                "actions": list(policies.actions)}
    if metadata_group is None:
        metadata_group = boundary.metadata_group or group
        if (policies.claims or policies.actions) and metadata_group == group:
            metadata_group = "evidence"
    if (policies.claims or policies.actions) and metadata_group == group:
        raise _refusal("Claims and action receipts require a separate metadata group")
    groups = {group: {rows_field: materialized.to_dicts(), "tn_polars_governance": metadata,
                      "tn_polars_claims": list(policies.claims)}}
    if metadata_group != group:
        groups[metadata_group] = {"tn_polars_governance": metadata, "tn_polars_claims": list(policies.claims)}
    output_type = object_type or boundary.output_type or boundary.data.object_type
    data = boundary.data.policy_output(output_type, groups)
    data.bind_manifest(metadata_group)
    return data.release(use=use, to=to, decide=decide, object_type=output_type)
