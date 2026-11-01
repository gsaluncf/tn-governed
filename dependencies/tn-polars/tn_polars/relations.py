"""Native relation admission under independently configured endpoint authorities."""

from copy import deepcopy

import polars as pl
import tn

from .audit import rows_digest, verify_native_frame
from .authority import local_policy_set
from .release import PolicyDenied
from .support import Support
from .tn_boundary import TnBoundary, _check_use, root_name


def _get(data, field, group):
    try:
        return data.get(field, group=group)
    except (KeyError, ValueError):
        return None


def _claims(data, groups, verify_claim):
    identifiers = set()
    for group in groups:
        carried = _get(data, "tn_polars_claims", group)
        if isinstance(carried, list):
            identifiers.update(item["id"] if isinstance(item, dict) else item for item in carried)
        manifest = _get(data, "manifest", group)
        if isinstance(manifest, dict):
            identifiers.update(manifest.get("claims", []))
    if identifiers and not callable(verify_claim):
        raise PolicyDenied("attributed source claims require a configured record verifier")
    result = []
    for identity in sorted(identifiers):
        record = verify_claim(identity)
        if (
            record.id != identity
            or not isinstance(record.writer, str)
            or record.body.get("kind") != "Claim"
        ):
            raise PolicyDenied("source claim reference is not a verified Claim record")
        result.append({"id": record.id, "writer": record.writer, "body": deepcopy(record.body)})
    return tuple(result)


def _frame(
    data,
    rows,
    *,
    use,
    evaluators,
    source_id,
    group,
    rows_field,
    claims=(),
    schema=None,
    upstream=None,
):
    from .frame import GovernedLazyFrame

    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise TypeError("native relation requires a list of row objects")
    frame = pl.DataFrame(rows, schema=schema).lazy()
    if rows_digest(frame.collect().to_dicts()) != rows_digest(rows):
        raise ValueError("relation conversion changes values or types; provide a lossless schema")
    columns = frame.collect_schema().names()
    policies = local_policy_set(
        data.policies,
        evaluators,
        source_id=source_id,
        columns=columns,
        bindings=data.dataset_bindings,
    )
    policies.claims = claims
    sources = {name: {root_name(source_id, name)} for name in columns}
    policies.decide("load", use.application, sources, set(), use)
    parameters = {"group": group, "rows_field": rows_field}
    if upstream is not None:
        parameters["upstream"] = deepcopy(upstream)
    policies.record_operation("load", parameters)
    first = next(iter(policies._entries.values()))
    support = Support.source(frame, source_id, policies.revision_ids)
    if upstream is not None:
        support = support.unknown(frame)
    return GovernedLazyFrame(
        frame,
        first.policy,
        {},
        first.evaluator,
        sources=sources,
        tn_boundary=TnBoundary(data.copy(), policies, use, group, rows_field, "tn.polars.frame"),
        _support=support,
    )


def load_relation(
    publication,
    *,
    session,
    use,
    evaluators,
    decide,
    group="finance",
    rows_field="rows",
    schema=None,
    verify_claim=None,
):
    """Authorize native row objects with local evaluators rather than catalog OPA.

    A callback identity is an endpoint choice; it does not assert approval by the
    source catalog. Native contract signatures remain authoritative identities.
    The receive callback runs before business decryption; output-aware policy
    checks run again after the typed relation is constructed and before use.
    """
    _check_use(use)
    obj = (
        publication
        if isinstance(publication, tn.GovernedObject)
        else tn.GovernedObject.parse(publication)
    )
    view = session.governance(obj)
    policies = local_policy_set(
        view.governance.policies, evaluators, source_id=obj.id, columns=list(schema or ())
    )
    metadata = None
    if "evidence" in obj.envelope and group != "evidence":
        metadata = session.receive(obj, use=use, groups=["evidence"], decide=decide)
        policies.claims = _claims(metadata, ["evidence"], verify_claim)

    def admit(context):
        policies.validate_contracts(context)
        policies.decide("load", use.application, {}, set(), use)
        return decide(context)

    data = session.receive(obj, use=use, groups=[group], decide=admit)
    claims = {item["id"]: item for item in policies.claims}
    claims.update({item["id"]: item for item in _claims(data, [group], verify_claim)})
    rows = deepcopy(data.get(rows_field, group=group))
    upstream = None
    if _get(data, "tn_polars_audit", group) is not None:
        prior = verify_native_frame(
            data,
            governance=view.governance,
            group=group,
            rows_field=rows_field,
            verify_claim=verify_claim,
        )
        upstream = {
            "kind": "tn.polars-audit.v1",
            "audit_id": prior["id"],
            "support": deepcopy(prior["support"]),
        }
    elif metadata is not None:
        manifest = _get(metadata, "manifest", "evidence")
        if isinstance(manifest, dict):
            upstream = {"kind": "native-manifest", "manifest": deepcopy(manifest)}
    return _frame(
        data,
        rows,
        use=use,
        evaluators=evaluators,
        source_id=obj.id,
        group=group,
        rows_field=rows_field,
        claims=tuple(claims.values()),
        schema=schema,
        upstream=upstream,
    )


def from_admitted_query(admitted, *, use, evaluators, names=None, verify_claim=None):
    """Continue from an authorized SQL processing admission without plain reveal.

    Output names are positional. Duplicate SQL aliases require an explicit unique
    mapping. Query lineage remains in the signed load observation for recipients.
    """
    _check_use(use)
    from tn_governed.values.query_result import AdmittedQuery

    if not isinstance(admitted, AdmittedQuery):
        raise TypeError("SQL transfer requires an AdmittedQuery")
    schema = admitted.manifest["binding"]["output_schema"]
    names = tuple(column["name"] for column in schema) if names is None else tuple(names)
    if (
        len(names) != len(schema)
        or len(set(names)) != len(names)
        or any(not isinstance(name, str) or not name for name in names)
    ):
        raise ValueError("SQL columns require unique positional dataframe names")
    rows = [dict(zip(names, row, strict=True)) for row in admitted.rows]
    claims = _claims(admitted.data, ["evidence"], verify_claim)
    return _frame(
        admitted.data,
        rows,
        use=use,
        evaluators=evaluators,
        source_id=admitted.reference.object_id,
        group="values",
        rows_field="rows",
        claims=claims,
        schema={name: pl.Null for name in names} if not rows else None,
        upstream=admitted.manifest["lineage"],
    )
