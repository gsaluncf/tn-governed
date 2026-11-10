"""Verify signed frame governance and previously issued v1 execution records."""

import base64
import hashlib
import json
from datetime import date, datetime, time, timedelta
from decimal import Decimal



class AuditError(ValueError):
    """Execution evidence is inconsistent with its bound inputs or output."""


def _json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _digest(value):
    return "sha256:" + hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _value(value):
    """A type-tagged encoding prevents value/type and user-object collisions."""
    if value is None:
        return ["null"]
    if type(value) is bool:
        return ["bool", value]
    if type(value) is int:
        return ["int", str(value)]
    if type(value) is float:
        return ["float", value.hex()]
    if isinstance(value, Decimal):
        return ["decimal", str(value)]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, bytes):
        return ["bytes", base64.b64encode(value).decode("ascii")]
    if isinstance(value, (datetime, date, time)):
        return [type(value).__name__, value.isoformat()]
    if isinstance(value, timedelta):
        return ["timedelta", value.days, value.seconds, value.microseconds]
    if isinstance(value, (list, tuple)):
        return ["list", [_value(item) for item in value]]
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return ["object", [[key, _value(value[key])] for key in sorted(value)]]
    raise AuditError(f"unsupported audit value type: {type(value).__name__}")


def rows_digest(rows):
    return _digest(_value(rows))


def artifact_facts(artifacts):
    if isinstance(artifacts, dict) and artifacts.get("kind") == "endpoint-evaluator":
        names = (
            "kind",
            "policy_revision",
            "policy_ref",
            "authority",
            "identifier",
            "version",
            "configuration_digest",
        )
        return {name: artifacts[name] for name in names}
    names = (
        "policy_revision",
        "compiled_policy_sha256",
        "profile_sha256",
        "wasm_sha256",
        "data_sha256",
    )
    return {
        name: artifacts[name] if isinstance(artifacts, dict) else getattr(artifacts, name)
        for name in names
    }


def _valid_members(source, members):
    """Accept sorted unique tokens, or the single canonical range form of a long list."""
    if isinstance(members, list):
        return members == sorted(set(members)) and all(
            item.startswith(source + "::") for item in members
        )
    ranges = members["ranges"]
    return (
        set(members) == {"ranges"}
        and all(len(pair) == 2 and all(type(item) is int for item in pair) for pair in ranges)
        and all(0 <= first <= last for first, last in ranges)
        and all(left[1] + 1 < right[0] for left, right in zip(ranges, ranges[1:], strict=False))
        and sum(last - first + 1 for first, last in ranges) >= 64
    )


def _require(condition, message):
    if not condition:
        raise AuditError(message)


def verify_audit(
    record, *, rows=None, expected_sources=None, expected_artifacts=None, evaluator_for=None
):
    """Check an authenticated record; optional evaluators replay policy decisions.

    The caller authenticates the enclosing publication/Result and supplies its
    source set. Artifact expectations must come from accepted signed editions.
    Recorded observations do not replace execution or trust in their signer.
    """
    try:
        _verify_audit(
            record,
            rows=rows,
            expected_sources=expected_sources,
            expected_artifacts=expected_artifacts,
            evaluator_for=evaluator_for,
        )
    except (KeyError, TypeError, AttributeError) as exc:
        raise AuditError("malformed dataframe audit") from exc
    return record


def _verify_audit(record, *, rows, expected_sources, expected_artifacts, evaluator_for):
    _require(record["schema"] == "tn.polars-audit.v1", "unsupported dataframe audit schema")
    _require(
        record["id"] == _digest({key: value for key, value in record.items() if key != "id"}),
        "dataframe audit digest differs",
    )
    inputs = record["inputs"]
    _require(inputs == sorted(set(inputs)) and bool(inputs), "audit source set is invalid")
    if expected_sources is not None:
        _require(
            inputs == sorted(set(expected_sources)), "audit source set differs from signed inputs"
        )
    if rows is not None:
        _require(
            record["output"]["rows_digest"] == rows_digest(rows)
            and record["output"]["row_count"] == len(rows),
            "audit output differs from released rows",
        )
        _require(
            all(set(row) == set(record["output"]["schema"]) for row in rows),
            "audit output schema differs from released rows",
        )
    events, parents, ancestors = {}, set(), {}
    for event in record["events"]:
        identity = event["id"]
        _require(
            identity == _digest({key: value for key, value in event.items() if key != "id"}),
            "audit event digest differs",
        )
        _require(
            identity not in events and set(event["parents"]) <= set(events),
            "audit event ancestry is missing, duplicated, or out of order",
        )
        events[identity] = event
        parents.update(event["parents"])
        ancestors[identity] = set(event["parents"]).union(
            *(ancestors[parent] for parent in event["parents"])
        )
    _require(record["heads"] == sorted(set(events) - parents), "audit heads omit execution events")
    _require(len(record["heads"]) == 1, "audit requires one terminal release")
    terminal = events[record["heads"][0]]
    _require(
        terminal["kind"] == "operation" and terminal["details"]["name"] == "release",
        "audit requires a terminal release operation",
    )
    release = terminal["details"]
    _require(
        release["parameters"]["output_digest"] == _digest(record["output"])
        and release["parameters"]["support_digest"] == _digest(record["support"]),
        "audit release differs from final output or support",
    )
    bindings = [event["details"] for event in events.values() if event["kind"] == "source"]
    _require(
        bindings == record["source_bindings"] and bool(bindings), "audit source bindings differ"
    )
    source_ids = {binding["source_id"] for binding in bindings}
    policies = {item["policy_revision"]: item for item in record["policies"]}
    _require(
        len(policies) == len(record["policies"]) and bool(policies), "audit policy set is invalid"
    )
    for revision, policy in policies.items():
        _require(
            set(policy["source_ids"])
            == {
                binding["source_id"]
                for binding in bindings
                if revision in binding["policy_revisions"]
            },
            "audit policy source binding differs",
        )
    _require(
        set(policies)
        == {revision for binding in bindings for revision in binding["policy_revisions"]},
        "audit source policies are incomplete",
    )
    if expected_artifacts is not None:
        _require(
            {revision: artifact_facts(item) for revision, item in policies.items()}
            == {revision: artifact_facts(item) for revision, item in expected_artifacts.items()},
            "audit evaluator artifacts differ from signed editions",
        )
    released = set()
    for event in events.values():
        details = event["details"]
        if event["kind"] == "policy-decision":
            request = details["request"]
            revision = request["policy_revision"]
            _require(
                revision in policies and details["allow"] is True,
                "audit includes an unknown or refused policy decision",
            )
            if request["operation"] == "release":
                released.add(revision)
            if evaluator_for is not None:
                decision = evaluator_for(revision).decide(request)
                _require(
                    decision.allow is True
                    and decision.decision_id == details["decision_id"]
                    and decision.reason == details["reason"],
                    "audit policy replay differs",
                )
        elif event["kind"] == "operation":
            ancestry = ancestors[event["id"]]
            _require(
                set(details["authorization"]) <= ancestry,
                "audit operation authorization is not in its ancestry",
            )
            decisions = [events[identity] for identity in details["authorization"]]
            _require(
                bool(decisions)
                and event["parents"] == [decisions[-1]["id"]]
                and all(
                    current["parents"] == [previous["id"]]
                    for previous, current in zip(decisions, decisions[1:], strict=False)
                ),
                "audit operation does not follow its authorization",
            )
            _require(
                all(
                    item["kind"] == "policy-decision"
                    and item["details"]["request"]["operation"] == details["name"]
                    for item in decisions
                ),
                "audit operation authorization differs",
            )
            _require(
                sorted(item["details"]["request"]["policy_revision"] for item in decisions)
                == details["policy_revisions"],
                "audit operation lacks contributing policy decisions",
            )
            required = {
                revision
                for identity in ancestry
                if events[identity]["kind"] == "source"
                for revision in events[identity]["details"]["policy_revisions"]
            }
            _require(
                set(details["policy_revisions"]) == required,
                "audit operation omits contributing policies",
            )
            if details["name"] == "join":
                for side in ("left", "right"):
                    branch = details["parameters"][side]
                    _require(
                        bool(branch) and set(branch) <= ancestry,
                        "audit join input branch is missing",
                    )
        else:
            _require(event["kind"] == "source", "unknown audit event kind")
    _require(released == set(policies), "audit lacks release decisions for contributing policies")
    for identity in release["authorization"]:
        request = events[identity]["details"]["request"]
        revision = request["policy_revision"]
        sources = set(policies[revision]["source_ids"])

        def local(roots, sources=sources):
            return sorted(
                {
                    column
                    for root in roots
                    for source, _, column in [root.partition("::")]
                    if source in sources
                }
            )

        expected_columns = [
            {"name": name, "sources": local(roots)}
            for name, roots in record["output"]["columns"].items()
        ]
        observed_columns = [
            {"name": item["name"], "sources": item["sources"]} for item in request["columns"]
        ]
        _require(
            sorted(observed_columns, key=lambda item: item["name"])
            == sorted(expected_columns, key=lambda item: item["name"])
            and request["row_selection_sources"]
            == local(record["output"]["row_selection_sources"]),
            "audit release lineage differs from final output",
        )
        _require(
            request["aggregate_support"] == record["support"]["policy_facts"][revision]
            and request["aggregate_support"]["output_rows"] == record["output"]["row_count"],
            "audit release support differs from final output",
        )
        _require(
            request["use"] == release["parameters"]["use"]
            and request["audience"] == release["parameters"]["audience"],
            "audit release use differs from its authorization",
        )
    for roots in [*record["output"]["columns"].values(), record["output"]["row_selection_sources"]]:
        _require(
            all(root.partition("::")[0] in source_ids for root in roots),
            "audit output depends on an unbound source",
        )
    support = record["support"]
    _require(
        type(support["known"]) is bool
        and type(support["shape_known"]) is bool
        and type(support["aggregated"]) is bool,
        "audit support precision is invalid",
    )
    _require(
        support["policy_sources"]
        == {revision: item["source_ids"] for revision, item in policies.items()},
        "audit support policies differ",
    )
    _require(
        set(support["policy_facts"]) == set(policies), "audit aggregate support policies differ"
    )
    for facts in support["policy_facts"].values():
        _require(
            facts["known"]
            is (support["known"] or (not support["aggregated"] and support["shape_known"]))
            and facts["aggregated"] is support["aggregated"]
            and facts["output_rows"] == record["output"]["row_count"],
            "audit aggregate support precision differs",
        )
        _require(
            isinstance(facts["group_sizes"], list)
            and all(type(size) is int and size >= 0 for size in facts["group_sizes"]),
            "audit aggregate group sizes are invalid",
        )
    if support["known"]:
        _require(
            isinstance(support["rows"], list)
            and len(support["rows"]) == record["output"]["row_count"],
            "audit row support is incomplete",
        )
        for members in support["rows"]:
            _require(set(members) <= source_ids, "audit row support has an unbound source")
            for source, contributors in members.items():
                _require(
                    _valid_members(source, contributors), "audit row contributor identity differs"
                )
    else:
        _require(support["rows"] is None, "unknown support must not claim precise contributors")


def open_audited_frame(
    publication,
    *,
    session,
    use,
    decide,
    group="finance",
    rows_field="rows",
    expected_artifacts=None,
    evaluator_for=None,
    verify_claim=None,
):
    """Authenticate and open the rows and audit from one native TN publication."""
    view = session.governance(publication)
    data = session.receive(publication, use=use, groups=[group], decide=decide)
    return verify_native_frame(
        data,
        governance=view.governance,
        group=group,
        rows_field=rows_field,
        expected_artifacts=expected_artifacts,
        evaluator_for=evaluator_for,
        verify_claim=verify_claim,
    )


def verify_frame_metadata(data, group, verify_record=None):
    """Authenticate a v2 frame's policy selection and its portable signed evidence."""
    from .authority import policy_identity

    descriptor = data.get("tn_polars_governance", group=group)
    _require(isinstance(descriptor, dict)
             and set(descriptor) == {"schema", "group", "rows_field", "policies", "claims", "actions"}
             and descriptor["schema"] == "tn.polars-governance.v2"
             and all(isinstance(descriptor[key], str) and descriptor[key] for key in ("group", "rows_field"))
             and descriptor["policies"] == sorted(policy_identity(policy) for policy in data.policies),
             "frame descriptor differs from native governance")
    for key in ("claims", "actions"):
        ids = descriptor[key]
        _require(isinstance(ids, list) and all(isinstance(item, str) and item for item in ids)
                 and len(ids) == len(set(ids)), "frame has invalid evidence identities")
    carried = data.get("tn_polars_claims", group=group)
    _require(isinstance(carried, list) and all(isinstance(item, dict) for item in carried)
             and [item.get("id") for item in carried] == descriptor["claims"],
             "frame claims differ from the policy descriptor")
    if carried or descriptor["actions"]:
        _require(callable(verify_record), "frame evidence requires an authority for signed records")
    for item in carried:
        record = verify_record(item["id"])
        _require(record.id == item["id"] and record.writer == item.get("writer")
                 and record.body == item.get("body") and record.body.get("kind") == "Claim",
                 "frame claim differs from its signed record")
    for identity in descriptor["actions"]:
        record = verify_record(identity)
        details = record.body["details"]
        required, discharged = details.get("obligations"), details.get("discharged")
        _require(record.id == identity and record.body.get("kind") == "Decision"
                 and details.get("permitted") is True and isinstance(required, list) and bool(required)
                 and isinstance(discharged, list) and all(isinstance(step, dict)
                     and step.get("satisfied") is True and isinstance(step.get("evidence"), str)
                     and step["evidence"].strip() for step in discharged)
                 and [step.get("obligation") for step in discharged] == required,
                 "invalid signed required-action decision")
    return descriptor


def verify_native_frame(
    data,
    *,
    governance,
    group,
    rows_field,
    expected_artifacts=None,
    evaluator_for=None,
    verify_claim=None,
):
    """Validate an already authorized native opening against its signed audit."""
    from .authority import policy_identity

    try:
        descriptor = data.get("tn_polars_governance", group=group)
    except KeyError:
        descriptor = None
    if descriptor is not None:
        _require(expected_artifacts is None and evaluator_for is None,
                 "historical evaluator replay requires a v1 audit")
        descriptor = verify_frame_metadata(data, group, verify_claim)
        _require(descriptor["group"] == group and descriptor["rows_field"] == rows_field
                 and isinstance(data.get(rows_field, group=group), list),
                 "frame descriptor differs from its signed business field")
        return descriptor

    record = verify_audit(
        data.get("tn_polars_audit", group=group),
        rows=data.get(rows_field, group=group),
        expected_sources=[source.object_id for source in governance.sources],
        expected_artifacts=expected_artifacts,
        evaluator_for=evaluator_for,
    )
    _require(
        {item["policy_revision"] for item in record["policies"]}
        == {policy_identity(policy) for policy in data.policies},
        "audit policies differ from native contracts",
    )
    _require(
        {
            (
                item.get("binding_source_id", item["source_id"]),
                item["dataset"],
                item["edition"],
                item["edition_record_id"],
            )
            for item in record["source_bindings"]
            if item["dataset"] is not None
        }
        == {
            (item.source_object_id, item.dataset, item.edition, item.edition_record_id)
            for item in data.dataset_bindings
        },
        "audit source editions differ from native bindings",
    )
    try:
        carried_claims = data.get("tn_polars_claims", group=group)
    except KeyError:
        carried_claims = []
    _require(
        carried_claims == record.get("claims", []), "audit claim records differ from publication"
    )
    if carried_claims:
        _require(callable(verify_claim), "attributed claims require a record verifier")
        for item in carried_claims:
            claim = verify_claim(item["id"])
            _require(
                claim.id == item["id"]
                and claim.writer == item["writer"]
                and claim.body == item["body"]
                and claim.body["kind"] == "Claim",
                "audit claim differs from its original signed record",
            )
    context = governance.get("release_context")
    release = next(
        event["details"]["parameters"]
        for event in record["events"]
        if event["id"] == record["heads"][0]
    )
    _require(
        isinstance(context, dict)
        and context.get("destination") == release["audience"]
        and all(context.get(key) == value for key, value in release["use"].items()),
        "audit release context differs from the signed publication",
    )
    return record
