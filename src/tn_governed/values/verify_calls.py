"""Checks on each protected call's signed records: one Decision, its permit, and its completion."""

from collections import defaultdict
from dataclasses import dataclass

from .evidence import require

_TERMINAL = ("Result", "Refusal", "Disclosure", "Observation", "Failure", "ModelResult")
_COMPLETION = {"reveal": "Disclosure", "compare": "Observation", "truth": "Observation",
               "is_integer": "Observation", "model_handoff": "ModelResult"}
_CALL_FIELDS = ("inputs", "operation", "application", "purpose", "destination")
_MONITOR_FIELDS = ("context_id", "application", "purpose", "operation", "inputs", "destination")


@dataclass(frozen=True)
class AssignmentTerms:
    """What the signed source assignment grants: its authority, rules, and selected contracts."""

    authority: str
    rules: dict
    policies: dict


@dataclass(frozen=True)
class CheckedCalls:
    refusals: list
    sql_reads: dict


def check_calls(records, by_id, terms):
    """Check every protected call; return its refusals and each call's SQL reads."""
    refusals, sql_reads_by_call = [], {}
    for call_key, call in _calls(records).items():
        decision = _decision(call)
        terminal = [r.body["kind"] for r in call if r.body["kind"] in _TERMINAL]
        sql_reads = [r for r in call if r.body["kind"] == "SQLRead"]
        sql_reads_by_call[call_key] = sql_reads
        empty_select = (decision.body["operation"] == "select" and len(sql_reads) == 1
                        and sql_reads[0].body["details"]["row_count"] == 0)
        require(terminal or empty_select, "protected call lacks terminal evidence")
        if decision.body["details"].get("permitted") is not True:
            refusals.append(_refusal(decision, call, terminal))
            continue
        require("Refusal" not in terminal, "permitted call was reported as refused")
        _check_discharged(decision, _permitted_obligations(decision, terms), by_id)
        _check_completion(decision, terminal)
    return CheckedCalls(refusals, sql_reads_by_call)


def _calls(records):
    calls = defaultdict(list)
    for record in records:
        if record.body["kind"] != "Monitor":
            calls[record.body["context_id"], record.body["call_id"]].append(record)
    return calls


def _decision(call):
    """The call's one Decision; every other record keeps its identity and cites it."""
    decisions = [r for r in call if r.body["kind"] == "Decision"]
    require(len(decisions) == 1, "protected call must have exactly one Decision")
    decision = decisions[0]
    db = decision.body
    for record in call:
        body = record.body
        require(record.writer == decision.writer and all(body[k] == db[k] for k in _CALL_FIELDS),
                "call evidence changed identity, input, or requested use")
        if body["kind"] != "Decision":
            require(body["sequence"] > db["sequence"], "operation evidence precedes Decision")
            if body["kind"] != "Claim":
                require(body["details"].get("decision_id") == decision.id, "completion cites another Decision")
    return decision


def _refusal(decision, call, terminal):
    require(terminal == ["Refusal"] and all(r.body["kind"] in ("Decision", "Refusal") for r in call),
            "refused call has protected-stage evidence")
    db = decision.body
    return {"decision_id": decision.id, "operation": db["operation"], "purpose": db["purpose"],
            "destination": db["destination"], "following_record_kinds": terminal}


def _permitted_obligations(decision, terms):
    """Check the permit against the signed assignment; return the obligations its rules require."""
    db, dd = decision.body, decision.body["details"]
    require(dd.get("policies"), "permit lacks source policies")
    obligations = set()
    for item in dd["policies"]:
        rule = terms.rules.get(item["revision"])
        require(rule is not None and item["authority"] == terms.authority
                and item["policy"] == terms.policies[item["revision"]].policy_ref, "permit cites unknown governance")
        require(dd["actor"] in rule["actors"] and db["application"] == rule["application"]
                and db["purpose"] in rule["purposes"] and db["operation"] in rule["operations"],
                "permit is outside the signed source assignment")
        if db["operation"] == "reveal":
            require(db["destination"] in rule["destinations"], "disclosure destination was not permitted")
        if db["operation"] == "model_handoff":
            grant = rule.get("model", {})
            require(db["destination"] in grant.get("destinations", []) and grant.get("required_disclosure"),
                    "model handoff lacks a disclosure-conditioned destination grant")
        obligations.update(rule["obligations"])
    return obligations


def _check_discharged(decision, obligations, by_id):
    """Every required obligation is discharged by monitoring that preceded this permit."""
    db, dd = decision.body, decision.body["details"]
    require(set(dd["obligations"]) == obligations, "required source obligation omitted")
    require({d["obligation"] for d in dd["discharged"]} == obligations, "obligation was not discharged")
    for discharge in dd["discharged"]:
        monitor = by_id.get(discharge["evidence"])
        require(discharge["satisfied"] is True and monitor is not None, "missing obligation evidence")
        mb = monitor.body
        require(monitor.writer == decision.writer and mb["kind"] == "Monitor"
                and mb["sequence"] < db["sequence"] and all(mb[k] == db[k] for k in _MONITOR_FIELDS)
                and mb["details"]["actor"] == dd["actor"], "monitoring did not precede this permit")


def _check_completion(decision, terminal):
    if "Failure" in terminal:
        require(terminal.count("Failure") == 1 and terminal[-1] == "Failure",
                "successful operation evidence follows a failure")
        return
    expected = _COMPLETION.get(decision.body["operation"], "Result")
    # A SELECT yielding zero rows has SQLRead but no Result.
    require(all(t == expected for t in terminal), "wrong completion kind for operation")
