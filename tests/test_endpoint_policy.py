"""Authority precedence and action graphs belong to individual endpoints."""

import pytest
from test_endpoints import endpoints as endpoints

from tn_governed.values.runtime import ObligationResult
from tn_governed.values.string import OperationDenied


def test_endpoints_can_apply_different_precedence_without_rewriting_policies(endpoints):
    from tn_governed.endpoint_policy import AuthorityEvaluator, PolicyRule, PolicyVote

    peers, policies = endpoints
    source = peers["source"]
    value = source.originate(9, policies=policies[:2])
    rules = (
        PolicyRule(policies[0], lambda request: PolicyVote(True, "analysis allowed")),
        PolicyRule(policies[1], lambda request: PolicyVote(False, "restricted")),
    )
    bundle = source.export(value)
    outcomes = []
    for role, ranks in (("analyst", (2, 1)), ("restricted", (1, 2))):
        endpoint = peers[role]
        arrived = endpoint.receive(bundle)
        endpoint.evaluator = AuthorityEvaluator(
            rules,
            mode="precedence",
            authority_priority={
                policy.governed_by: rank for policy, rank in zip(policies[:2], ranks, strict=True)
            },
        )
        try:
            outcomes.append(endpoint.reveal(arrived, destination="internal"))
        except OperationDenied:
            outcomes.append("refused")
        decision = next(
            record for record in reversed(endpoint.records()) if record.body["kind"] == "Decision"
        )
        assert len(decision.body["details"]["evaluation"]["votes"]) == 2
    assert outcomes == [9, "refused"]
    assert len(source._metadata(value)[0].policies) == 2


def test_action_dependencies_execute_in_order_and_retain_evidence(endpoints):
    from tn_governed.endpoint_policy import (
        ActionRequirement,
        AuthorityEvaluator,
        PolicyRule,
        PolicyVote,
    )

    peers, policies = endpoints
    endpoint = peers["source"]
    value = endpoint.originate(4, policies=(policies[0],))
    endpoint.evaluator = AuthorityEvaluator(
        (
            PolicyRule(
                policies[0],
                lambda request: PolicyVote(
                    request.purpose == "analysis", "purpose check", actions=("release-ticket",)
                ),
            ),
        ),
        actions=(
            ActionRequirement("log"),
            ActionRequirement("review", after=("log",)),
            ActionRequirement("release-ticket", after=("review",)),
        ),
    )
    called = []

    def handler(name):
        return lambda request: called.append(name) or ObligationResult(True, "ledger:" + name)

    endpoint.obligations.update(
        {name: handler(name) for name in ("log", "review", "release-ticket")}
    )
    derived = endpoint.execute("calculate", (value,), lambda values: values[0] + 1)
    assert called == ["log", "review", "release-ticket"]
    assert endpoint.metadata(derived)["action_records"][-1] == derived.decision_id
    details = endpoint.read_record(derived.decision_id).body["details"]
    assert details["evaluation"]["action_order"] == called
    assert all(item["satisfied"] for item in details["discharged"])


@pytest.mark.parametrize("graph", ["cycle", "conflict", "missing"])
def test_invalid_action_graph_is_refused_before_any_handler(endpoints, graph):
    from tn_governed.endpoint_policy import (
        ActionRequirement,
        AuthorityEvaluator,
        PolicyRule,
        PolicyVote,
    )

    peers, policies = endpoints
    endpoint = peers["source"]
    value = endpoint.originate(4, policies=(policies[0],))
    definitions = {
        "cycle": (ActionRequirement("a", after=("b",)), ActionRequirement("b", after=("a",))),
        "conflict": (
            ActionRequirement("a", after=("b",), conflicts=("b",)),
            ActionRequirement("b"),
        ),
        "missing": (ActionRequirement("a", after=("b",)),),
    }
    endpoint.evaluator = AuthorityEvaluator(
        (PolicyRule(policies[0], lambda request: PolicyVote(True, "conditional", actions=("a",))),),
        actions=definitions[graph],
    )
    called = []
    endpoint.obligations.update(a=lambda _: called.append("a"), b=lambda _: called.append("b"))
    with pytest.raises(OperationDenied):
        endpoint.execute("calculate", (value,), lambda _: pytest.fail("computation started"))
    assert called == []


def test_unrecognized_rule_and_equal_rank_conflict_refuse(endpoints):
    from tn_governed.endpoint_policy import AuthorityEvaluator, PolicyRule, PolicyVote

    peers, policies = endpoints
    endpoint = peers["source"]
    value = endpoint.originate(4, policies=policies[:2])
    endpoint.evaluator = AuthorityEvaluator(
        (PolicyRule(policies[0], lambda _: PolicyVote(True, "allow")),)
    )
    with pytest.raises(OperationDenied):
        endpoint.reveal(value, destination="internal")
    endpoint.evaluator = AuthorityEvaluator(
        (
            PolicyRule(policies[0], lambda _: PolicyVote(True, "allow")),
            PolicyRule(policies[1], lambda _: PolicyVote(False, "deny")),
        ),
        mode="precedence",
        authority_priority={policy.governed_by: 1 for policy in policies[:2]},
    )
    with pytest.raises(OperationDenied):
        endpoint.reveal(value, destination="internal")


@pytest.mark.parametrize("malformed", ["ab", {"a", "b"}, {"a": True}, None])
def test_action_collections_reject_nonsequences(malformed):
    from tn_governed.endpoint_policy import ActionRequirement, PolicyVote

    for constructor in (
        lambda: ActionRequirement("review", after=malformed),
        lambda: ActionRequirement("review", conflicts=malformed),
        lambda: PolicyVote(True, "conditional", actions=malformed),
    ):
        with pytest.raises(ValueError, match="sequence"):
            constructor()


def test_mutating_config_lists_does_not_change_frozen_vote_or_action():
    from tn_governed.endpoint_policy import ActionRequirement, PolicyVote

    required, dependencies, conflicts = ["review"], ["log"], ["export"]
    vote = PolicyVote(True, "conditional", actions=required)
    action = ActionRequirement("review", after=dependencies, conflicts=conflicts)
    for names in (required, dependencies, conflicts):
        names.append("injected")
    assert vote.actions == ("review",)
    assert action.after == ("log",)
    assert action.conflicts == ("export",)


@pytest.mark.parametrize("judge", [False, 0, "", "informative"])
def test_invalid_claim_judge_is_not_silently_replaced(judge):
    from tn_governed.endpoint_policy import AuthorityEvaluator

    with pytest.raises(TypeError, match="claim"):
        AuthorityEvaluator((), claim_judge=judge)


def test_string_action_vote_is_refused_without_invoking_character_named_handlers(endpoints):
    from tn_governed.endpoint_policy import (
        ActionRequirement,
        AuthorityEvaluator,
        PolicyRule,
        PolicyVote,
    )

    peers, policies = endpoints
    endpoint = peers["source"]
    value = endpoint.originate(7, policies=(policies[0],))
    called = []
    endpoint.evaluator = AuthorityEvaluator(
        (PolicyRule(policies[0], lambda _: PolicyVote(True, "conditional", actions="ab")),),
        actions=(ActionRequirement("a"), ActionRequirement("b")),
    )
    for name in ("a", "b"):
        endpoint.obligations[name] = lambda _, name=name: (
            called.append(name) or ObligationResult(True, "receipt:" + name)
        )
    with pytest.raises(OperationDenied):
        endpoint.reveal(value, destination="internal")
    assert called == []
