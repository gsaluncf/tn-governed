"""Endpoint-local authority combination and required-action dependency rules."""

from dataclasses import dataclass, field
from types import MappingProxyType

from .values.runtime import Assessment


def _action_names(value):
    if not isinstance(value, (tuple, list)):
        raise ValueError("required actions need an ordered sequence of names")
    if any(type(name) is not str or not name.strip() for name in value):
        raise ValueError("required actions need nonempty names")
    return tuple(value)


@dataclass(frozen=True)
class ActionRequirement:
    name: str
    after: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()

    def __post_init__(self):
        if type(self.name) is not str or not self.name.strip():
            raise ValueError("actions require nonempty names")
        object.__setattr__(self, "after", _action_names(self.after))
        object.__setattr__(self, "conflicts", _action_names(self.conflicts))


@dataclass(frozen=True)
class PolicyVote:
    permit: bool
    reason: str
    actions: tuple[str, ...] = ()
    domain: str = "use"

    def __post_init__(self):
        if (
            type(self.permit) is not bool
            or type(self.reason) is not str
            or type(self.domain) is not str
            or not self.domain.strip()
        ):
            raise ValueError("policy votes require explicit permission, reason, and domain")
        object.__setattr__(self, "actions", _action_names(self.actions))


@dataclass(frozen=True)
class PolicyRule:
    contract: object
    evaluate: object


@dataclass(frozen=True)
class PolicyAssessment(Assessment):
    evaluation: dict = field(default_factory=dict)


class AuthorityEvaluator:
    """Combine exact-contract votes using this endpoint's explicit authority order.

    Precedence selects the highest-ranked authorities independently in each
    conflict domain. Ties require agreement. Every vote is retained in the
    signed decision, and discarded votes do not remove their source contracts.
    """

    def __init__(self, rules, *, mode="all", authority_priority=None, actions=(), claim_judge=None):
        self.rules = tuple(rules)
        if mode not in {"all", "precedence"}:
            raise ValueError("authority combination must be all or precedence")
        if any(
            not isinstance(rule, PolicyRule) or not callable(rule.evaluate) for rule in self.rules
        ):
            raise TypeError("policy rules require native contracts and evaluators")
        self.mode = mode
        priorities = dict(authority_priority or {})
        if any(type(rank) is not int for rank in priorities.values()):
            raise TypeError("authority priority must be an integer")
        self.priorities = MappingProxyType(priorities)
        definitions = tuple(actions)
        if any(not isinstance(action, ActionRequirement) for action in definitions):
            raise TypeError("required actions need explicit dependency definitions")
        self.actions = MappingProxyType({action.name: action for action in definitions})
        if len(self.actions) != len(definitions):
            raise ValueError("required action names must be unique")
        if claim_judge is not None and not callable(claim_judge):
            raise TypeError("claim judge must be callable")
        self.claim_judge = (
            (lambda claim, request: "informative") if claim_judge is None else claim_judge
        )

    def _order_actions(self, required):
        visiting, visited, order = set(), set(), []

        def visit(name):
            if name in visited:
                return
            if name in visiting:
                raise ValueError("required-action dependencies contain a cycle")
            if name not in self.actions:
                raise ValueError("required action has no configured dependency definition")
            visiting.add(name)
            for dependency in self.actions[name].after:
                visit(dependency)
            visiting.remove(name)
            visited.add(name)
            order.append(name)

        for name in sorted(set(required)):
            visit(name)
        if any(set(self.actions[name].conflicts) & visited for name in visited):
            raise ValueError("required actions are incompatible")
        return tuple(order)

    def __call__(self, request):
        votes, reasons = [], []
        for policy in request.policies:
            matching = [rule for rule in self.rules if policy.matches_contract(rule.contract)]
            if len(matching) != 1:
                reasons.append("source contract requires exactly one recognized local rule")
                continue
            vote = matching[0].evaluate(request)
            if (
                not isinstance(vote, PolicyVote)
                or type(vote.permit) is not bool
                or not isinstance(vote.reason, str)
                or not isinstance(vote.domain, str)
                or not vote.domain
                or any(not isinstance(name, str) or not name for name in vote.actions)
            ):
                raise ValueError("policy evaluator returned an invalid vote")
            rank = self.priorities.get(policy.governed_by)
            if self.mode == "precedence" and rank is None:
                reasons.append("source authority has no configured precedence")
            votes.append(
                {
                    "authority": policy.governed_by,
                    "policy": policy.policy_ref,
                    "revision": policy.revision_id,
                    "permit": vote.permit,
                    "reason": vote.reason,
                    "domain": vote.domain,
                    "rank": rank,
                    "actions": list(vote.actions),
                    "selected": True,
                }
            )
        if self.mode == "precedence" and not reasons:
            for domain in {vote["domain"] for vote in votes}:
                highest = max(vote["rank"] for vote in votes if vote["domain"] == domain)
                for vote in votes:
                    if vote["domain"] == domain:
                        vote["selected"] = vote["rank"] == highest
        chosen = [vote for vote in votes if vote["selected"]]
        if not chosen or any(not vote["permit"] for vote in chosen):
            reasons.append("selected source conditions do not permit this operation")
        ordered = ()
        if not reasons:
            try:
                ordered = self._order_actions(name for vote in chosen for name in vote["actions"])
            except ValueError as exc:
                reasons.append(str(exc))
        judgments = tuple((claim.id, self.claim_judge(claim, request)) for claim in request.claims)
        if any(not isinstance(judgment, str) or not judgment for _, judgment in judgments):
            raise ValueError("claim judgments require nonempty statements")
        return PolicyAssessment(
            not reasons,
            "; ".join(reasons) or "local source rules permit the request",
            ordered,
            judgments,
            {
                "mode": self.mode,
                "votes": votes,
                "action_order": list(ordered),
                "action_dependencies": {name: list(self.actions[name].after) for name in ordered},
            },
        )
