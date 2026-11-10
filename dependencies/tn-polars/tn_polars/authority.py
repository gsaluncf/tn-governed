"""Endpoint-owned policy evaluators for admitted native relations."""

import json
from copy import deepcopy
from dataclasses import dataclass

from .audit import _digest
from .policy import CompiledPolicy
from .release import Decision, PolicyDenied


def policy_identity(policy):
    return (
        policy.revision_id
        or "native-policy:"
        + _digest({"authority": policy.governed_by, "policy_ref": policy.policy_ref})[7:]
    )


@dataclass(frozen=True)
class EndpointEvaluator:
    """A locally trusted evaluator identity and immutable configuration snapshot.

    Its authority/version are endpoint configuration, not a catalog endorsement.
    The callback receives exact native contract identity, requested use, source
    columns, claims, and observed contributor precision at release.
    """

    authority: str
    identifier: str
    version: str
    configuration: object
    evaluate: object

    def __post_init__(self):
        if any(
            not isinstance(value, str) or not value.strip()
            for value in (self.authority, self.identifier, self.version)
        ):
            raise ValueError("endpoint evaluator requires authority, identifier and version")
        if not callable(self.evaluate):
            raise TypeError("endpoint evaluator requires a decision callback")
        object.__setattr__(
            self,
            "_configuration",
            json.dumps(self.configuration, sort_keys=True, separators=(",", ":"), allow_nan=False),
        )
        object.__setattr__(self, "configuration", None)

    def artifact(self, policy):
        return {
            "kind": "endpoint-evaluator",
            "policy_revision": policy_identity(policy),
            "policy_ref": policy.policy_ref,
            "authority": self.authority,
            "identifier": self.identifier,
            "version": self.version,
            "configuration_digest": _digest(json.loads(self._configuration)),
        }

    def decide(self, request):
        decision = self.evaluate(deepcopy(request))
        if (
            not isinstance(decision, Decision)
            or type(decision.allow) is not bool
            or not isinstance(decision.reason, str)
            or not isinstance(decision.decision_id, str)
            or not decision.decision_id
        ):
            raise PolicyDenied("endpoint evaluator returned no explicit attributable decision")
        return decision


def local_policy_set(policies, evaluators, *, source_id, columns, bindings=()):
    from .tn_boundary import PolicySet, _PolicyEntry

    native = {policy_identity(policy): policy for policy in policies}
    if not native or set(native) != set(evaluators):
        raise PolicyDenied("every native source contract needs an endpoint evaluator")
    entries = {}
    for identity, policy in native.items():
        evaluator = evaluators[identity]
        if not isinstance(evaluator, EndpointEvaluator):
            raise TypeError("local admission requires EndpointEvaluator registrations")
        classification = CompiledPolicy(
            "tn.polars-policy.v1", policy.policy_ref, {name: "confidential" for name in columns}, {}
        )
        entries[identity] = _PolicyEntry(
            classification, evaluator, evaluator.artifact(policy), frozenset({source_id}), None
        )
    return PolicySet(entries)
