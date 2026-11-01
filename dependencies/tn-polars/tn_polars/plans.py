"""Configured Polars plan execution with conservative dependency coverage."""

import hashlib
from dataclasses import dataclass

import polars as pl

from .release import PolicyDenied
from .support import Support


@dataclass(frozen=True)
class PlanTransform:
    """Endpoint-trusted lazy-plan builder; callbacks receive admitted input plans.

    The identifier and version identify the configured implementation. Plan bytes
    are hashed, not transported: in-memory scans and Python closures can contain
    protected values. The verifier does not deserialize or execute a saved plan.
    """

    identifier: str
    version: str
    build: object

    def __post_init__(self):
        if (
            not isinstance(self.identifier, str)
            or not self.identifier.strip()
            or not isinstance(self.version, str)
            or not self.version.strip()
            or not callable(self.build)
        ):
            raise ValueError("plan transform requires identity, version and callable")


def transform(frame, registration, others):
    from .frame import GovernedLazyFrame

    if not isinstance(registration, PlanTransform):
        raise TypeError("general plans require a configured PlanTransform")
    inputs = (frame, *others)
    if any(not isinstance(item, GovernedLazyFrame) or item._tn is None for item in inputs):
        raise PolicyDenied("plan inputs require native governed dataframe admission")
    boundary = frame._tn.copy()
    for item in others:
        boundary = boundary.include(item._tn)
    roots = set().union(*(set().union(*item.sources.values()) for item in inputs))
    roots.update(root for item in inputs for root in item.row_sources)
    parameters = {
        "identifier": registration.identifier,
        "version": registration.version,
        "input_heads": [list(item._tn.policies.audit.heads) for item in inputs],
    }
    boundary.policies.decide(
        "transform",
        boundary.use.application,
        {"*": roots},
        roots,
        boundary.use,
        parameters=parameters,
    )
    result = registration.build(*(item.frame.clone() for item in inputs))
    if not isinstance(result, pl.LazyFrame):
        raise TypeError("plan builders must return a Polars LazyFrame")
    names = result.collect_schema().names()
    if any(name.startswith("__tn_support_") for name in names):
        raise PolicyDenied("plan outputs use reserved contributor columns")
    parameters["plan_digest"] = "sha256:" + hashlib.sha256(result.serialize()).hexdigest()
    parameters["engine_version"] = pl.__version__
    parameters["output_columns"] = names
    boundary.policies.record_operation("transform", parameters)
    policies = {}
    for item in inputs:
        for identity, sources in item._support.policy_sources.items():
            policies[identity] = policies.get(identity, frozenset()) | sources
    support = Support(
        result, {}, {}, policies, any(item._support.aggregated for item in inputs), False, False
    )
    return GovernedLazyFrame(
        result,
        frame.policy,
        frame.tn_governance,
        frame.evaluator,
        sources={name: set(roots) for name in names},
        row_sources=roots,
        tn_boundary=boundary,
        _support=support,
    )
