"""Configured Polars plan execution with conservative dependency coverage."""

from dataclasses import dataclass

import polars as pl

from .release import PolicyDenied


@dataclass(frozen=True)
class PlanTransform:
    """Endpoint-trusted lazy-plan builder; callbacks receive admitted input plans.

    The endpoint authorizes the configured identifier and version before invoking the builder.
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
    boundary = frame._tn
    for item in others:
        boundary = boundary.include(item._tn)
    roots = set().union(*(set().union(*item.sources.values()) for item in inputs))
    roots.update(root for item in inputs for root in item.row_sources)
    parameters = {
        "identifier": registration.identifier,
        "version": registration.version,
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
    return GovernedLazyFrame(
        result,
        frame.policy,
        frame.tn_governance,
        frame.evaluator,
        sources={name: set(roots) for name in names},
        row_sources=roots,
        tn_boundary=boundary,
        ordinary_rows=False,
    )
