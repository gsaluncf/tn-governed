"""Ordered required-action execution with retained completion evidence."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class ObligationResult:
    satisfied: bool
    evidence: str


@dataclass(frozen=True)
class ObligationStep:
    name: str
    satisfied: bool
    evidence: str | None


@dataclass(frozen=True)
class ObligationRun:
    steps: tuple[ObligationStep, ...] = ()
    failed_obligation: str | None = None
    error: Exception | None = None

    @property
    def complete(self) -> bool:
        return self.failed_obligation is None

    def record_details(self) -> dict:
        details = {
            "discharged": [
                {"obligation": step.name, "satisfied": step.satisfied, "evidence": step.evidence}
                for step in self.steps
            ]
        }
        if self.failed_obligation is not None:
            details["failed_obligation"] = self.failed_obligation
        if self.error is not None:
            details["error_type"] = type(self.error).__name__
        return details


def run_obligations(
    request: object,
    names: tuple[str, ...],
    handlers: Mapping[str, Callable[[object], ObligationResult]],
    *,
    observe: Callable[[ObligationStep], object] | None = None,
) -> ObligationRun:
    """Stop at the first incomplete action, preserving earlier reported evidence.

    Handler exceptions are returned with their failure record so callers can
    durably record refusal before raising an exception chained to the cause.
    """
    if not isinstance(names, tuple) or any(
        not isinstance(name, str) or not name.strip() for name in names
    ):
        raise ValueError("required actions must be a tuple of nonempty names")
    steps = []
    for name in names:
        try:
            handler = handlers.get(name)
            result = handler(request) if handler is not None else None
            evidence = (
                result.evidence
                if isinstance(result, ObligationResult) and result.satisfied is True
                else None
            )
            complete = isinstance(evidence, str) and bool(evidence.strip())
        except Exception as exc:
            steps.append(ObligationStep(name, False, None))
            if observe is not None:
                observe(steps[-1])
            return ObligationRun(tuple(steps), name, exc)
        steps.append(ObligationStep(name, complete, evidence if complete else None))
        if observe is not None:
            observe(steps[-1])
        if not complete:
            return ObligationRun(tuple(steps), name)
    return ObligationRun(tuple(steps))
