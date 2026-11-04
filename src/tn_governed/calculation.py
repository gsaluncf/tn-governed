"""Calculation interface for governed portfolio data."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import TYPE_CHECKING

import tn

from .calculation_client import CalculationRequest, CalculationResult


@dataclass(frozen=True)
class CalculationExecution:
    """The invocation and result retained with their exact governed input."""

    source_object_id: str
    request: CalculationRequest
    result: CalculationResult


def execute_calculation(
    port,
    source: tn.GovernedObject | str | bytes,
    *,
    work: tn.Workflow,
) -> tuple[CalculationExecution, tn.GovernedObject]:
    """Accept, calculate, and release the exact model-facing TN object once."""
    working = work.receive(source)
    input_id = working.snapshot.id
    rows = working.get("rows", group="finance")
    if rows is None:
        raise ValueError("calculation input requires ordered wealth rows")
    observations = []
    previous = None
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {"observed_at", "wealth"}:
            raise ValueError("calculation rows require observed_at and wealth")
        try:
            timestamp = datetime.fromisoformat(row["observed_at"])
        except (TypeError, ValueError) as error:
            raise ValueError("wealth rows require an ISO timestamp") from error
        if timestamp.tzinfo is None:
            raise ValueError("wealth rows require a timezone-aware timestamp")
        if previous is not None and timestamp <= previous:
            raise ValueError("wealth rows must be strictly ordered by timestamp")
        previous = timestamp
        observations.append(row["wealth"])
    request = CalculationRequest("max_drawdown", {"wealth_path": observations})
    result = port.calculate(request)
    execution = CalculationExecution(input_id, request, result)
    working.set(None, {
        "calculation": {
            "input_object_id": input_id,
            "request": {"function": request.function, "arguments": request.arguments},
            "result": asdict(result),
        },
    }, group="finance")
    working.select(["finance"])
    released = work.release(working)
    return execution, released

if TYPE_CHECKING:
    pass
