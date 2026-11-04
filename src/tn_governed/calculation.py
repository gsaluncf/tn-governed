"""Calculation interface for governed portfolio data."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime

import tn

from .calculation_client import CalculationRequest, CalculationResult


@dataclass(frozen=True)
class CalculationExecution:
    """The result returned by the calculation service."""
    result: CalculationResult


def execute_calculation(
    port,
    source: tn.GovernedObject | str | bytes,
    *,
    work: tn.Workflow,
) -> tuple[CalculationExecution, tn.GovernedObject]:
    """Accept, calculate, and release the exact model-facing TN object once."""
    working = work.receive(source)
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
    fields = {"calculation": {"result": asdict(result)}}
    groups = {"finance": fields}
    frame = working.get(group="finance").get("tn_polars_governance")
    if frame and (frame["claims"] or frame["actions"]):
        # Keep the signed record identities on the result. Their subjects are
        # the original subjects of those records, independent of the rows.
        groups["evidence"] = {"manifest": {"schema": "tn.governed-fields.v1", "bindings": {
            "calculation": {"group": "finance", "claims": frame["claims"], "actions": frame["actions"]},
        }}}
    output = working.policy_output("portfolio.calculation.calculated", groups, primary_group="finance")
    if "evidence" in groups:
        output.bind_manifest("evidence")
    return CalculationExecution(result), work.release(output)
