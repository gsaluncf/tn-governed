"""User-authored governed Polars transformations for the portfolio workflow."""

from __future__ import annotations


import tn
from tn_polars.builder import GovernedPolars
from tn_polars.frame import GovernedLazyFrame



def prepare_wealth_calculation(
    wealth_wire,
    calendar_wire,
    *,
    wealth_edition,
    calendar_edition,
    session: tn.Session,
    use: tn.UseContext,
    decide_receive,
) -> GovernedLazyFrame:
    """Admit two exact editions and prepare ordered wealth rows for calculation."""
    if wealth_edition.catalog is not calendar_edition.catalog:
        raise ValueError("calculation editions must share one accepted native catalog")
    wealth = GovernedPolars.load_from_tn(
        wealth_wire, session=session, use=use, selection=wealth_edition.selection,
        policies=wealth_edition.entries, decide=decide_receive,
    )
    calendar = GovernedPolars.load_from_tn(
        calendar_wire, session=session, use=use, selection=calendar_edition.selection,
        policies=calendar_edition.entries, decide=decide_receive,
    )
    return (
        wealth.join(calendar, on="observation_id")
        .select("observed_at", "wealth")
        .sort("observed_at")
    )

