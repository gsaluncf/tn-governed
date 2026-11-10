"""Recipients authenticate the frame policy descriptor against native contracts."""

import pytest
from test_native_calculation_path import POLARS_RELEASE, POLARS_USE
from test_native_calculation_path import setup as setup

from tn_governed.polars_stage import prepare_wealth_calculation


def joined_frame(setup):
    wealth, calendar = setup.editions()
    frame = prepare_wealth_calculation(
        setup.built[0].source.wire,
        setup.built[1].source.wire,
        wealth_edition=wealth,
        calendar_edition=calendar,
        session=setup.polars,
        use=POLARS_USE,
        decide_receive=lambda _: True,
    )
    return frame, (wealth, calendar)


def test_row_binding_distinguishes_types_and_nested_user_objects():
    from decimal import Decimal

    from tn_polars.audit import rows_digest

    values = [1, 1.0, Decimal("1"), "1", ["int", "1"], {"int": "1"}, None, False]
    assert len({rows_digest([{"value": value}]) for value in values}) == len(values)
    assert rows_digest([{"a": 1, "b": 2}]) == rows_digest([{"b": 2, "a": 1}])



@pytest.mark.parametrize("field,replacement", [
    ("policies", []), ("group", "outside"), ("claims", ["detached-claim"]),
    ("actions", ["detached-action"]), ("sql", "select *"),
])
def test_recipient_refuses_inconsistent_frame_governance(setup, field, replacement):
    from tn_polars.audit import AuditError, verify_native_frame

    frame, _ = joined_frame(setup)
    publication = frame.release_tn(use=POLARS_RELEASE, to="calculation", decide=lambda _: True)
    data = setup.polars.receive(publication, use=POLARS_USE, groups=["finance"], decide=lambda _: True)
    governance = setup.polars.governance(publication).governance
    descriptor = verify_native_frame(data, governance=governance, group="finance", rows_field="rows")
    assert set(descriptor["policies"]) == set(frame._tn.policies.revision_ids)
    modified = {**descriptor, field: replacement}
    data.set("tn_polars_governance", modified, group="finance")
    with pytest.raises(AuditError):
        verify_native_frame(data, governance=governance, group="finance", rows_field="rows")
