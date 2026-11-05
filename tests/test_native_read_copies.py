"""Python reads remain detached when the native JSON tree is borrowed."""

import pytest
import tn

from test_native_objects import POLICY


@pytest.mark.parametrize("field", [None, "nested"])
def test_python_read_mutation_does_not_change_native_data(field):
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        data = session.create({"nested": {"items": [1, 2]}},
                              session.policy("finance.account"), group="values")
        result = data.get(field, group="values")
        nested = result["nested"] if field is None else result
        nested["items"].append(3)
        assert data.get("nested", group="values") == {"items": [1, 2]}
        with pytest.raises(ValueError, match="no field"):
            data.get("missing", group="values")
