import json
import os

import pytest

from experiments.pvldb_evaluation.run import run_case
from tn_polars.registry import UnityCatalogRegistry


@pytest.fixture
def catalog(monkeypatch):
    volumes, calls = {}, []
    def request(self, method, path, payload=None):
        calls.append((method, path))
        if path in {"/catalogs", "/schemas"}:
            return {}
        if method == "POST" and path == "/volumes":
            full = f"{payload['catalog_name']}.{payload['schema_name']}.{payload['name']}"
            volumes[full] = dict(payload)
            return volumes[full]
        if method == "GET" and path.startswith("/volumes/"):
            return volumes[path.removeprefix("/volumes/")]
        raise AssertionError((method, path))
    monkeypatch.setattr(UnityCatalogRegistry, "_request", request)
    return calls


@pytest.mark.parametrize("kind", ["int", "float", "Decimal"])
def test_query_batch_keeps_types_claims_and_policies(tmp_path, catalog, kind):
    root = tmp_path / kind
    result = run_case(root, "primitive", rows=5, numeric_type=kind,
                      sdk_build_record=os.getenv("TN_TEST_SDK_BUILD_RECORD"))
    assert result["completed"] and result["verified"], result
    run = json.loads((root / "run.json").read_text())
    facts, = run["evaluation"]["dataframe"]
    assert facts["numeric_profile"]["kind"] == kind
    assert facts["source_row_count"] == 5
    assert len(facts["policies"]) == 2
    assert set(facts) == {"schema", "numeric_profile", "output_schema", "source_row_count",
                          "output_reference", "policies"}
    assert result["dataframe_verification"]["value_matches_reference"]
    assert len([call for call in catalog if call[0] == "GET" and ".source_" in call[1]]) == 1
    assert len([call for call in catalog if call[0] == "POST" and call[1] == "/volumes"]) == 2
    assert len([call for call in catalog if call[0] == "GET"]) == 2


def test_source_batch_boundary_keeps_all_rows_distinct(tmp_path, catalog):
    root = tmp_path / "boundary"
    result = run_case(root, "primitive", rows=65,
                      sdk_build_record=os.getenv("TN_TEST_SDK_BUILD_RECORD"))
    assert result["completed"] and result["verified"], result
    run = json.loads((root / "run.json").read_text())
    facts, = run["evaluation"]["dataframe"]
    assert facts["source_row_count"] == 65
    assert len(facts["policies"]) == 2
    assert result["dataframe_verification"]["value_matches_reference"]
    assert len([call for call in catalog if call[0] == "GET"]) == 2


def test_derived_singleton_carries_policy_into_dataframe(tmp_path, catalog, monkeypatch):
    from experiments.pvldb_evaluation import run as module
    original = module.dataframe_calculate
    def calculate(context, rows):
        rows = list(rows)
        # The replacement publication carries the same admitted policy.
        rows[1] = (rows[1][0], rows[1][1] + 0)
        assert rows[1][1].reference.field == "value"
        return original(context, rows)
    monkeypatch.setattr(module, "dataframe_calculate", calculate)
    result = run_case(tmp_path / "derived", "primitive", rows=5,
                      sdk_build_record=os.getenv("TN_TEST_SDK_BUILD_RECORD"))
    assert result["completed"] and result["verified"], result
