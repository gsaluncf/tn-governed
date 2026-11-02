"""Application computations carry native objects until an export boundary."""

import json
import sqlite3

from tn_polars.registry import UnityCatalogRegistry

from experiments.pvldb_evaluation.policy_accumulation import LocalCatalog
from experiments.pvldb_evaluation.run import run_case


def test_sql_example_uses_only_source_database_and_exports_after_computation(tmp_path, monkeypatch):
    catalog = LocalCatalog()
    monkeypatch.setattr(UnityCatalogRegistry, "_request",
                        lambda self, *args, **kwargs: catalog.request(*args, **kwargs))
    connect = sqlite3.connect
    databases = []

    def source_connection(database, *args, **kwargs):
        databases.append(str(database))
        assert "market.sqlite" in str(database), "computation opened an evidence database"
        return connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", source_connection)
    root = tmp_path / "application"
    observed = []

    def completed(context, report, value, directory):
        assert not (directory / "publications").exists()
        publication = context.store_object(value.reference.object_id)
        assert publication.id == value.reference.object_id
        assert context._metadata(value)[2][0].statement
        observed.append(publication.id)
        return {"completed": True, "verified": True, "processing_seconds": 0.0}

    result = run_case(root, "primitive", rows=3, completion_handler=completed)
    assert result["completed"] and result["verified"], result
    assert observed and databases
    assert not tuple(root.rglob("publications.sqlite3"))
    assert tuple((root / "publications" / "objects").glob("*.tn"))
    manifest = json.loads((root / "run.json").read_text())
    assert manifest["console_disclosures"]["internal"] == result["expected_content"]
