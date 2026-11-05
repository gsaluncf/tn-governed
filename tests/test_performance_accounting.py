import json
from contextlib import nullcontext
from types import SimpleNamespace


def test_accounting_counts_retained_source_fields_in_policy_run(tmp_path, monkeypatch):
    from experiments.pvldb_evaluation.performance_scale import accounting
    from tn_governed import publications

    manifest = {
        "schema": "tn.policy-run.v2",
        "source_editions": [
            {"source_object_id": "names"}, {"source_object_id": "amounts"},
            {"source_object_id": "names"},
        ],
        "outputs": {"model_input": {"reference": {"object_id": "total"}}},
        "evaluation": {"dataframe": [{"policies": ["name-policy", "amount-policy"]}]},
        "tapes": {"gateway": {"count": 3}},
    }
    (tmp_path / "run.json").write_text(json.dumps(manifest))

    class Store:
        def publication_sizes(self):
            return {"names": 100, "amounts": 200, "total": 50}

        def read(self, identity):
            assert identity in {"names", "amounts"}
            return SimpleNamespace(envelope={"values": {"field_hashes": {
                "value_0": "a", "value_1": "b", "value_2": "c",
            }}})

    monkeypatch.setattr(
        publications, "open_publication_store", lambda *_a, **_k: nullcontext(Store()))
    result = accounting(tmp_path)
    assert result["direct_cell_refs"] == 6
    assert result["source_policies"] == 2
    assert result["retained_native_bytes"] == 350
