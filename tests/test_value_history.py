"""Value changes append governed versions without erasing earlier evidence."""

from concurrent.futures import ThreadPoolExecutor

import pytest
from test_endpoints import endpoints as endpoints

from tn_governed.values.string import OperationDenied


def test_insert_rederive_delete_retains_original_claim_and_actions(endpoints, tmp_path):
    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    original = endpoint.attest(endpoint.originate(3, policies=(policies[0],)), "estimated")
    history = ValueHistory(tmp_path / "history.sqlite", endpoint)
    inserted = history.insert("balance", original)
    updated = history.rederive(
        "balance", expected=inserted, inputs=(inserted,), compute=lambda values: values[0] + 4
    )
    deleted = history.delete("balance", expected=updated, reason="expired")
    assert history.versions("balance") == (inserted, updated, deleted)
    assert history.head("balance") == deleted
    assert endpoint.reveal(updated, destination="internal") == 7
    assert endpoint.metadata(deleted)["state"] == "deleted"
    assert endpoint.claims(deleted) == endpoint.claims(original)
    assert set(endpoint.metadata(original)["action_records"]) <= set(
        endpoint.metadata(deleted)["action_records"]
    )
    with pytest.raises(OperationDenied):
        endpoint.reveal(deleted, destination="internal")
    reader = peers["analyst"]
    received = reader.receive(endpoint.export(deleted))
    assert reader.claims(received)[0].subjects == endpoint.claims(original)[0].subjects
    reopened = ValueHistory(tmp_path / "history.sqlite", endpoint)
    assert reopened.head("balance") == deleted


def test_optimistic_updates_allow_one_successor_for_a_shared_head(endpoints, tmp_path):
    from tn_governed.value_history import HistoryConflict, ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    path = tmp_path / "history.sqlite"
    first = ValueHistory(path, endpoint)
    head = first.insert("amount", endpoint.originate(1, policies=(policies[0],)))
    second = ValueHistory(path, endpoint)

    def change(history, increment):
        try:
            return history.rederive(
                "amount",
                expected=head,
                inputs=(head,),
                compute=lambda values: values[0] + increment,
            )
        except HistoryConflict:
            return None

    with ThreadPoolExecutor(2) as pool:
        values = list(pool.map(lambda pair: change(*pair), ((first, 2), (second, 4))))
    assert sum(value is not None for value in values) == 1
    assert len(first.versions("amount")) == 2


def test_failed_rederivation_does_not_advance_history(endpoints, tmp_path):
    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    history = ValueHistory(tmp_path / "history.sqlite", endpoint)
    head = history.insert("amount", endpoint.originate(1, policies=(policies[0],)))

    def failed(values):
        raise RuntimeError("calculation unavailable")

    with pytest.raises(RuntimeError):
        history.rederive("amount", expected=head, inputs=(head,), compute=failed)
    assert history.versions("amount") == (head,)


def test_restore_preserves_deleted_predecessor_and_new_source(endpoints, tmp_path):
    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    original = endpoint.attest(endpoint.originate(3, policies=(policies[0],)), "original estimate")
    history = ValueHistory(tmp_path / "history.sqlite", endpoint)
    first = history.insert("amount", original)
    deleted = history.delete("amount", expected=first, reason="expired")
    replacement = endpoint.originate(11, policies=(policies[1],))
    restored = history.restore("amount", expected=deleted, artifact=replacement)
    assert history.versions("amount") == (first, deleted, restored)
    assert endpoint.reveal(restored, destination="internal") == 11
    assert endpoint.claims(restored) == endpoint.claims(original)
    assert len(endpoint._metadata(restored)[0].policies) == 2


def test_restore_rejects_deleted_replacement_without_advancing_history(endpoints, tmp_path):
    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    history = ValueHistory(tmp_path / "history.sqlite", endpoint)
    first = history.insert("amount", endpoint.originate(3, policies=(policies[0],)))
    deleted = history.delete("amount", expected=first, reason="expired")
    with pytest.raises(ValueError, match="active replacement"):
        history.restore("amount", expected=deleted, artifact=deleted)
    assert history.versions("amount") == (first, deleted)


def test_history_rejects_signed_restore_without_a_deleted_predecessor(endpoints, tmp_path):
    import json
    import sqlite3

    from tn_governed.value_history import HistoryConflict, ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    history = ValueHistory(tmp_path / "history.sqlite", endpoint)
    source = endpoint.originate(7, policies=(policies[0],))
    forged = endpoint.execute(
        "restore",
        (source,),
        lambda values: values[0],
        parameters={"history": {"key": "amount", "sequence": 1, "previous": None}},
    )
    with sqlite3.connect(history.path) as connection:
        connection.execute(
            "INSERT INTO versions VALUES (?,?,?)", ("amount", 1, json.dumps(forged.to_dict()))
        )
    with pytest.raises(HistoryConflict, match="transition"):
        history.head("amount")
