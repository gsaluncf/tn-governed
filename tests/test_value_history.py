"""Value changes append governed versions without erasing earlier evidence."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
import tn
from test_carried_values import _without_persistence
from test_endpoints import endpoints as enrolled_endpoints  # noqa: F401 - Pytest fixture registration.

from tn_governed.endpoints import Endpoint
from tn_governed.values.string import OperationDenied


@pytest.fixture
def endpoints(request):
    peers, policies = request.getfixturevalue("enrolled_endpoints")
    return {
        role: Endpoint(
            session=endpoint.session,
            evidence_policy=endpoint.recorder.policy,
            evidence_policies=endpoint.evidence_policies,
            evaluator=endpoint.evaluator,
            application=endpoint.application,
            purpose=endpoint.purpose,
            accept_metadata=endpoint.accept_metadata,
        )
        for role, endpoint in peers.items()
    }, policies


def test_insert_rederive_delete_retains_original_claim_and_actions(endpoints):
    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    original = endpoint.attest(endpoint.originate(3, policies=(policies[0],)), "estimated")
    history = ValueHistory(endpoint)
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
    reopened = ValueHistory.receive(history.export(), reader)
    assert reopened.head("balance") == deleted
    assert reopened.head("balance").carrier is not None


def test_optimistic_updates_allow_one_successor_for_a_shared_head(endpoints):
    from tn_governed.value_history import HistoryConflict, ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    first = ValueHistory(endpoint)
    head = first.insert("amount", endpoint.originate(1, policies=(policies[0],)))

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
        values = list(pool.map(lambda pair: change(*pair), ((first, 2), (first, 4))))
    assert sum(value is not None for value in values) == 1
    assert len(first.versions("amount")) == 2


def test_failed_rederivation_does_not_advance_history(endpoints):
    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    history = ValueHistory(endpoint)
    head = history.insert("amount", endpoint.originate(1, policies=(policies[0],)))

    def failed(values):
        raise RuntimeError("calculation unavailable")

    with pytest.raises(RuntimeError):
        history.rederive("amount", expected=head, inputs=(head,), compute=failed)
    assert history.versions("amount") == (head,)


def test_restore_preserves_deleted_predecessor_and_new_source(endpoints):
    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    original = endpoint.attest(endpoint.originate(3, policies=(policies[0],)), "original estimate")
    history = ValueHistory(endpoint)
    first = history.insert("amount", original)
    deleted = history.delete("amount", expected=first, reason="expired")
    replacement = endpoint.originate(11, policies=(policies[1],))
    restored = history.restore("amount", expected=deleted, artifact=replacement)
    assert history.versions("amount") == (first, deleted, restored)
    assert endpoint.reveal(restored, destination="internal") == 11
    assert endpoint.claims(restored) == endpoint.claims(original)
    assert len(endpoint._metadata(restored)[0].policies) == 2


def test_restore_rejects_deleted_replacement_without_advancing_history(endpoints):
    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    history = ValueHistory(endpoint)
    first = history.insert("amount", endpoint.originate(3, policies=(policies[0],)))
    deleted = history.delete("amount", expected=first, reason="expired")
    with pytest.raises(ValueError, match="active replacement"):
        history.restore("amount", expected=deleted, artifact=deleted)
    assert history.versions("amount") == (first, deleted)


def test_history_rejects_signed_restore_without_a_deleted_predecessor(endpoints):
    from tn_governed.value_history import HistoryConflict, HistorySnapshot, ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    source = endpoint.originate(7, policies=(policies[0],))
    forged = endpoint.execute(
        "restore",
        (source,),
        lambda values: values[0],
        parameters={"history": {"key": "amount", "sequence": 1, "previous": None}},
    )
    bundle = endpoint.export(forged)
    snapshot = HistorySnapshot((("amount", (bundle.artifact,)),), bundle.publications)
    with pytest.raises(HistoryConflict, match="transition"):
        ValueHistory.receive(snapshot, peers["analyst"])


def test_history_computation_requires_no_files_or_database(endpoints, monkeypatch):
    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    with _without_persistence(monkeypatch):
        history = ValueHistory(endpoint)
        source = endpoint.originate(3, policies=(policies[0],))
        first = history.insert("amount", source)
        second = history.rederive(
            "amount", expected=first, inputs=(first,), compute=lambda values: values[0] * 2
        )
        deleted = history.delete("amount", expected=second, reason="expired")
        restored = history.restore("amount", expected=deleted, artifact=source)
        actual = endpoint.reveal(restored, destination="internal")
        versions = history.versions("amount")
    assert actual == 3
    assert versions == (first, second, deleted, restored)
    assert all(artifact.carrier is not None for artifact in versions)


def test_explicit_export_roundtrip_and_constructor_path_is_not_opened(
    endpoints, monkeypatch, tmp_path
):
    from tn_governed.value_history import HistorySnapshot, ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    path = tmp_path / "history.json"
    with _without_persistence(monkeypatch):
        history = ValueHistory(path, endpoint)
        first = history.insert("amount", endpoint.originate(3, policies=(policies[0],)))
        second = history.rederive(
            "amount", expected=first, inputs=(first,), compute=lambda values: values[0] + 4
        )
    assert not path.exists()
    snapshot = history.export()
    assert path.is_file()
    loaded = HistorySnapshot.parse(path.read_bytes())
    assert loaded == snapshot
    with _without_persistence(monkeypatch):
        received = ValueHistory.receive(loaded, peers["analyst"])
        assert received.versions("amount") == (first, second)
        assert peers["analyst"].reveal(received.head("amount"), destination="internal") == 7


@pytest.mark.parametrize(
    "change", ["reordered", "missing_predecessor", "wrong_key", "duplicate_key"]
)
def test_received_history_rejects_index_changes_against_signed_versions(endpoints, change):
    from tn_governed.value_history import HistoryConflict, ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    history = ValueHistory(endpoint)
    first = history.insert("amount", endpoint.originate(3, policies=(policies[0],)))
    second = history.rederive(
        "amount", expected=first, inputs=(first,), compute=lambda values: values[0] + 4
    )
    snapshot = history.export()
    changes = {
        "reordered": (("amount", (second, first)),),
        "missing_predecessor": (("amount", (second,)),),
        "wrong_key": (("other", (first, second)),),
        "duplicate_key": (("amount", (first, second)), ("amount", (first, second))),
    }
    with pytest.raises(HistoryConflict):
        ValueHistory.receive(replace(snapshot, versions=changes[change]), peers["analyst"])


def test_received_history_requires_referenced_native_evidence(endpoints):
    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    history = ValueHistory(endpoint)
    head = history.insert("amount", endpoint.originate(3, policies=(policies[0],)))
    snapshot = history.export()
    with pytest.raises((ValueError, FileNotFoundError)):
        ValueHistory.receive(replace(snapshot, publications=()), peers["analyst"])
    assert history.head("amount") == head


def test_reentrant_change_cannot_replace_a_more_recent_head(endpoints):
    from tn_governed.value_history import HistoryConflict, ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    history = ValueHistory(endpoint)
    first = history.insert("amount", endpoint.originate(3, policies=(policies[0],)))
    successors = []

    def nested_change(values):
        successors.append(
            history.rederive(
                "amount", expected=first, inputs=(first,), compute=lambda items: items[0] + 1
            )
        )
        return values[0] + 10

    with pytest.raises(HistoryConflict, match="during"):
        history.rederive("amount", expected=first, inputs=(first,), compute=nested_change)
    assert history.versions("amount") == (first, successors[0])
    assert endpoint.reveal(history.head("amount"), destination="internal") == 4


def test_history_receive_uses_the_recipients_authority_rules(endpoints):
    from tn.governed import UseDenied

    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    source = peers["source"]
    history = ValueHistory(source)
    history.insert("amount", source.originate(3, policies=(policies[0],)))
    snapshot = history.export()
    peers["analyst"].accept_metadata = lambda ctx: False
    with pytest.raises(UseDenied):
        ValueHistory.receive(snapshot, peers["analyst"])


def test_history_export_preserves_an_existing_database_archive(endpoints, tmp_path):
    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    path = tmp_path / "history.sqlite"
    retained = b"SQLite format 3\x00" + b"existing archive contents"
    path.write_bytes(retained)
    history = ValueHistory(path, endpoint)
    history.insert("amount", endpoint.originate(3, policies=(policies[0],)))
    with pytest.raises(ValueError, match="SQLite archive"):
        history.export()
    assert path.read_bytes() == retained


def test_history_accepts_an_endpoint_keyword_without_a_path(endpoints):
    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    history = ValueHistory(endpoint=endpoint)
    head = history.insert("amount", endpoint.originate(3, policies=(policies[0],)))
    assert history.head("amount") == head


def test_history_transfer_parses_each_native_publication_once(endpoints, monkeypatch):
    from tn_governed.value_history import ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    history = ValueHistory(endpoint)
    first = history.insert("amount", endpoint.originate(3, policies=(policies[0],)))
    second = history.rederive(
        "amount", expected=first, inputs=(first,), compute=lambda values: values[0] + 4
    )
    units = history.insert("units", endpoint.originate(2, policies=(policies[0],)))
    snapshot = history.export()
    parsed = []
    parse = tn.GovernedObject.parse

    def counted_parse(wire):
        parsed.append(wire)
        return parse(wire)

    monkeypatch.setattr(tn.GovernedObject, "parse", counted_parse)
    received = ValueHistory.receive(snapshot, peers["analyst"])
    assert received.versions("amount") == (first, second)
    assert received.versions("units") == (units,)
    assert len(parsed) == len(snapshot.publications)
    assert Counter(parsed) == Counter(snapshot.publications)


def test_history_receive_installs_no_heads_when_a_later_key_is_invalid(endpoints):
    from tn_governed.value_history import HistoryConflict, ValueHistory

    peers, policies = endpoints
    endpoint = peers["source"]
    history = ValueHistory(endpoint)
    history.insert("amount", endpoint.originate(3, policies=(policies[0],)))
    history.insert("units", endpoint.originate(2, policies=(policies[0],)))
    snapshot = history.export()
    altered = replace(
        snapshot,
        versions=(snapshot.versions[0], ("different", snapshot.versions[1][1])),
    )
    candidates = []

    class ObservedHistory(ValueHistory):
        def __init__(self, endpoint):
            super().__init__(endpoint)
            candidates.append(self)

    with pytest.raises(HistoryConflict, match="predecessor"):
        ObservedHistory.receive(altered, peers["analyst"])
    assert len(candidates) == 1
    assert candidates[0].head("amount") is None
    assert candidates[0].head("different") is None
