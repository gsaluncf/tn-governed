"""Large native SQL batches retain per-cell policy, positions, and claims."""

import sqlite3

import pytest
import tn
from test_sql_query_results import sql_endpoint as sql_endpoint

from tn_governed.values.primitives import Context
from tn_governed.values.numeric import TNNumeric
from tn_governed.values.sql import GovernedSQL


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "source.sqlite"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            "CREATE TABLE orders (id INTEGER, customer_id INTEGER, amount INTEGER);"
            "CREATE TABLE customers (id INTEGER, enabled INTEGER, label TEXT);"
        )
        connection.executemany(
            "INSERT INTO orders VALUES (?, ?, ?)", [(index, 1, index + 10) for index in range(257)]
        )
    return path


def test_native_256_cell_batches_preserve_field_positions_policies_and_claims(
    sql_endpoint, tmp_path, monkeypatch
):
    original = sql_endpoint.driver
    driver = GovernedSQL(
        original.database,
        gateway=original.gateway,
        consumer=original.consumer,
        edition_publisher=original.edition_publisher,
        directory=tmp_path / "large-editions",
        batch_size=256,
    )
    def reject_walk(*args, **kwargs):
        pytest.fail("a current SQL source must not request calculation history")
    monkeypatch.setattr(tn, "LineageVerifier", reject_walk)
    constructions = []
    initialize = TNNumeric.__init__

    def construct(self, reference, *args, **kwargs):
        constructions.append(reference)
        initialize(self, reference, *args, **kwargs)

    monkeypatch.setattr(TNNumeric, "__init__", construct)
    rows = driver.execute("SELECT id, amount FROM orders").fetchall()
    assert len(constructions) == 514
    context = sql_endpoint.contexts["consumer"]
    assert len(rows) == 257
    references = [value.reference for row in rows for value in row]
    assert len(set(references)) == 514
    assert len({reference.object_id for reference in references}) == 4
    metadata = context._metadata_many([value for row in rows for value in row])
    policies = {}
    for index, (data, binding, claims) in enumerate(metadata):
        row, column_index = divmod(index, 2)
        column = ("id", "amount")[column_index]
        value = rows[row][column_index]
        assert value.reference.field == f"value_{row}"
        edition = context.editions[value.reference.object_id]
        assert edition.dataset == f"orders.{column}"
        assert value.publication.resolve(edition.id).id == edition.id
        assert set(binding) == {"claims", "declared", "actions"}
        assert claims == ()
        assert len(data.policies) == 1
        policies.setdefault(column, data.policies[0])
        assert data.policies[0].matches_contract(policies[column])
    assert not policies["id"].matches_contract(policies["amount"])
    publication = context.store_object(rows[0][0].reference.object_id)
    assert len(publication.envelope["values"]["field_hashes"]) == 256
    assert not context.session.governance(publication).governance.sources
    gateway = original.gateway
    records = [gateway.recorder.read(identity).body["kind"] for identity in gateway.recorder.ids()]
    assert "Decision" in records and "SQLRead" in records and "Result" not in records
    with context:
        claimed = rows[64][1].attest("Amount at row 64 is a synthetic observation.", context)
        result = claimed + rows[255][1]
    data, binding, claims = context._metadata(result)
    assert len(claims) == 1
    assert claims[0].subjects == (rows[64][1].reference,)
    assert claims[0].issuer == context.session.did
    assert "origins" not in binding and "parents" not in binding
    assert data.policies[0].matches_contract(policies["amount"])
    assert result.reveal(context, destination="support-console") == 339


@pytest.mark.parametrize("batch_size", [0, True, 4097])
def test_sql_rejects_out_of_range_batch_size_before_accessing_database(batch_size):
    with pytest.raises(ValueError, match="batch size"):
        GovernedSQL(
            None,
            gateway=None,
            consumer=None,
            edition_publisher=None,
            directory=None,
            batch_size=batch_size,
        )


def test_source_batch_limit_applies_before_native_publication():
    with pytest.raises(ValueError, match="4096"):
        Context.originate_batch(
            None, [(0, {})] * 4097, None, request=None, decision_id=None, call_id=None
        )
