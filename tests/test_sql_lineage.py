"""SQLite execution retains row identities for values and query controls."""

import sqlite3

import pytest

from tn_governed.values.query import (
    SourceColumn,
    SQLFunction,
    SQLiteQuery,
    decode_sql,
    lineage_cells,
)


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "lineage.sqlite"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE sales (id INTEGER, account INTEGER, amount INTEGER);
            CREATE TABLE accounts (id INTEGER, active INTEGER, label TEXT);
            INSERT INTO sales VALUES (1,10,4),(2,10,4),(3,20,9),(4,99,2);
            INSERT INTO accounts VALUES (10,1,'A'),(10,1,'A'),(20,0,'B'),(1,1,'D');
        """)
    return path


def execute(database, sql, parameters=()):
    with SQLiteQuery(database, sql, parameters) as query:
        plan = query.track_contributors()
        rows = query.execute()
        binding = {"sources": [source.to_dict() for source in query.dependencies]}
        lineage = query.result_lineage(binding, rows)
        return plan, rows, {**lineage, "cells": lineage_cells(lineage)}


def keys(cell, table, column, role="value"):
    return {
        tuple(decode_sql(value) for value in contributor["row_key"])
        for contributor in cell["contributors"]
        if contributor["table"] == table
        and contributor["column"] == column
        and contributor["role"] == role
    }


def test_join_expression_distinguishes_equal_values_and_combination_rows(database):
    plan, rows, lineage = execute(
        database,
        """
        SELECT s.amount * :factor AS total, a.label
        FROM sales s JOIN accounts a ON s.account=a.id
        WHERE a.active=:active ORDER BY s.id,a.rowid
    """,
        {"factor": 3, "active": 1},
    )
    assert plan.identifier == "sqlite-ast"
    assert rows.rows == ((12, "A"),) * 4
    assert lineage["row_support"] == "known"
    first, second = lineage["cells"][0], lineage["cells"][2]
    assert keys(first, "sales", "amount") == {(1,)}
    assert keys(second, "sales", "amount") == {(1,)}
    assert keys(first, "accounts", "id", "control") == {(1,)}
    assert keys(second, "accounts", "id", "control") == {(2,)}
    assert {("accounts", "active"), ("sales", "account")} <= {
        (item["table"], item["column"]) for item in lineage["controls"]
    }


def test_filtered_group_aggregation_retains_group_membership(database):
    _, rows, lineage = execute(
        database,
        """
        SELECT account, sum(amount) AS total FROM sales
        WHERE amount < ? GROUP BY account ORDER BY account
    """,
        (9,),
    )
    assert rows.rows == ((10, 8), (99, 2))
    assert keys(lineage["cells"][1], "sales", "amount") == {(1,), (2,)}
    assert keys(lineage["cells"][3], "sales", "amount") == {(4,)}


def test_window_frame_uses_its_actual_partition_and_frame(database):
    _, rows, lineage = execute(
        database,
        """
        SELECT id, sum(amount) OVER (
            PARTITION BY account ORDER BY id ROWS BETWEEN 1 PRECEDING AND CURRENT ROW
        ) AS rolling FROM sales ORDER BY id
    """,
    )
    assert rows.rows == ((1, 4), (2, 8), (3, 9), (4, 2))
    assert keys(lineage["cells"][1], "sales", "amount") == {(1,)}
    assert keys(lineage["cells"][3], "sales", "amount") == {(1,), (2,)}
    assert keys(lineage["cells"][5], "sales", "amount") == {(3,)}


def test_outer_join_missing_side_does_not_invent_a_row_identity(database):
    _, rows, lineage = execute(
        database,
        """
        SELECT s.id,a.label FROM sales s LEFT JOIN accounts a ON s.account=a.id
        WHERE s.id=4
    """,
    )
    assert rows.rows == ((4, None),)
    assert keys(lineage["cells"][1], "accounts", "label") == set()
    assert any(item["table"] == "accounts" for item in lineage["controls"])


def test_empty_result_retains_selection_dependencies(database):
    _, rows, lineage = execute(database, "SELECT amount FROM sales WHERE id < 0")
    assert rows.rows == ()
    assert lineage["cells"] == []
    assert any(item["table"] == "sales" and item["column"] == "id" for item in lineage["controls"])


def test_distinct_uses_declared_snapshot_scope_without_changing_cardinality(database):
    plan, rows, lineage = execute(database, "SELECT DISTINCT amount FROM sales ORDER BY amount")
    assert plan.identifier == "sqlite-authorizer"
    assert rows.rows == ((2,), (4,), (9,))
    assert lineage["row_support"] == "unknown"
    assert lineage["source_columns"]


def test_composite_primary_keys_in_without_rowid_tables(tmp_path):
    path = tmp_path / "keys.sqlite"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE positions(account TEXT, day INTEGER, amount INTEGER,
                PRIMARY KEY(account,day)) WITHOUT ROWID;
            INSERT INTO positions VALUES ('a',1,4),('a',2,7);
        """)
    _, rows, lineage = execute(path, "SELECT amount FROM positions WHERE day=2")
    assert rows.rows == ((7,),)
    assert keys(lineage["cells"][0], "positions", "amount") == {("a", 2)}


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM sales WHERE id=1",
        "SELECT s.* FROM sales s WHERE id=1",
        "SELECT * FROM sales JOIN accounts USING(id)",
        "SELECT * FROM sales NATURAL JOIN accounts",
        "SELECT * FROM sales LEFT JOIN accounts USING(id) ORDER BY id",
        "SELECT * FROM sales RIGHT JOIN accounts USING(id) ORDER BY id",
        "SELECT * FROM sales FULL JOIN accounts USING(id) ORDER BY id",
        "SELECT a.id,b.amount FROM sales a JOIN sales b ON a.account=b.account ORDER BY a.id,b.id",
        "SELECT s.id FROM sales s CROSS JOIN accounts a ORDER BY s.id,a.rowid",
        "SELECT account,sum(amount) FROM sales GROUP BY 1 ORDER BY 1",
    ],
)
def test_identity_projections_preserve_sqlite_shapes(database, sql):
    with sqlite3.connect(database) as connection:
        expected = tuple(connection.execute(sql).fetchall())
    plan, actual, lineage = execute(database, sql)
    assert plan.identifier == "sqlite-ast"
    assert actual.rows == expected
    assert len(lineage["cells"]) == len(actual.rows) * len(actual.columns)
    assert all(
        any(item["role"] == "presence" for item in cell["contributors"])
        for cell in lineage["cells"]
    )


def test_business_udf_executes_once_per_result_not_once_per_lineage_pass(database):
    calls = []
    function = SQLFunction(
        "observe", 1, lambda value: calls.append(value) or value, authority="application:analysis"
    )
    with SQLiteQuery(
        database, "SELECT observe(amount) FROM sales ORDER BY id", functions=(function,)
    ) as query:
        plan = query.track_contributors()
        assert calls == []
        rows = query.execute()
    assert plan.identifier == "sqlite-ast"
    assert rows.rows == ((4,), (4,), (9,), (2,))
    assert calls == [4, 4, 9, 2]


def test_copied_window_parameters_keep_their_original_bindings(database):
    _, result, _ = execute(
        database,
        """
        SELECT id, sum(amount * ?) OVER (ORDER BY id ROWS BETWEEN ? PRECEDING AND CURRENT ROW)
        FROM sales WHERE id <= ? ORDER BY id
    """,
        (2, 1, 3),
    )
    assert result.rows == ((1, 8), (2, 16), (3, 26))


def test_projection_alias_precedence_does_not_substitute_a_source_column(database):
    _, result, lineage = execute(database, "SELECT amount * -1 AS id FROM sales ORDER BY id")
    assert result.rows == ((-9,), (-4,), (-4,), (-2,))
    assert {item["column"] for item in lineage["controls"]} == {"amount"}


def test_private_projection_names_do_not_change_ordering(database):
    sql = "SELECT amount AS __tn_lineage_0 FROM sales ORDER BY __tn_lineage_0"
    _, result, _ = execute(database, sql)
    assert result.rows == ((2,), (4,), (4,), (9,))


def test_function_external_dependencies_remain_explicitly_unmapped(database):
    function = SQLFunction(
        "extra",
        1,
        lambda value: value + 5,
        authority="accounting",
        dependencies=(SourceColumn("accounts", "active"),),
    )
    with SQLiteQuery(
        database, "SELECT extra(amount) FROM sales WHERE id=1", functions=(function,)
    ) as query:
        query.track_contributors()
        rows = query.execute()
        lineage = query.result_lineage(
            {"sources": [source.to_dict() for source in query.dependencies]}, rows
        )
    assert rows.rows == ((9,),)
    assert lineage["row_support"] == "partial"
    assert any(
        item["table"] == "accounts" and item["column"] == "active" and item["row_key"] is None
        for item in lineage_cells(lineage)[0]["contributors"]
    )


@pytest.mark.parametrize("expression", ["min(amount,id)", "max(amount,id)", "min(amount)"])
def test_sqlite_scalar_and_aggregate_min_max_preserve_cardinality(database, expression):
    sql = f"SELECT {expression} FROM sales ORDER BY id"
    with sqlite3.connect(database) as connection:
        expected = tuple(connection.execute(sql).fetchall())
    _, actual, _ = execute(database, sql)
    assert actual.rows == expected


def test_configured_scalar_override_of_aggregate_name_keeps_scalar_cardinality(database):
    function = SQLFunction("sum", 1, lambda value: value * 2, authority="analysis")
    with SQLiteQuery(
        database, "SELECT sum(amount) FROM sales ORDER BY id", functions=(function,)
    ) as query:
        query.track_contributors()
        rows = query.execute()
    assert rows.rows == ((8,), (8,), (18,), (4,))


def test_window_and_current_row_dependencies_remain_distinct(database):
    _, rows, lineage = execute(
        database,
        "SELECT id + sum(amount) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND 1 PRECEDING) "
        "FROM sales ORDER BY id",
    )
    assert rows.rows == ((None,), (6,), (7,), (13,))
    assert keys(lineage["cells"][1], "sales", "id") == {(1,), (2,)}
    assert keys(lineage["cells"][1], "sales", "amount") == {(1,)}
