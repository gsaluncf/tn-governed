"""SQLite executes the original query after resolving its read-column policies."""

import sqlite3

import pytest

from tn_governed.values.query import (
    SourceColumn,
    SQLFunction,
    SQLiteQuery,
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
        return query.execute(), {(source.table, source.column) for source in query.dependencies}


def test_join_expression_retains_all_read_assignments(database):
    rows, sources = execute(
        database,
        """
        SELECT s.amount * :factor AS total, a.label
        FROM sales s JOIN accounts a ON s.account=a.id
        WHERE a.active=:active ORDER BY s.id,a.rowid
    """,
        {"factor": 3, "active": 1},
    )
    assert rows.rows == ((12, "A"),) * 4
    assert {("accounts","active"), ("accounts","id"), ("sales","account"), ("sales","amount")} <= sources


def test_filtered_group_aggregation_preserves_values(database):
    rows, sources = execute(
        database,
        """
        SELECT account, sum(amount) AS total FROM sales
        WHERE amount < ? GROUP BY account ORDER BY account
    """,
        (9,),
    )
    assert rows.rows == ((10, 8), (99, 2))


def test_window_frame_uses_its_actual_partition_and_frame(database):
    rows, sources = execute(
        database,
        """
        SELECT id, sum(amount) OVER (
            PARTITION BY account ORDER BY id ROWS BETWEEN 1 PRECEDING AND CURRENT ROW
        ) AS rolling FROM sales ORDER BY id
    """,
    )
    assert rows.rows == ((1, 4), (2, 8), (3, 9), (4, 2))


def test_outer_join_preserves_missing_side(database):
    rows, sources = execute(
        database,
        """
        SELECT s.id,a.label FROM sales s LEFT JOIN accounts a ON s.account=a.id
        WHERE s.id=4
    """,
    )
    assert rows.rows == ((4, None),)


def test_empty_result_retains_selection_dependencies(database):
    rows, sources = execute(database, "SELECT amount FROM sales WHERE id < 0")
    assert rows.rows == ()
    assert ("sales", "id") in sources


def test_distinct_uses_declared_snapshot_scope_without_changing_cardinality(database):
    rows, sources = execute(database, "SELECT DISTINCT amount FROM sales ORDER BY amount")
    assert rows.rows == ((2,), (4,), (9,))


def test_composite_primary_keys_in_without_rowid_tables(tmp_path):
    path = tmp_path / "keys.sqlite"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE positions(account TEXT, day INTEGER, amount INTEGER,
                PRIMARY KEY(account,day)) WITHOUT ROWID;
            INSERT INTO positions VALUES ('a',1,4),('a',2,7);
        """)
    rows, sources = execute(path, "SELECT amount FROM positions WHERE day=2")
    assert rows.rows == ((7,),)


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
def test_authorized_query_preserves_sqlite_shapes(database, sql):
    with sqlite3.connect(database) as connection:
        expected = tuple(connection.execute(sql).fetchall())
    actual, sources = execute(database, sql)
    assert actual.rows == expected


def test_business_udf_executes_once_per_result_not_once_per_lineage_pass(database):
    calls = []
    function = SQLFunction(
        "observe", 1, lambda value: calls.append(value) or value, authority="application:analysis"
    )
    with SQLiteQuery(
        database, "SELECT observe(amount) FROM sales ORDER BY id", functions=(function,)
    ) as query:
        assert calls == []
        rows = query.execute()
    assert rows.rows == ((4,), (4,), (9,), (2,))
    assert calls == [4, 4, 9, 2]


def test_copied_window_parameters_keep_their_original_bindings(database):
    result, _ = execute(
        database,
        """
        SELECT id, sum(amount * ?) OVER (ORDER BY id ROWS BETWEEN ? PRECEDING AND CURRENT ROW)
        FROM sales WHERE id <= ? ORDER BY id
    """,
        (2, 1, 3),
    )
    assert result.rows == ((1, 8), (2, 16), (3, 26))


def test_projection_alias_precedence_does_not_substitute_a_source_column(database):
    result, sources = execute(database, "SELECT amount * -1 AS id FROM sales ORDER BY id")
    assert result.rows == ((-9,), (-4,), (-4,), (-2,))


def test_private_projection_names_do_not_change_ordering(database):
    sql = "SELECT amount AS __tn_lineage_0 FROM sales ORDER BY __tn_lineage_0"
    result, _ = execute(database, sql)
    assert result.rows == ((2,), (4,), (4,), (9,))


def test_function_external_dependencies_require_source_assignments(database):
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
        rows = query.execute()
        sources = {(source.table, source.column) for source in query.dependencies}
    assert rows.rows == ((9,),)
    assert ("accounts", "active") in sources


@pytest.mark.parametrize("expression", ["min(amount,id)", "max(amount,id)", "min(amount)"])
def test_sqlite_scalar_and_aggregate_min_max_preserve_cardinality(database, expression):
    sql = f"SELECT {expression} FROM sales ORDER BY id"
    with sqlite3.connect(database) as connection:
        expected = tuple(connection.execute(sql).fetchall())
    actual, _ = execute(database, sql)
    assert actual.rows == expected


def test_configured_scalar_override_of_aggregate_name_keeps_scalar_cardinality(database):
    function = SQLFunction("sum", 1, lambda value: value * 2, authority="analysis")
    with SQLiteQuery(
        database, "SELECT sum(amount) FROM sales ORDER BY id", functions=(function,)
    ) as query:
        rows = query.execute()
    assert rows.rows == ((8,), (8,), (18,), (4,))


def test_window_and_current_row_dependencies_remain_distinct(database):
    rows, sources = execute(
        database,
        "SELECT id + sum(amount) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND 1 PRECEDING) "
        "FROM sales ORDER BY id",
    )
    assert rows.rows == ((None,), (6,), (7,), (13,))
