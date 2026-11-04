"""Deterministic TPC-H-shaped data and queries for SQLite.

The schema, cardinalities, and value ranges follow the TPC-H specification. The
generator and query text are derived from it and are not an audited TPC-H
implementation. Dates are ISO strings, and decimal columns use SQLite REAL.
"""

from __future__ import annotations

import random
import sqlite3
from contextlib import closing
from datetime import date, timedelta
from pathlib import Path

REGIONS = ("AFRICA", "AMERICA", "ASIA", "EUROPE", "MIDDLE EAST")
NATIONS = (
    ("ALGERIA", 0), ("ARGENTINA", 1), ("BRAZIL", 1), ("CANADA", 1), ("EGYPT", 4), ("ETHIOPIA", 0),
    ("FRANCE", 3), ("GERMANY", 3), ("INDIA", 2), ("INDONESIA", 2), ("IRAN", 4), ("IRAQ", 4),
    ("JAPAN", 2), ("JORDAN", 4), ("KENYA", 0), ("MOROCCO", 0), ("MOZAMBIQUE", 0), ("PERU", 1),
    ("CHINA", 2), ("ROMANIA", 3), ("SAUDI ARABIA", 4), ("VIETNAM", 2), ("RUSSIA", 3),
    ("UNITED KINGDOM", 3), ("UNITED STATES", 1),
)
SEGMENTS = ("AUTOMOBILE", "BUILDING", "FURNITURE", "HOUSEHOLD", "MACHINERY")
PRIORITIES = ("1-URGENT", "2-HIGH", "3-MEDIUM", "4-NOT SPECIFIED", "5-LOW")
INSTRUCTIONS = ("DELIVER IN PERSON", "COLLECT COD", "NONE", "TAKE BACK RETURN")
MODES = ("REG AIR", "AIR", "RAIL", "SHIP", "TRUCK", "MAIL", "FOB")
TYPES = tuple(f"{a} {b} {c}" for a in ("STANDARD", "SMALL", "MEDIUM", "LARGE", "ECONOMY", "PROMO")
              for b in ("ANODIZED", "BURNISHED", "PLATED", "POLISHED", "BRUSHED")
              for c in ("TIN", "NICKEL", "BRASS", "STEEL", "COPPER"))
CONTAINERS = tuple(f"{a} {b}" for a in ("SM", "LG", "MED", "JUMBO", "WRAP")
                   for b in ("CASE", "BOX", "BAG", "JAR", "PKG", "PACK", "CAN", "DRUM"))
START, CURRENT, DAYS = date(1992, 1, 1), date(1995, 6, 17), 2406

SCHEMA = {
    "region": {"r_regionkey": "int", "r_name": "str"},
    "nation": {"n_nationkey": "int", "n_name": "str", "n_regionkey": "int"},
    "supplier": {"s_suppkey": "int", "s_name": "str", "s_nationkey": "int", "s_acctbal": "float"},
    "customer": {"c_custkey": "int", "c_name": "str", "c_nationkey": "int", "c_acctbal": "float",
                 "c_mktsegment": "str"},
    "part": {"p_partkey": "int", "p_name": "str", "p_brand": "str", "p_type": "str", "p_size": "int",
             "p_container": "str", "p_retailprice": "float"},
    "orders": {"o_orderkey": "int", "o_custkey": "int", "o_orderstatus": "str",
               "o_totalprice": "float", "o_orderdate": "str", "o_orderpriority": "str",
               "o_shippriority": "int"},
    "lineitem": {"l_orderkey": "int", "l_partkey": "int", "l_suppkey": "int",
                 "l_linenumber": "int", "l_quantity": "float", "l_extendedprice": "float",
                 "l_discount": "float", "l_tax": "float", "l_returnflag": "str",
                 "l_linestatus": "str", "l_shipdate": "str", "l_commitdate": "str",
                 "l_receiptdate": "str", "l_shipinstruct": "str", "l_shipmode": "str"},
}
SQL_TYPES = {"int": "INTEGER", "float": "REAL", "str": "TEXT"}

# Query numbers follow TPC-H. Validation parameters are fixed.
QUERIES = {
    "Q1": """SELECT l_returnflag, l_linestatus, sum(l_quantity) AS sum_qty,
        sum(l_extendedprice) AS sum_base, sum(l_extendedprice*(1-l_discount)) AS sum_disc,
        avg(l_discount) AS avg_disc, count(*) AS count_order FROM lineitem
        WHERE l_shipdate <= '1998-09-02' GROUP BY l_returnflag, l_linestatus
        ORDER BY l_returnflag, l_linestatus""",
    "Q3": """SELECT l_orderkey, sum(l_extendedprice*(1-l_discount)) AS revenue, o_orderdate,
        o_shippriority FROM customer JOIN orders ON c_custkey=o_custkey
        JOIN lineitem ON l_orderkey=o_orderkey
        WHERE c_mktsegment='BUILDING' AND o_orderdate<'1995-03-15' AND l_shipdate>'1995-03-15'
        GROUP BY l_orderkey, o_orderdate, o_shippriority
        ORDER BY revenue DESC, o_orderdate LIMIT 10""",
    "Q5": """SELECT n_name, sum(l_extendedprice*(1-l_discount)) AS revenue
        FROM customer JOIN orders ON c_custkey=o_custkey JOIN lineitem ON l_orderkey=o_orderkey
        JOIN supplier ON l_suppkey=s_suppkey JOIN nation ON s_nationkey=n_nationkey
        JOIN region ON n_regionkey=r_regionkey
        WHERE c_nationkey=s_nationkey AND r_name='ASIA'
        AND o_orderdate>='1994-01-01' AND o_orderdate<'1995-01-01'
        GROUP BY n_name ORDER BY revenue DESC""",
    "Q6": """SELECT sum(l_extendedprice*l_discount) AS revenue FROM lineitem
        WHERE l_shipdate>='1994-01-01' AND l_shipdate<'1995-01-01'
        AND l_discount BETWEEN 0.05 AND 0.07 AND l_quantity<24""",
    "Q10": """SELECT c_custkey, c_name, sum(l_extendedprice*(1-l_discount)) AS revenue,
        c_acctbal, n_name FROM customer JOIN orders ON c_custkey=o_custkey
        JOIN lineitem ON l_orderkey=o_orderkey JOIN nation ON c_nationkey=n_nationkey
        WHERE o_orderdate>='1993-10-01' AND o_orderdate<'1994-01-01' AND l_returnflag='R'
        GROUP BY c_custkey, c_name, c_acctbal, n_name ORDER BY revenue DESC LIMIT 20""",
    "Q12": """SELECT l_shipmode,
        sum(CASE WHEN o_orderpriority IN ('1-URGENT','2-HIGH') THEN 1 ELSE 0 END) AS high_line,
        sum(CASE WHEN o_orderpriority NOT IN ('1-URGENT','2-HIGH') THEN 1 ELSE 0 END) AS low_line
        FROM orders JOIN lineitem ON o_orderkey=l_orderkey
        WHERE l_shipmode IN ('MAIL','SHIP') AND l_commitdate<l_receiptdate
        AND l_shipdate<l_commitdate AND l_receiptdate>='1994-01-01' AND l_receiptdate<'1995-01-01'
        GROUP BY l_shipmode ORDER BY l_shipmode""",
    "Q14": """SELECT 100.0*sum(CASE WHEN p_type LIKE 'PROMO%'
        THEN l_extendedprice*(1-l_discount) ELSE 0 END)
        / sum(l_extendedprice*(1-l_discount)) AS promo_revenue
        FROM lineitem JOIN part ON l_partkey=p_partkey
        WHERE l_shipdate>='1995-09-01' AND l_shipdate<'1995-10-01'""",
    "Q19": """SELECT sum(l_extendedprice*(1-l_discount)) AS revenue
        FROM lineitem JOIN part ON p_partkey=l_partkey
        WHERE p_size BETWEEN 1 AND 15 AND l_shipmode IN ('AIR','REG AIR')
        AND l_shipinstruct='DELIVER IN PERSON' AND l_quantity BETWEEN 1 AND 30""",
}


def _day(offset):
    return (START + timedelta(days=offset)).isoformat()


def _lineitems(generator, order, order_day, parts, suppliers):
    rows, status = [], set()
    for line in range(1, generator.randint(1, 7) + 1):
        partkey, quantity = generator.randint(1, parts), float(generator.randint(1, 50))
        retail = (90000 + (partkey // 10) % 20001 + 100 * (partkey % 1000)) / 100
        ship = order_day + generator.randint(1, 121)
        commit = order_day + generator.randint(30, 90)
        receipt = ship + generator.randint(1, 30)
        flag = generator.choice("RA") if _day(receipt) <= CURRENT.isoformat() else "N"
        line_status = "O" if _day(ship) > CURRENT.isoformat() else "F"
        status.add(line_status)
        rows.append((order, partkey, generator.randint(1, suppliers), line, quantity,
                     round(quantity * retail, 2), generator.randint(0, 10) / 100,
                     generator.randint(0, 8) / 100, flag, line_status, _day(ship), _day(commit),
                     _day(receipt), generator.choice(INSTRUCTIONS), generator.choice(MODES)))
    return rows, ("F" if status == {"F"} else "O" if status == {"O"} else "P")


def _create(connection):
    for table, columns in SCHEMA.items():
        names = ", ".join(f"{name} {SQL_TYPES[kind]}" for name, kind in columns.items())
        connection.execute(f"CREATE TABLE {table} ({names})")


def _insert(connection, table, rows):
    marks = ", ".join("?" * len(SCHEMA[table]))
    connection.executemany(f"INSERT INTO {table} VALUES ({marks})", rows)


def _dimensions(connection, generator, scale):
    suppliers = max(1, round(10_000 * scale))
    customers = max(1, round(150_000 * scale))
    parts = max(1, round(200_000 * scale))
    _insert(connection, "region", enumerate(REGIONS))
    _insert(connection, "nation", ((i, name, region) for i, (name, region) in enumerate(NATIONS)))
    _insert(connection, "supplier", ((key, f"Supplier#{key:09d}", generator.randint(0, 24),
             round(generator.uniform(-999.99, 9999.99), 2)) for key in range(1, suppliers + 1)))
    _insert(connection, "customer", ((key, f"Customer#{key:09d}", generator.randint(0, 24),
             round(generator.uniform(-999.99, 9999.99), 2), generator.choice(SEGMENTS))
             for key in range(1, customers + 1)))
    _insert(connection, "part", ((key, f"part {key}", f"Brand#{generator.randint(1, 5)}"
             f"{generator.randint(1, 5)}", generator.choice(TYPES), generator.randint(1, 50),
             generator.choice(CONTAINERS), (90000 + (key // 10) % 20001 + 100 * (key % 1000)) / 100)
             for key in range(1, parts + 1)))
    return suppliers, customers, parts


def generate(path, scale, *, seed=20261102):
    """Create one SQLite database at the requested scale factor."""
    path = Path(path)
    generator = random.Random(seed)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA synchronous=OFF")
        _create(connection)
        suppliers, customers, parts = _dimensions(connection, generator, scale)
        orders, items = [], []
        for index in range(1, max(1, round(1_500_000 * scale)) + 1):
            order_day = generator.randint(0, DAYS)
            rows, status = _lineitems(generator, index * 4, order_day, parts, suppliers)
            total = round(sum(row[5] for row in rows), 2)
            orders.append((index * 4, generator.randint(1, customers), status, total,
                           _day(order_day), generator.choice(PRIORITIES), 0))
            items.extend(rows)
            if len(orders) >= 50_000:
                _insert(connection, "orders", orders)
                _insert(connection, "lineitem", items)
                orders, items = [], []
        _insert(connection, "orders", orders)
        _insert(connection, "lineitem", items)
        for statement in ("CREATE INDEX i_orders_key ON orders(o_orderkey)",
                          "CREATE INDEX i_orders_customer ON orders(o_custkey)",
                          "CREATE INDEX i_line_order ON lineitem(l_orderkey)",
                          "CREATE INDEX i_line_part ON lineitem(l_partkey)",
                          "CREATE INDEX i_line_supplier ON lineitem(l_suppkey)",
                          "CREATE INDEX i_customer_key ON customer(c_custkey)",
                          "CREATE INDEX i_part_key ON part(p_partkey)",
                          "CREATE INDEX i_supplier_key ON supplier(s_suppkey)",
                          "CREATE INDEX i_nation_key ON nation(n_nationkey)",
                          "CREATE INDEX i_region_key ON region(r_regionkey)"):
            connection.execute(statement)
        connection.commit()
        connection.execute("ANALYZE")
        connection.commit()
        connection.execute("PRAGMA journal_mode=DELETE")
    return path
