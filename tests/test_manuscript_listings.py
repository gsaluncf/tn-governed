"""The relational listings in the manuscript run as written and match ordinary engines."""

import sqlite3
from contextlib import ExitStack, closing

import polars as pl
import tn_polars

from experiments.paper_evaluation.relation_study import USE, build_endpoint, evaluators_for

TABLES = {
    "companies": {"id": "int", "name": "str", "region": "str", "active": "int"},
    "market": {"company_id": "int", "amount": "int"},
}
QUERY = ("SELECT a.id AS company_id, a.name, a.region, "
         "b.amount * :rate AS amount "
         "FROM companies a JOIN market b "
         "ON a.id = b.company_id "
         "WHERE a.active = 1 AND b.amount > 0")


def regional_shares(frame):
    return (frame.group_by("region", "company_id", "name")
            .agg(pl.col("amount").sum().alias("company_total"))
            .with_columns(pl.col("company_total").sum()
                          .over("region").alias("region_total"))
            .with_columns((pl.col("company_total") /
                           pl.col("region_total")).alias("share"))
            .sort(["region", "company_total"])
            .select("name", "region", "share"))


def source_database(path):
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript("""
            CREATE TABLE companies (id INTEGER, name TEXT, region TEXT, active INTEGER);
            CREATE TABLE market (company_id INTEGER, amount INTEGER);
            INSERT INTO companies VALUES (1,'Acme','east',1),(2,'Acme','west',1),
                (3,'Birch','east',1),(4,'Cedar','east',0);
            INSERT INTO market VALUES (1,10),(1,5),(2,8),(3,25),(4,99),(3,-4);
        """)
        connection.commit()
    return path


def test_join_and_regional_share_listings_retain_sources_and_match_polars(tmp_path):
    database = source_database(tmp_path / "market.sqlite")
    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute(QUERY, {"rate": 2}).fetchall()
    plain = pl.DataFrame(rows, schema=["company_id", "name", "region", "amount"], orient="row")
    with ExitStack() as stack:
        driver, _ = build_endpoint(stack, tmp_path, database, TABLES)
        result = driver.execute_query(QUERY, {"rate": 2})
        admitted = result.open_for_processing("select", "reporting-service")
        frame = tn_polars.from_admitted_query(
            admitted, use=USE, evaluators=evaluators_for(admitted.data.policies))
        analysis = regional_shares(frame)
        publication = analysis.release_tn(use=USE, to="internal", decide=lambda _: True)
        session = result.context.session
        audit = tn_polars.open_audited_frame(publication, session=session, use=USE, group="values",
                                             decide=lambda _: True)
        opened = session.receive(publication, use=USE, groups=["values"], decide=lambda _: True)
        released = opened.get("rows", group="values")
        sources = {(item["table"], item["column"])
                   for item in result.metadata()["binding"]["sources"]}
    assert released == regional_shares(plain.lazy()).collect().to_dicts()
    assert {("companies", "active"), ("market", "company_id"), ("market", "amount")} <= sources
    assert set(audit["policies"]) == set(frame._tn.policies.revision_ids)
    assert "inputs" not in audit and "events" not in audit
