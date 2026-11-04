"""Read-only SQL gateway with catalog-bound query-result publication.

SQLite determines the accepted query language and source dependencies. Direct
column projections retain their primitive publication format; other queries
produce a governed relation with an indexed schema and explicit lineage fidelity.
"""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import sqlite3
from uuid import uuid4

from .collection import pauses_collection
from .numeric_codec import KINDS
from .primitives import MAX_SOURCE_PUBLICATION_CELLS
from .query import SQLiteQuery, contributor_manifest, digest, encode_sql
from .runtime import Request

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SELECT = re.compile(r"^\s*select\s+([A-Za-z0-9_,\s]+)\s+from\s+([A-Za-z_][A-Za-z0-9_]*)"
                    r"(?:\s+limit\s+(\?|[0-9]+))?\s*;?\s*$", re.I)
SQL_TYPES = {"str": str, **KINDS}


def source_identity(path):
    path = Path(path).resolve()
    with path.open("rb") as stream:
        snapshot_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"kind": "sqlite", "location": path.as_uri(),
            "snapshot_sha256": snapshot_sha256}


@dataclass
class QueryResponse:
    data: list[dict]


class TableQuery:
    def __init__(self, driver, table):
        if not IDENTIFIER.fullmatch(table):
            raise ValueError("invalid table identifier")
        self.driver, self.table_name = driver, table
        self.columns, self.row_limit = None, 1

    def select(self, columns):
        names = [name.strip() for name in columns.split(",")]
        if not names or any(not IDENTIFIER.fullmatch(name) for name in names):
            raise ValueError("select requires direct column names")
        self.columns = names
        return self

    def limit(self, count):
        if type(count) is not int or count < 0:
            raise ValueError("limit requires a nonnegative ordinary integer")
        self.row_limit = count
        return self

    def execute(self):
        if self.columns is None:
            raise ValueError("select columns before executing")
        cursor = self.driver.execute(
            f"SELECT {', '.join(self.columns)} FROM {self.table_name} LIMIT ?", (self.row_limit,))
        return QueryResponse([dict(zip(self.columns, row, strict=True)) for row in cursor.fetchall()])


class GovernedCursor:
    def __init__(self, columns, rows):
        self.description = tuple((name, None, None, None, None, None, None) for name in columns)
        self._rows, self._index = rows, 0

    def fetchone(self):
        if self._index == len(self._rows):
            return None
        row = self._rows[self._index]
        self._index += 1
        return row

    def fetchall(self):
        rows = self._rows[self._index:]
        self._index = len(self._rows)
        return rows


class GovernedSQL:
    def __init__(self, database, *, gateway, consumer, edition_publisher, directory, detect_types=0,
                 batch_size=64, functions=(), lineage_provider=None):
        if type(batch_size) is not int or not 1 <= batch_size <= MAX_SOURCE_PUBLICATION_CELLS:
            raise ValueError(
                f"SQL publication batch size must be between 1 and {MAX_SOURCE_PUBLICATION_CELLS}")
        self.database = Path(database).resolve()
        self.batch_size = batch_size
        self.detect_types = detect_types
        self.functions, self.lineage_provider = tuple(functions), lineage_provider
        self.gateway, self.consumer, self.edition_publisher = gateway, consumer, edition_publisher
        self.directory = Path(directory)
        self.executions, self.editions, self.published_values = [], [], []
        self.edition_transports = {}

    def table(self, name):
        return TableQuery(self, name)

    @pauses_collection
    def execute(self, sql, parameters=()):
        with SQLiteQuery(self.database, sql, parameters, functions=self.functions,
                         detect_types=self.detect_types) as prepared:
            match = SELECT.fullmatch(sql)
            if match is not None and self.lineage_provider is None:
                columns = [item.strip() for item in match.group(1).split(",")]
                direct = {(match.group(2), column) for column in columns}
                discovered = {(source.table, source.column) for source in prepared.dependencies}
                if (len(columns) == len(set(columns)) and direct == discovered
                        and all(IDENTIFIER.fullmatch(column) for column in columns)):
                    return self._execute_direct(sql, parameters, prepared)
            return self._execute_query(prepared)

    def execute_query(self, sql, parameters=(), *, contributor_tracking=True):
        """Return a governed relation for any authorized read-only SQLite query.

        Without contributor tracking the result records its authorized source
        columns and unknown row support; a recipient that requires row support
        refuses it under its own evidence rule.
        """
        with SQLiteQuery(self.database, sql, parameters, functions=self.functions,
                         detect_types=self.detect_types) as prepared:
            return self._execute_query(prepared, contributor_tracking)

    def _execute_query(self, prepared, contributor_tracking=True):
        from .query_result import GovernedQueryResult, publish_result
        gateway = self.gateway
        plan = None
        if self.lineage_provider is None:
            plan = (prepared.track_contributors() if contributor_tracking
                    else prepared.track_source_scope())
        resolution = gateway.resolver.resolve_query(prepared.dependencies, actor=gateway.actor,
            application=gateway.application, purpose=gateway.purpose, expected_source=prepared.identity)
        provider = self.lineage_provider
        query_id = uuid4().hex
        binding = {"schema": "tn.sql-query.v1", "query_id": query_id, "sql": prepared.sql,
                   "parameters": prepared.parameter_binding, "snapshot": prepared.identity,
                   "sources": list(resolution.sources), "engine": "sqlite",
                   "engine_version": sqlite3.sqlite_version,
                   "functions": [function.to_dict() for function in prepared.used_functions],
                   "lineage_provider": plan.identifier if provider is None else provider.identifier,
                   "lineage_precision": "conservative" if provider is None else provider.precision}
        if plan is not None:
            binding["lineage_execution"] = {"schema": "tn.sqlite-lineage.v1",
                "statement": plan.sql or prepared.sql,
                "parameter_binding": {key: encode_sql(value)
                                      for key, value in plan.parameters.items()}
                                     if isinstance(plan.parameters, dict) else prepared.parameter_binding}
        request = Request(gateway.application, gateway.purpose, "select", (), (),
                          resolution.policies, (), parameters=(binding,))
        decision = gateway._decision(request, query_id)
        try:
            raw = prepared.execute()
            result_binding = {**binding, "output_schema": raw.schema}
            lineage = (prepared.result_lineage(result_binding, raw) if provider is None
                       else contributor_manifest(result_binding, raw, provider))
            gateway._append("SQLRead", request, query_id, {"decision_id": decision,
                "query_id": query_id, "row_count": len(raw.rows), "source": prepared.identity,
                "assignment_ids": [item.assignment_id for item in resolution.resolutions],
                "binding_id": digest(result_binding)})
            self.executions.append({"query_id": query_id, "rows": len(raw.rows),
                                    "binding_id": digest(result_binding)})
            publication, result_id, binding_id = publish_result(gateway, raw, result_binding,
                lineage, request=request, decision_id=decision, query_id=query_id)
            info, transport = self.edition_publisher.publish_result_edition(publication, resolution,
                query_id=query_id, binding_id=binding_id, directory=self.directory / query_id,
                application=self.consumer.application, purpose=self.consumer.purpose)
            result = GovernedQueryResult(self.consumer, object_id=publication.id, decision_id=decision,
                result_id=result_id, resolution=resolution, source=prepared.identity,
                edition=info, transport=transport)
            prepared._assert_snapshot()
            self.editions.append(info)
            return result
        except Exception as exc:
            gateway._append("Failure", request, query_id,
                            {"decision_id": decision, "error_type": type(exc).__name__})
            raise

    def _execute_direct(self, sql, parameters, prepared):
        match = SELECT.fullmatch(sql)
        columns, table, limit = match.groups()
        columns = [item.strip() for item in columns.split(",")]
        if len(set(columns)) != len(columns) or any(not IDENTIFIER.fullmatch(item) for item in columns):
            raise ValueError("invalid or duplicated projection columns")
        if limit == "?":
            if len(parameters) != 1 or type(parameters[0]) is not int or parameters[0] < 0:
                raise ValueError("LIMIT ? requires one nonnegative integer")
        elif parameters:
            raise ValueError("no parameters are accepted without LIMIT ?")
        identity = prepared.identity
        gateway = self.gateway
        resolution = gateway.resolver.resolve(table, columns, actor=gateway.actor,
            application=gateway.application, purpose=gateway.purpose, expected_source=identity)
        query_id = uuid4().hex
        request = Request(gateway.application, gateway.purpose, "select", (), (),
                          tuple(resolution.policies.values()), (), parameters=(sql, list(parameters), resolution.assignment_id))
        decision = gateway._decision(request, query_id)
        try:
            raw_rows = prepared.execute().rows
            gateway._append("SQLRead", request, query_id, {"decision_id": decision,
                "query_id": query_id, "row_count": len(raw_rows), "source": identity,
                "assignment_id": resolution.assignment_id})
            self.executions.append({"query_id": query_id, "rows": len(raw_rows),
                                    "assignment_id": resolution.assignment_id})
            self.consumer.resolver.resolve(table, columns, actor=self.consumer.actor,
                application=self.consumer.application, purpose=self.consumer.purpose, expected_source=identity,
                packet=resolution.packet)
            rows = [[None] * len(columns) for _ in raw_rows]
            publications, handles, positions = [], [], []
            for start in range(0, len(raw_rows), self.batch_size):
                for column_index, column in enumerate(columns):
                    cells = []
                    for index in range(start, min(start + self.batch_size, len(raw_rows))):
                        content = raw_rows[index][column_index]
                        assigned_kind = resolution.columns[column]["kind"]
                        if assigned_kind not in SQL_TYPES or type(content) is not SQL_TYPES[assigned_kind]:
                            raise TypeError("SQL type differs from its signed column assignment")
                        source = {"table": table, "column": column, "row": index,
                              "query_id": query_id, "assignment_id": resolution.assignment_id,
                              "snapshot_sha256": identity["snapshot_sha256"]}
                        cells.append((content, source))
                    policy = resolution.policies[column]
                    values = gateway.originate_batch(cells, policy, request=request,
                                                      decision_id=decision, call_id=query_id)
                    publications.append((values[0], policy, cells[0][1]))
                    for value, (content, source) in zip(values, cells, strict=True):
                        handles.append((value.reference, value.decision_id, value.result_id,
                                        type(content).__name__, value.publication))
                        positions.append((source["row"], column_index))
            if publications:
                editions = self.edition_publisher.publish_query_editions(query_id, publications,
                    directory=self.directory / query_id, application=self.consumer.application,
                    purpose=self.consumer.purpose)
                for info, transport in editions:
                    self.consumer.resolver.admit_edition(info, self.consumer, transport=transport)
                    self.editions.append(info)
                    self.edition_transports[info["record_id"]] = transport
                for position, value in zip(positions, self.consumer.hydrate_many(handles), strict=True):
                    rows[position[0]][position[1]] = value
                self.published_values.extend(value for row in rows for value in row)
            return GovernedCursor(columns, [tuple(row) for row in rows])
        except Exception as exc:
            gateway._append("Failure", request, query_id,
                             {"decision_id": decision, "error_type": type(exc).__name__})
            raise
