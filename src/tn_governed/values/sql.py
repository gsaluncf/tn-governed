"""Read-only SQL gateway with catalog-bound query-result publication.

SQLite determines the accepted query language and source dependencies. Direct
column projections retain their primitive publication format; other queries
produce a governed relation with an indexed schema and the policies assigned to the columns read.
"""

from bisect import bisect_right
from dataclasses import dataclass
from collections.abc import Sequence
import hashlib
from pathlib import Path
import re
from uuid import uuid4

from .collection import pauses_collection
from .metadata import describe
from .numeric_codec import KINDS, encode
from .primitives import MAX_SOURCE_PUBLICATION_CELLS, _PrimitiveHandle
from .query import SQLiteQuery, digest
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


class GovernedRows(Sequence):
    """Ordered admitted field handles; scalar wrappers are created on access."""

    def __init__(self, columns, rows):
        self.columns, self._rows = tuple(columns), rows
        if any(len(row) != len(self.columns) for row in rows):
            raise ValueError("governed row width differs from its columns")

    def __len__(self):
        return len(self._rows)

    @staticmethod
    def _row(row):
        return tuple(value.materialize() if isinstance(value, _PrimitiveHandle) else value
                     for value in row)

    def __getitem__(self, index):
        rows = self._rows[index]
        if isinstance(index, slice):
            return [self._row(row) for row in rows]
        if any(isinstance(value, _PrimitiveHandle) for value in rows):
            rows = self._row(rows)
            self._rows[index] = rows
        return rows

    def handles(self):
        return tuple(value for row in self._rows for value in row)

    def with_row(self, index, row):
        rows = list(self._rows)
        rows[index] = tuple(row)
        return GovernedRows(self.columns, rows)


class ColumnRows(GovernedRows):
    """Admitted source cells held as column batches; a row's wrappers are built only when it is read."""

    def __init__(self, columns, batches, count, overrides=None):
        self.columns, self._count = tuple(columns), count
        self._batches = {column: tuple(batches[column]) for column in self.columns}
        self._starts = {column: [batch.first_row for batch in self._batches[column]] for column in self.columns}
        self._overrides, self._cells = dict(overrides or {}), {}

    def __len__(self):
        return self._count

    def batch(self, row, column):
        batches = self._batches[column]
        return batches[bisect_right(self._starts[column], row) - 1]

    def _cell(self, row, column):
        if (row, column) in self._overrides:
            return self._overrides[row, column]
        if (row, column) not in self._cells:
            batch = self.batch(row, column)
            self._cells[row, column] = batch.handle(row - batch.first_row).materialize()
        return self._cells[row, column]

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[row] for row in range(*index.indices(self._count))]
        if index < 0:
            index += self._count
        if not 0 <= index < self._count:
            raise IndexError("governed row index out of range")
        return tuple(self._cell(index, column) for column in self.columns)

    def handles(self):
        return tuple(self._overrides.get((row, column)) or self.batch(row, column).handle(
                         row - self.batch(row, column).first_row)
                     for row in range(self._count) for column in self.columns)

    def with_row(self, index, row):
        overrides = dict(self._overrides)
        for column, value in zip(self.columns, row, strict=True):
            batch = self.batch(index, column)
            if value.reference != batch.reference(index - batch.first_row):
                overrides[index, column] = value
        return ColumnRows(self.columns, self._batches, self._count, overrides)

    def column_inputs(self):
        """The column batches and the cells that replace batch cells, by (row, column)."""
        return self._batches, dict(self._overrides)


class GovernedCursor:
    def __init__(self, columns, rows):
        self.description = tuple((name, None, None, None, None, None, None) for name in columns)
        self._rows, self._index = rows, 0

    def fetchone(self):
        if self._index == len(self._rows):
            return None
        row = self._rows[self._index]
        self._index += 1
        return GovernedRows._row(row)

    def fetchall(self):
        return list(self.fetch_batches())

    def fetch_batches(self):
        if isinstance(self._rows, ColumnRows) and self._index == 0:
            self._index = len(self._rows)
            return self._rows
        rows = self._rows[self._index:]
        self._index = len(self._rows)
        return GovernedRows([column[0] for column in self.description], rows)


class GovernedSQL:
    def __init__(self, database, *, gateway, consumer, edition_publisher, directory, detect_types=0,
                 batch_size=64, functions=()):
        if type(batch_size) is not int or not 1 <= batch_size <= MAX_SOURCE_PUBLICATION_CELLS:
            raise ValueError(
                f"SQL publication batch size must be between 1 and {MAX_SOURCE_PUBLICATION_CELLS}")
        self.database = Path(database).resolve()
        self.batch_size = batch_size
        self.detect_types = detect_types
        self.functions = tuple(functions)
        self.gateway, self.consumer, self.edition_publisher = gateway, consumer, edition_publisher
        self.directory = Path(directory)
        self.executions, self.editions, self.published_values = [], [], []
        self.published_batches = []
        self.edition_transports = {}

    def table(self, name):
        return TableQuery(self, name)

    @pauses_collection
    def execute(self, sql, parameters=()):
        with SQLiteQuery(self.database, sql, parameters, functions=self.functions,
                         detect_types=self.detect_types) as prepared:
            match = SELECT.fullmatch(sql)
            if match is not None:
                columns = [item.strip() for item in match.group(1).split(",")]
                direct = {(match.group(2), column) for column in columns}
                discovered = {(source.table, source.column) for source in prepared.dependencies}
                if (len(columns) == len(set(columns)) and direct == discovered
                        and all(IDENTIFIER.fullmatch(column) for column in columns)):
                    return self._execute_direct(sql, parameters, prepared)
            return self._execute_query(prepared)

    def execute_query(self, sql, parameters=()):
        """Return a governed relation under the assignments for all columns SQLite reads."""
        with SQLiteQuery(self.database, sql, parameters, functions=self.functions,
                         detect_types=self.detect_types) as prepared:
            return self._execute_query(prepared)

    def _execute_query(self, prepared):
        from .query_result import GovernedQueryResult, publish_result
        gateway = self.gateway
        resolution = gateway.resolver.resolve_query(prepared.dependencies, actor=gateway.actor,
            application=gateway.application, purpose=gateway.purpose, expected_source=prepared.identity)
        query_id = uuid4().hex
        binding = {"schema": "tn.sql-query.v2", "query_id": query_id,
                   "snapshot": prepared.identity, "sources": list(resolution.sources)}
        request = Request(gateway.application, gateway.purpose, "select", (), (),
                          resolution.policies, (), parameters=(binding,))
        decision = gateway._decision(request, query_id)
        try:
            raw = prepared.execute()
            result_binding = {**binding, "output_schema": raw.schema}
            gateway._append("SQLRead", request, query_id, {"decision_id": decision,
                "query_id": query_id, "row_count": len(raw.rows), "source": prepared.identity,
                "assignment_ids": [item.assignment_id for item in resolution.resolutions],
                "binding_id": digest(result_binding)})
            self.executions.append({"query_id": query_id, "rows": len(raw.rows),
                                    "binding_id": digest(result_binding)})
            publication, result_id, binding_id = publish_result(gateway, raw, result_binding,
                request=request, decision_id=decision, query_id=query_id)
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

    def _publish_column(self, contents, *, first_row, kind, policy, request, decision_id, call_id):
        """Encode a SQL column once and hand native references to its receiver."""
        expected_type = SQL_TYPES.get(kind)
        fields, facts = {}, {}
        for index, content in enumerate(contents, first_row):
            if expected_type is None or type(content) is not expected_type:
                raise TypeError("SQL type differs from its signed column assignment")
            field = f"value_{index}"
            fields[field] = encode(content)
            facts[field] = describe(content)
        return self.gateway._source_fields(fields, facts, policy, request, decision_id, call_id,
                                           _handles=True)

    def _direct_columns(self, raw_rows, columns, table, identity, resolution, request, decision, query_id):
        """Publish, register and admit each column of each batch as one object."""
        gateway = self.gateway
        batches, publications = {column: [] for column in columns}, []
        for start in range(0, len(raw_rows), self.batch_size):
            block = raw_rows[start:start + self.batch_size]
            for column_index, column in enumerate(columns):
                contents = [row[column_index] for row in block]
                expected = SQL_TYPES.get(resolution.columns[column]["kind"])
                if expected is None or set(map(type, contents)) != {expected}:
                    raise TypeError("SQL type differs from its signed column assignment")
                policy = resolution.policies[column]
                batch = gateway.originate_column(contents, policy, first_row=start, request=request,
                                                 decision_id=decision, call_id=query_id)
                source = {"table": table, "column": column, "row": start, "query_id": query_id,
                          "assignment_id": resolution.assignment_id,
                          "snapshot_sha256": identity["snapshot_sha256"]}
                publications.append((batch.publication.object, policy, source))
                batches[column].append(batch)
        editions = self.edition_publisher.publish_query_editions(query_id, publications,
            directory=self.directory / query_id, application=self.consumer.application,
            purpose=self.consumer.purpose)
        for info, transport in editions:
            self.consumer.resolver.admit_edition(info, self.consumer, transport=transport)
            self.editions.append(info)
            self.edition_transports[info["record_id"]] = transport
        admitted = iter(self.consumer.admit_columns(batch for start_batches in zip(*batches.values())
                                                    for batch in start_batches))
        ordered = {column: [] for column in columns}
        for start_batches in zip(*batches.values()):
            for column in columns:
                ordered[column].append(next(admitted))
        self.published_batches.extend(batch for column in columns for batch in ordered[column])
        return GovernedCursor(columns, ColumnRows(columns, ordered, len(raw_rows)))

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
                          tuple(resolution.policies.values()), (), parameters=(resolution.assignment_id,))
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
            if (getattr(gateway, "column_batches", False) and getattr(self.consumer, "column_batches", False) and raw_rows
                    and all(resolution.columns[column]["kind"] in ("str", "int") for column in columns)):
                return self._direct_columns(raw_rows, columns, table, identity, resolution, request, decision,
                                            query_id)
            rows = [[None] * len(columns) for _ in raw_rows]
            publications, handles, positions = [], [], []
            for start in range(0, len(raw_rows), self.batch_size):
                batch = raw_rows[start:start + self.batch_size]
                for column_index, column in enumerate(columns):
                    policy = resolution.policies[column]
                    batch_handles = self._publish_column(
                        (row[column_index] for row in batch), first_row=start,
                        kind=resolution.columns[column]["kind"], policy=policy, request=request,
                        decision_id=decision, call_id=query_id)
                    source = {"table": table, "column": column, "row": start,
                              "query_id": query_id, "assignment_id": resolution.assignment_id,
                              "snapshot_sha256": identity["snapshot_sha256"]}
                    publications.append((batch_handles[0][4].object, policy, source))
                    handles.extend(batch_handles)
                    positions.extend((start + offset, column_index) for offset in range(len(batch)))
            if publications:
                editions = self.edition_publisher.publish_query_editions(query_id, publications,
                    directory=self.directory / query_id, application=self.consumer.application,
                    purpose=self.consumer.purpose)
                for info, transport in editions:
                    self.consumer.resolver.admit_edition(info, self.consumer, transport=transport)
                    self.editions.append(info)
                    self.edition_transports[info["record_id"]] = transport
                for position, value in zip(positions, self.consumer.hydrate_many(handles, _lazy=True), strict=True):
                    rows[position[0]][position[1]] = value
                self.published_values.extend(value for row in rows for value in row)
            return GovernedCursor(columns, [tuple(row) for row in rows])
        except Exception as exc:
            gateway._append("Failure", request, query_id,
                             {"decision_id": decision, "error_type": type(exc).__name__})
            raise
