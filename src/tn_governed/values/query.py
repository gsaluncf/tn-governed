"""SQLite query preparation, snapshot binding, and contributor contracts.

SQLite's authorizer reports reads during statement compilation. EXPLAIN compiles
the statement without executing its expressions or user functions. Read columns
are a conservative dependency set: they include value and control inputs, but
do not establish the source rows contributing to a particular result position.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .numeric_codec import KINDS, NUMERIC_TYPES, decode, encode
from .string import OperationDenied


def digest(value):
    wire = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(wire.encode("ascii")).hexdigest()


def encode_sql(value):
    """Preserve SQL storage types, including NULL and binary values, exactly."""
    if value is None:
        return {"kind": "null", "value": None}
    if type(value) is bytes:
        return {"kind": "bytes", "value": value.hex()}
    if type(value) not in (str, *NUMERIC_TYPES):
        raise TypeError("SQL values require NULL, text, bytes, or supported exact numeric types")
    return {"kind": type(value).__name__, "value": encode(value)}


def decode_sql(value):
    if not isinstance(value, dict) or set(value) != {"kind", "value"}:
        raise ValueError("invalid SQL value encoding")
    kind, payload = value["kind"], value["value"]
    if kind == "null" and payload is None:
        return None
    if kind == "bytes" and isinstance(payload, str):
        return bytes.fromhex(payload)
    if kind in {"str", *KINDS}:
        try:
            return decode(payload, kind)
        except (TypeError, ValueError, ArithmeticError, struct.error) as exc:
            raise ValueError("invalid SQL typed value encoding") from exc
    raise ValueError("invalid SQL value type")


@dataclass(frozen=True, order=True)
class SourceColumn:
    table: str
    column: str
    database: str = "main"

    def to_dict(self):
        return {"database": self.database, "table": self.table, "column": self.column}


@dataclass(frozen=True)
class SQLFunction:
    """An endpoint-trusted function and its declared additional data dependencies.

    Registration authorizes its implementation to execute after the query permit.
    The authority string identifies that configuration in the signed binding;
    it is not itself a signature or an independently verified function identity.
    """

    name: str
    arity: int
    callback: Callable
    authority: str
    dependencies: tuple[SourceColumn, ...] = ()
    deterministic: bool = False

    def __post_init__(self):
        if (
            not isinstance(self.name, str)
            or not self.name.strip()
            or self.name.lower() == "load_extension"
            or self.name.lower().startswith("__tn_")
            or type(self.arity) is not int
            or not -1 <= self.arity <= 127
            or not callable(self.callback)
            or not isinstance(self.authority, str)
            or not self.authority.strip()
            or type(self.deterministic) is not bool
            or not isinstance(self.dependencies, tuple)
            or any(not isinstance(item, SourceColumn) for item in self.dependencies)
        ):
            raise ValueError("SQL function requires an explicit trusted registration")

    def to_dict(self):
        return {
            "name": self.name.lower(),
            "arity": self.arity,
            "authority": self.authority,
            "deterministic": self.deterministic,
            "dependencies": [source.to_dict() for source in self.dependencies],
        }


@dataclass(frozen=True)
class QueryRows:
    columns: tuple[str, ...]
    rows: tuple[tuple, ...]

    @property
    def schema(self):
        return [
            {
                "position": index,
                "name": name,
                "storage_types": sorted({encode_sql(row[index])["kind"] for row in self.rows}),
            }
            for index, name in enumerate(self.columns)
        ]


class SQLiteQuery:
    """One read transaction, prepared before authorization and executed afterwards.

    Assignments hash the main database file. WAL contents require a separate
    snapshot contract and are refused here. The read transaction prevents a
    rollback-journal writer from committing between preparation and execution.
    The authorizer is also active during execution, including SQLite reprepares.
    """

    def __init__(self, database, sql, parameters=(), *, functions=(), detect_types=0):
        if not isinstance(sql, str) or not sql.strip():
            raise ValueError("query requires SQL text")
        if isinstance(parameters, Mapping):
            if any(not isinstance(key, str) for key in parameters):
                raise TypeError("named SQL parameters require string keys")
            self.parameters = dict(parameters)
            self.parameter_binding = {key: encode_sql(value) for key, value in parameters.items()}
        else:
            if not isinstance(parameters, (tuple, list)):
                raise TypeError("SQL parameters require a sequence or mapping")
            self.parameters = tuple(parameters)
            self.parameter_binding = [encode_sql(value) for value in parameters]
        self.database, self.sql = Path(database).resolve(), sql
        self.functions, self.detect_types = tuple(functions), detect_types
        if any(not isinstance(function, SQLFunction) for function in self.functions):
            raise TypeError("SQL functions require trusted registrations")
        if len({(f.name.lower(), f.arity) for f in self.functions}) != len(self.functions):
            raise ValueError("duplicate SQL function registration")
        self.connection = None
        self.dependencies = ()
        self.used_functions = ()
        self._reads, self._function_names = set(), set()
        self._origin_scopes = set()
        self._executed = False
        self._lineage_plan = None

    def _file_fingerprint(self):
        status = Path(self.database).stat()
        return status.st_size, status.st_mtime_ns

    def _assert_snapshot(self, *, full=False):
        """Check the signed snapshot; file metadata suffices between full hashes."""
        wal = Path(str(self.database) + "-wal")
        if wal.exists() and wal.stat().st_size:
            raise OperationDenied("SQL WAL content is outside the signed database-file snapshot")
        from .sql import source_identity

        if not full and self._file_fingerprint() == self._fingerprint:
            return
        if source_identity(self.database) != self.identity:
            raise OperationDenied("SQL source changed since its signed governance assignment")

    def __enter__(self):
        from .sql import source_identity

        self._fingerprint = self._file_fingerprint()
        self.identity = source_identity(self.database)
        self._assert_snapshot()
        try:
            self.connection = sqlite3.connect(
                self.database.as_uri() + "?mode=ro",
                uri=True,
                detect_types=self.detect_types,
                cached_statements=0,
            )
            self.connection.execute("PRAGMA query_only = ON")
            self.connection.execute("PRAGMA trusted_schema = OFF")
            self.connection.execute("BEGIN")
            self._builtin_functions = {
                row[0].lower()
                for row in self.connection.execute("PRAGMA function_list")
                if row[1] == 1
            }
            # Reading the schema pins the transaction without reading business rows.
            self.connection.execute("SELECT name FROM sqlite_schema").fetchall()
            self._assert_snapshot()
            for function in self.functions:
                self.connection.create_function(
                    function.name,
                    function.arity,
                    function.callback,
                    deterministic=function.deterministic,
                )
            self.connection.set_authorizer(self._authorize)
            self.connection.execute("EXPLAIN " + self.sql, self.parameters).fetchall()
            self.connection.set_authorizer(None)
            from sqlglot import tokenize
            from sqlglot.errors import TokenError

            try:
                implicit_matching = any(
                    token.token_type.name in {"USING", "NATURAL"}
                    for token in tokenize(self.sql, read="sqlite")
                )
            except TokenError:
                implicit_matching = True
            dependencies = set()
            for table, column, database in self._reads:
                if database is None and column == "":
                    database = "main"
                if database != "main" or table.startswith("sqlite_"):
                    raise OperationDenied("query reads a source outside the enrolled database")
                fields = self._columns(table)
                # SQLite omits right-hand USING/NATURAL key reads from its
                # authorizer callbacks. Views can contain those joins too.
                if implicit_matching or self._origin_scopes:
                    dependencies.update(SourceColumn(table, field) for field in fields)
                if not column or column.lower() in {"rowid", "_rowid_", "oid"} - set(fields):
                    dependencies.update(SourceColumn(table, field) for field in fields)
                elif column in fields:
                    dependencies.add(SourceColumn(table, column))
                else:
                    raise OperationDenied("query source column is absent from its schema")
            self.used_functions = tuple(
                function
                for function in self.functions
                if function.name.lower() in self._function_names
            )
            for function in self.used_functions:
                for source in function.dependencies:
                    if source.database != "main" or source.column not in self._columns(
                        source.table
                    ):
                        raise OperationDenied(
                            "SQL function dependency is outside the enrolled schema"
                        )
                    dependencies.add(source)
            if not dependencies:
                raise OperationDenied("SQL query has no assigned source dependencies")
            self.dependencies = tuple(sorted(dependencies))
            self.connection.set_authorizer(self._authorize_execution)
            self._assert_snapshot()
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def _columns(self, table):
        return tuple(row[1] for row in self._table_info(table))

    def _table_info(self, table):
        quoted = '"' + table.replace('"', '""') + '"'
        return tuple(self.connection.execute(f"PRAGMA main.table_xinfo({quoted})"))

    def track_contributors(self):
        """Prepare private identity projections before source authorization."""
        from .sql_lineage import SQLiteLineagePlan, _key

        if self.connection is None or self._executed or self._lineage_plan is not None:
            raise RuntimeError("lineage is prepared once before query execution")
        self.connection.set_authorizer(None)
        prior_reads, prior_functions = set(self._reads), set(self._function_names)
        try:
            plan = SQLiteLineagePlan.prepare(self)
            if plan.sql is not None:
                self.connection.create_function("__tn_row_key", -1, _key, deterministic=True)
                self._builtin_functions.add("__tn_row_key")
                self.connection.set_authorizer(self._authorize)
                self.connection.execute("EXPLAIN " + plan.sql, plan.parameters).fetchall()
                self.dependencies = tuple(
                    sorted(set(self.dependencies) | set(plan.additional_sources))
                )
            self._lineage_plan = plan
        except sqlite3.Error:
            self._reads, self._function_names = prior_reads, prior_functions
            self._lineage_plan = SQLiteLineagePlan(reason="unsupported-identity-projection")
        finally:
            self.connection.set_authorizer(self._authorize_execution)
        self._assert_snapshot()
        return self._lineage_plan

    def track_source_scope(self):
        """Retain authorized source columns without row identity projections."""
        from .sql_lineage import SQLiteLineagePlan

        if self.connection is None or self._executed or self._lineage_plan is not None:
            raise RuntimeError("lineage is prepared once before query execution")
        self._lineage_plan = SQLiteLineagePlan(reason="source-scope-requested")
        return self._lineage_plan

    def result_lineage(self, binding, result):
        if self._lineage_plan is None:
            return contributor_manifest(binding, result)
        return self._lineage_plan.manifest(binding, result)

    def _authorize(self, action, first, second, database, trigger):
        if action == sqlite3.SQLITE_READ:
            self._reads.add((first, second, database))
            if trigger is not None:
                self._origin_scopes.add(trigger)
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION:
            name = (second or first or "").lower()
            configured = {function.name.lower() for function in self.functions}
            if name == "load_extension" or name not in self._builtin_functions | configured:
                return sqlite3.SQLITE_DENY
            self._function_names.add(name)
            return sqlite3.SQLITE_OK
        if action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_RECURSIVE}:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    def _authorize_execution(self, action, first, second, database, trigger):
        if action == sqlite3.SQLITE_READ and (first, second, database) not in self._reads:
            return sqlite3.SQLITE_DENY
        if (
            action == sqlite3.SQLITE_FUNCTION
            and (second or first or "").lower() not in self._function_names
        ):
            return sqlite3.SQLITE_DENY
        return self._authorize(action, first, second, database, trigger)

    def execute(self):
        if self.connection is None or self._executed:
            raise RuntimeError("prepared SQL query executes once within its read transaction")
        self._assert_snapshot()
        self._executed = True
        plan = self._lineage_plan
        cursor = self.connection.execute(
            plan.sql if plan is not None and plan.sql is not None else self.sql,
            plan.parameters if plan is not None and plan.sql is not None else self.parameters,
        )
        if cursor.description is None:
            raise OperationDenied("SQL statement did not produce a query result")
        result = QueryRows(
            tuple(item[0] for item in cursor.description),
            tuple(tuple(row) for row in cursor.fetchall()),
        )
        if plan is not None and plan.sql is not None:
            result = plan.extract(result.columns, result.rows)
        self._assert_snapshot(full=True)
        return result

    def __exit__(self, *_):
        if self.connection is not None:
            self.connection.set_authorizer(None)
            self.connection.close()
            self.connection = None


@dataclass(frozen=True)
class Contributor:
    table: str
    column: str
    row_key: tuple | None = None
    role: str = "value"

    def to_dict(self):
        return {
            "table": self.table,
            "column": self.column,
            "role": self.role,
            "row_key": None
            if self.row_key is None
            else [encode_sql(item) for item in self.row_key],
        }


@dataclass(frozen=True)
class CellLineage:
    row: int
    column: int
    contributors: tuple[Contributor, ...]

    def to_dict(self):
        return {
            "row": self.row,
            "column": self.column,
            "contributors": [item.to_dict() for item in self.contributors],
        }


@dataclass(frozen=True)
class QueryLineage:
    precision: str
    cells: tuple[CellLineage, ...]
    controls: tuple[Contributor, ...] = ()


@dataclass(frozen=True)
class LineageProvider:
    """Endpoint-configured mapper and validator for an exact result/snapshot pair.

    Validation must establish row-key identity and value, predicate, join,
    ordering and existence support, including empty or unmatched result sets.
    The gateway checks coverage and enrolled sources; it cannot infer whether a
    provider's semantic derivation is true from matching output values.
    """

    identifier: str
    map_result: Callable
    validate: Callable
    precision: str = "exact"

    def __post_init__(self):
        if (
            not isinstance(self.identifier, str)
            or not self.identifier.strip()
            or not callable(self.map_result)
            or not callable(self.validate)
            or self.precision not in {"exact", "conservative"}
        ):
            raise ValueError("lineage provider requires an identity, mapper and validator")


def row_key(member):
    """Return the typed key of one retained row identity."""
    return [encode_sql(member)] if type(member) is int else json.loads(member)


def lineage_cells(lineage):
    """Return contributors for each result position, expanding shared row identities."""
    rows = lineage.get("contributor_rows")
    if rows is None:
        return lineage["cells"]
    cells = []
    for row, identities in enumerate(rows):
        for column, sources in enumerate(lineage["contributor_columns"]):
            contributors = {}
            for source in sources:
                index = source["identity"]
                keys = [None] if index is None else [row_key(item) for item in identities[index]]
                for key in keys:
                    item = {name: source[name] for name in ("table", "column", "role")}
                    item["row_key"] = key
                    contributors[json.dumps(item, sort_keys=True)] = item
            cells.append({"row": row, "column": column,
                          "contributors": [contributors[key] for key in sorted(contributors)]})
    return cells


def contributor_manifest(binding, result, provider=None):
    sources = {(item["table"], item["column"]) for item in binding["sources"]}
    if provider is None:
        return {
            "precision": "conservative",
            "row_support": "unknown",
            "provider": "sqlite-authorizer",
            "cells": [],
            "controls": [],
            "source_columns": [
                source.to_dict()
                for source in sorted(SourceColumn(table, column) for table, column in sources)
            ],
        }
    if not isinstance(provider, LineageProvider):
        raise TypeError("lineage mappings require a configured provider")
    # Detached JSON prevents a provider from rewriting the authoritative binding.
    supplied = json.loads(json.dumps(binding))
    lineage = provider.map_result(supplied, result)
    if not isinstance(lineage, QueryLineage) or lineage.precision != provider.precision:
        raise OperationDenied("SQL lineage provider returned an invalid precision contract")
    coordinates = set()
    for cell in lineage.cells:
        if (
            not isinstance(cell, CellLineage)
            or type(cell.row) is not int
            or type(cell.column) is not int
            or not 0 <= cell.row < len(result.rows)
            or not 0 <= cell.column < len(result.columns)
            or (cell.row, cell.column) in coordinates
        ):
            raise OperationDenied("SQL lineage has an invalid or duplicate result position")
        coordinates.add((cell.row, cell.column))
    if coordinates != {
        (row, column) for row in range(len(result.rows)) for column in range(len(result.columns))
    }:
        raise OperationDenied("SQL lineage must describe every result position")
    for contributor in (
        *lineage.controls,
        *(item for cell in lineage.cells for item in cell.contributors),
    ):
        if (
            not isinstance(contributor, Contributor)
            or (contributor.table, contributor.column) not in sources
            or contributor.role not in {"value", "control", "presence"}
            or (
                lineage.precision == "exact"
                and (not isinstance(contributor.row_key, tuple) or not contributor.row_key)
            )
        ):
            raise OperationDenied("SQL lineage names an unassigned or unidentified contributor")
        contributor.to_dict()
    if provider.validate(json.loads(json.dumps(binding)), result, lineage) is not True:
        raise OperationDenied("SQL lineage failed its configured provider validation")
    return {
        "precision": lineage.precision,
        "row_support": "known" if lineage.precision == "exact" else "unknown",
        "provider": provider.identifier,
        "cells": [cell.to_dict() for cell in lineage.cells],
        "controls": [item.to_dict() for item in lineage.controls],
        "source_columns": [
            source.to_dict()
            for source in sorted(SourceColumn(table, column) for table, column in sources)
        ],
    }
