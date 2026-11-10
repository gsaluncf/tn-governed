"""The case a caller requests, checked before its run directory exists, and its source rows."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from contextlib import closing
from dataclasses import dataclass, replace
from decimal import Decimal
from pathlib import Path

MODES = {"primitive", "explicit"}
COLUMN_TYPES = {"int": "INTEGER", "float": "REAL", "Decimal": "DECIMAL_TEXT"}


@dataclass(frozen=True)
class CaseRequest:
    """One measured case's settings; a fixture replaces the generated rows with (name, value) pairs."""

    mode: str
    rows: int = 1
    depth: int = 1
    branches: int = 1
    model: bool = False
    claim: bool = True
    unity_url: str = "http://127.0.0.1:8080"
    binary: str | Path | None = None
    model_path: str | Path | None = None
    port: int = 18325
    numeric_type: str = "int"
    decimal_precision: int = 38
    decimal_scale: int = 4
    storage: str = "files"
    sdk_build_record: str | Path | None = None
    runtime_limits: dict | None = None
    gpu_layers: int | None = None
    completion_handler: Callable | None = None
    sql_batch_size: int = 64
    company: str = "ACME"
    additional_claims: int = 0
    fixture: Sequence | None = None
    cell_reads: int = 0

    def checked(self):
        """Return the request with any fixture applied, or raise before anything is written."""
        request = self if self.fixture is None else replace(
            self, rows=len(self.fixture), company=self.fixture[0][0])
        request._check_shape()
        request._check_runtime()
        return request

    def _check_shape(self):
        if self.mode not in MODES:
            raise ValueError("mode must be primitive or explicit")
        if self.storage != "files":
            raise ValueError("application computation uses native objects; archive storage must be files")
        if any(type(n) is not int or n < 1 for n in (self.rows, self.branches)):
            raise ValueError("rows and branches must be positive integers")
        if type(self.depth) is not int or self.depth < 0:
            raise ValueError("depth must be a nonnegative integer")
        if self.numeric_type not in COLUMN_TYPES:
            raise ValueError("unsupported source numeric type")

    def _check_runtime(self):
        from tn_governed.values.primitives import MAX_SOURCE_PUBLICATION_CELLS

        if self.completion_handler is not None and not callable(self.completion_handler):
            raise ValueError("completion_handler must be callable")
        if self.model and self.gpu_layers == 0:
            raise ValueError("the evaluation runs every model layer on the GPU")
        batch = self.sql_batch_size
        if type(batch) is not int or not 1 <= batch <= MAX_SOURCE_PUBLICATION_CELLS:
            raise ValueError("sql_batch_size exceeds the supported publication size")


@dataclass(frozen=True)
class Workload:
    """The source rows and the content the application must compute from them."""

    names: tuple
    values: tuple
    numeric_type: str
    expected_content: str

    @classmethod
    def of(cls, request):
        fixture = request.fixture
        values = [value for _, value in fixture] if fixture else [1250 + i for i in range(request.rows)]
        names = ([name for name, _ in fixture] if fixture
                 else [request.company if i == 0 else f"ACME-{i}" for i in range(request.rows)])
        if request.numeric_type == "float":
            values = [float(value) + 0.125 for value in values]
        elif request.numeric_type == "Decimal":
            values = [Decimal(f"{value}.1250") for value in values]
        amount = sum(value + 250 for value in values if value >= 0) + request.depth
        label = request.company.upper() + " / A" * (request.branches - 1)
        return cls(tuple(names), tuple(values), request.numeric_type,
                   f"{label}: {amount} demonstration cents")

    def write(self, database):
        """Create the SQLite table the governed query reads."""
        sqlite3.register_converter("DECIMAL_TEXT", lambda raw: Decimal(raw.decode("ascii")))
        decimal = self.numeric_type == "Decimal"
        rows = [(name, str(value) if decimal else value)
                for name, value in zip(self.names, self.values, strict=True)]
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("CREATE TABLE market_data (name TEXT NOT NULL, "
                               f"value {COLUMN_TYPES[self.numeric_type]} NOT NULL)")
            connection.executemany("INSERT INTO market_data VALUES (?, ?)", rows)
            connection.commit()
