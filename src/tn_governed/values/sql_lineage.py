"""Row dependencies collected in the same SQLite statement as its result.

The AST adds private identity projections; value expressions execute once. Row
identities describe positive contributors. Snapshot-scoped controls also retain
the dependencies needed to explain selection, absence, ordering, and grouping.
Those controls are conservative, so this strategy never claims exact why-not
provenance. Shapes whose cardinality could change under projection augmentation
keep the engine's original statement and its snapshot-scoped dependency set.
"""

import json
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from sqlglot import ErrorLevel, exp, parse_one, tokenize
from sqlglot.errors import SqlglotError

from .query import Contributor, QueryRows, SourceColumn, contributor_manifest, encode_sql

_ROWID_NAMES = ("rowid", "_rowid_", "oid")


def _key(*values):
    if all(value is None for value in values):
        return None
    # A lone integer row identity stays a number, so grouped arrays stay compact.
    if len(values) == 1 and type(values[0]) is int:
        return values[0]
    return json.dumps([encode_sql(value) for value in values], separators=(",", ":"))


def _member_order(member):
    return type(member) is str, member


def _parameters(sql, parameters):
    if isinstance(parameters, dict):
        return sql, parameters
    tokens = tokenize(sql, read="sqlite")
    edits, bindings, index = [], {}, 0
    for position, token in enumerate(tokens):
        if token.token_type.name in {"COLON", "PARAMETER"}:
            raise ValueError("mixed parameter forms need the engine's original statement")
        if token.token_type.name != "PLACEHOLDER":
            continue
        end = token.end
        following = tokens[position + 1] if position + 1 < len(tokens) else None
        if (
            following is not None
            and following.start == end + 1
            and following.token_type.name == "NUMBER"
        ):
            slot = int(following.text)
            end = following.end
            index = max(index, slot)
        else:
            index += 1
            slot = index
        name = f"__tn_parameter_{slot}"
        bindings[name] = parameters[slot - 1]
        edits.append((token.start, end + 1, ":" + name))
    for start, end, replacement in reversed(edits):
        sql = sql[:start] + replacement + sql[end:]
    return sql, bindings


def _single_select(tree):
    if (
        not isinstance(tree, exp.Select)
        or len(list(tree.find_all(exp.Select))) != 1
        or tree.args.get("distinct")
        or tree.args.get("with_")
    ):
        raise ValueError("projection augmentation cannot establish these row identities")
    return tree


def _base_tables(tree):
    source = tree.args.get("from_")
    tables = [source.this] if source is not None else []
    tables += [join.this for join in tree.args.get("joins", [])]
    if not tables or any(not isinstance(table, exp.Table) for table in tables):
        raise ValueError("row identities require enrolled base relations")
    return tables


def _is_aggregate(node):
    return isinstance(node, exp.AggFunc) and not (
        isinstance(node, (exp.Min, exp.Max)) and node.expressions
    )


class _LineagePlanner:
    """One SELECT's sources and projection roots, and the identity columns appended to it."""

    def __init__(self, query):
        if any(
            function.name.lower() in query._builtin_functions for function in query.used_functions
        ):
            # SQLite permits scalar registrations to override aggregate names.
            # The configured callback then determines cardinality, while a SQL
            # parser still classifies the original name as an aggregate.
            raise ValueError("overridden built-in functions require engine-scoped lineage")
        self.query = query
        sql, self.parameters = _parameters(query.sql, query.parameters)
        self.tree = _single_select(parse_one(sql, read="sqlite"))
        tables = _base_tables(self.tree)
        self.aliases, self.fields, self.keys = {}, {}, {}
        self.extra, self.rowid_aliases = set(), set()
        for table in tables:
            self._bind(table)
        self.coalesced, self.hidden = self._joined_columns(tables[0].alias_or_name)
        self.tree.set("expressions", self._expanded_projections())
        self.projection_aliases = {
            node.alias: node.this for node in self.tree.expressions if isinstance(node, exp.Alias)
        }
        self.aggregate, self.names, self.metadata, self.indices = None, set(), [], {}

    def plan(self):
        """Return the plan's fields; every identity column is appended before the SQL is rendered."""
        projections = list(self.tree.expressions)
        all_roots = tuple(tuple(sorted(self.roots(node))) for node in projections)
        controls = self._controls(all_roots)
        self.aggregate = self._aggregate()
        self.names = {node.name.lower() for node in self.tree.find_all(exp.Identifier)}
        self.names.update(name.lower() for columns in self.fields.values() for name in columns)
        maps = [self._projection_map(projection) for projection in projections]
        control_map = {(alias, column): self.identity(alias) for alias, column in sorted(controls)}
        referenced = set(controls).union(*(set(items) for items in all_roots))
        self.extra.update(SourceColumn(self.aliases[alias], column) for alias, column in referenced)
        presence = self._presence()
        return {
            "identifier": "sqlite-ast",
            "sql": self.tree.sql(dialect="sqlite", unsupported_level=ErrorLevel.RAISE),
            "parameters": self.parameters,
            "roots": tuple(maps),
            "controls": tuple(control_map.items()),
            "presence": tuple(presence),
            "aliases": self.aliases,
            "metadata": tuple(self.metadata),
            "columns": len(projections),
            "additional_sources": tuple(sorted(self.extra)),
            "function_sources": tuple(sorted({
                source for function in self.query.used_functions for source in function.dependencies
            })),
        }

    def _bind(self, table):
        """Record one source's alias, columns, and stable row identity."""
        alias, name = table.alias_or_name, table.name
        if alias in self.aliases:
            raise ValueError("ambiguous source alias")
        self.aliases[alias] = name
        columns = self.query._table_info(name)
        self.fields[alias] = tuple(column[1] for column in columns)
        schema = self.query.connection.execute(
            "SELECT type,sql FROM sqlite_schema WHERE name=?", (name,)
        ).fetchone()
        if schema is None or schema[0] != "table" or "VIRTUAL TABLE" in schema[1].upper():
            raise ValueError("relation requires its own identity integration")
        if "WITHOUT ROWID" not in schema[1].upper():
            identity = next((key for key in _ROWID_NAMES if key not in self.fields[alias]), None)
            if identity is None:
                raise ValueError("implicit row identity is shadowed")
            self.keys[alias] = (identity,)
            self.rowid_aliases.add(alias)
            return
        self.keys[alias] = tuple(
            column[1] for column in sorted(columns, key=lambda c: c[5]) if column[5]
        )
        if not self.keys[alias]:
            raise ValueError("source has no stable row identity")
        self.extra.update(SourceColumn(name, column) for column in self.keys[alias])

    def _joined_columns(self, first):
        """USING and NATURAL join columns: coalesced in the output, hidden on the joined side."""
        coalesced, hidden = set(), {}
        available = set(self.fields[first])
        for join in self.tree.args.get("joins", []):
            alias = join.this.alias_or_name
            using = {item.name for item in join.args.get("using", [])}
            if join.args.get("method") == "NATURAL":
                using |= available & set(self.fields[alias])
            coalesced |= using
            hidden[alias] = using
            available.update(self.fields[alias])
        return coalesced, hidden

    def _expanded_projections(self):
        projections = []
        for node in self.tree.expressions:
            if isinstance(node, exp.Star):
                projections += [
                    exp.column(name, table=None if name in self.coalesced else alias, quoted=True)
                    for alias, columns in self.fields.items()
                    for name in columns
                    if name not in self.hidden.get(alias, set())
                ]
            elif isinstance(node, exp.Column) and node.is_star:
                projections += [
                    exp.column(name, table=node.table, quoted=True) for name in self.fields[node.table]
                ]
            else:
                projections.append(node)
        return projections

    def roots(self, node, seen=(), prefer_alias=False, skip_windows=False):
        """The (alias, column) sources a node reads, following projection aliases."""
        found = set()
        for column in node.walk(prune=lambda item: skip_windows and isinstance(item, exp.Window)):
            if isinstance(column, exp.Column):
                found.update(self._column_roots(column, seen, prefer_alias))
        return found

    def _column_roots(self, column, seen, prefer_alias):
        if column.is_star:
            raise ValueError("star projection needs schema expansion")
        if column.table:
            if column.table not in self.aliases:
                raise ValueError("unresolved column qualifier")
            matches = [column.table]
        else:
            matches = [alias for alias, names in self.fields.items() if column.name in names]
            if (
                (prefer_alias or not matches)
                and column.name in self.projection_aliases
                and column.name not in seen
            ):
                return self.roots(self.projection_aliases[column.name], (*seen, column.name))
            if len(matches) != 1 and column.name not in self.coalesced:
                raise ValueError("unresolved or ambiguous column")
        return {pair for alias in matches for pair in self._source_columns(alias, column.name)}

    def _source_columns(self, alias, name):
        if name in self.fields[alias]:
            return {(alias, name)}
        if name.lower() not in _ROWID_NAMES:
            raise ValueError("column is absent from source schema")
        # A row identity selects a record of the table, so its
        # catalog dependency remains the table's source columns.
        return {(alias, field) for field in self.fields[alias]}

    def _controls(self, all_roots):
        """Sources that select, group, order, or join rows without supplying a value."""
        controls = set()
        for name in ("where", "group", "having", "order", "qualify"):
            clause = self.tree.args.get(name)
            if clause is not None:
                controls.update(self.roots(clause, prefer_alias=name == "order"))
                if name in {"group", "order"}:
                    controls.update(self._positional(clause, all_roots))
        for join in self.tree.args.get("joins", []):
            if join.args.get("on") is not None:
                controls.update(self.roots(join.args["on"]))
            for key in self.hidden.get(join.this.alias_or_name, set()):
                controls.update((alias, key) for alias, columns in self.fields.items() if key in columns)
        for window in self.tree.find_all(exp.Window):
            for name in ("partition_by", "order"):
                value = window.args.get(name)
                for part in value if isinstance(value, list) else [] if value is None else [value]:
                    controls.update(self.roots(part))
        return controls

    def _positional(self, clause, all_roots):
        """GROUP BY 2 and ORDER BY 2 name the second projection's sources."""
        found = set()
        for item in clause.expressions:
            selected = item.this if isinstance(item, exp.Ordered) else item
            if isinstance(selected, exp.Literal) and selected.is_int:
                index = int(selected.this) - 1
                if 0 <= index < len(self.tree.expressions):
                    found.update(all_roots[index])
        return found

    def _aggregate(self):
        aggregate = bool(self.tree.args.get("group")) or any(
            _is_aggregate(node) and node.find_ancestor(exp.Window) is None
            for node in self.tree.find_all(exp.AggFunc)
        )
        if aggregate and any(self.tree.find_all(exp.Window)):
            raise ValueError("nested group/window support needs a separate materialization")
        return aggregate

    def _projection_map(self, projection):
        windows = list(projection.find_all(exp.Window))
        mapping = {}
        for alias, column in self.roots(projection, skip_windows=True):
            mapping.setdefault((alias, column), set()).add(self.identity(alias))
        for window in windows:
            for alias, column in self.roots(window):
                mapping.setdefault((alias, column), set()).add(self.identity(alias, window))
        return {source: tuple(sorted(indices)) for source, indices in mapping.items()}

    def _presence(self):
        presence = []
        for alias, table in self.aliases.items():
            source = next((source for source in self.query.dependencies if source.table == table), None)
            if source is not None:
                presence.append((alias, source.column, self.identity(alias)))
        return presence

    def identity(self, alias, window=None):
        """The index of the column collecting this source's row keys, appended once per mode."""
        mode = "group" if self.aggregate else "row"
        if window is not None:
            mode = window.sql(dialect="sqlite")
        token = alias, mode
        if token not in self.indices:
            self.indices[token] = self._append_identity(alias, window, mode)
        return self.indices[token]

    def _append_identity(self, alias, window, mode):
        key = self._row_key(alias)
        collected = exp.Anonymous(this="JSON_GROUP_ARRAY", expressions=[key])
        if window is not None:
            value = window.copy()
            if not _is_aggregate(window.this):
                # Ranking and navigation depend on their partition, including
                # future rows. Retain the partition rather than a fake frame.
                value.set("order", None)
                value.set("spec", None)
            value.set("this", collected)
        else:
            value = collected if self.aggregate else key
        index = len(self.metadata)
        self.metadata.append((alias, mode != "row"))
        name = f"__tn_lineage_{index}"
        while name.lower() in self.names:
            name += "_"
        self.names.add(name.lower())
        self.tree.select(exp.alias_(value, name, quoted=True), append=True, copy=False)
        return index

    def _row_key(self, alias):
        # A rowid is already the integer form of a row key, so no row needs a Python call.
        if alias in self.rowid_aliases:
            return exp.column(self.keys[alias][0], table=alias, quoted=True)
        return exp.Anonymous(
            this="__tn_row_key",
            expressions=[exp.column(column, table=alias, quoted=True) for column in self.keys[alias]],
        )


@dataclass
class SQLiteLineagePlan:
    identifier: str = "sqlite-authorizer"
    precision: str = "conservative"
    sql: str | None = None
    parameters: object = ()
    roots: tuple = ()
    controls: tuple = ()
    presence: tuple = ()
    aliases: dict = dataclass_field(default_factory=dict)
    metadata: tuple = ()
    columns: int = 0
    identities: tuple = ()
    additional_sources: tuple = ()
    function_sources: tuple = ()
    reason: str | None = None

    @classmethod
    def prepare(cls, query):
        try:
            return cls(**_LineagePlanner(query).plan())
        except (SqlglotError, ValueError, KeyError, IndexError, TypeError) as exc:
            return cls(reason=type(exc).__name__)

    def extract(self, columns, rows):
        self.identities = tuple(tuple(row[self.columns :]) for row in rows)
        return QueryRows(
            tuple(columns[: self.columns]), tuple(tuple(row[: self.columns]) for row in rows)
        )

    def manifest(self, binding, result):
        if self.identifier != "sqlite-ast":
            return contributor_manifest(binding, result)
        # Output columns share each row's identity lists, so a group of n source
        # rows costs n entries in total, not n per column and dependency.
        columns = [self._column_sources(mapping) for mapping in self.roots]
        rows = [
            [self._members(identities, index) for index in range(len(self.metadata))]
            for identities in self.identities
        ]
        return {
            "precision": "conservative",
            "row_support": "partial" if self.function_sources else "known",
            "provider": "sqlite-ast",
            "cells": [],
            "contributor_columns": columns,
            "contributor_rows": rows,
            "controls": self._control_contributors(),
            "source_columns": [
                {key: source[key] for key in ("database", "table", "column")}
                for source in binding["sources"]
            ],
            "control_scope": "source-snapshot",
            "row_identity": "sqlite-rowid-or-primary-key",
        }

    def _members(self, raw, index):
        value = raw[index]
        if value is None:
            return []
        values = json.loads(value) if self.metadata[index][1] else [value]
        unique = set(values)
        unique.discard(None)
        try:
            return sorted(unique)
        except TypeError:
            return sorted(unique, key=_member_order)

    def _column_sources(self, mapping):
        sources = [
            (alias, field, "value", index)
            for (alias, field), indices in mapping.items()
            for index in indices
        ]
        sources += [(alias, field, "control", index) for (alias, field), index in self.controls]
        sources += [(alias, field, "presence", index) for alias, field, index in self.presence]
        listed = [
            {"table": self.aliases[alias], "column": field, "role": role, "identity": index}
            for alias, field, role, index in sources
        ]
        listed += [
            {"table": item.table, "column": item.column, "role": "value", "identity": None}
            for item in self.function_sources
        ]
        return listed

    def _control_contributors(self):
        scopes = {(self.aliases[alias], column) for (alias, column), _ in self.controls}
        presence_scopes = {(self.aliases[alias], column) for alias, column, _ in self.presence}
        return (
            [Contributor(table, column, role="control").to_dict() for table, column in sorted(scopes)]
            + [
                Contributor(table, column, role="presence").to_dict()
                for table, column in sorted(presence_scopes)
            ]
            + [Contributor(source.table, source.column).to_dict() for source in self.function_sources]
        )
