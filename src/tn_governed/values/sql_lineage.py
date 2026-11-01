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


def _key(*values):
    if all(value is None for value in values):
        return None
    return json.dumps([encode_sql(value) for value in values], separators=(",", ":"))


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
            return cls._prepare(query)
        except (SqlglotError, ValueError, KeyError, IndexError, TypeError) as exc:
            return cls(reason=type(exc).__name__)

    @classmethod
    def _prepare(cls, query):
        if any(
            function.name.lower() in query._builtin_functions for function in query.used_functions
        ):
            # SQLite permits scalar registrations to override aggregate names.
            # The configured callback then determines cardinality, while a SQL
            # parser still classifies the original name as an aggregate.
            raise ValueError("overridden built-in functions require engine-scoped lineage")
        sql, parameters = _parameters(query.sql, query.parameters)
        tree = parse_one(sql, read="sqlite")
        if (
            not isinstance(tree, exp.Select)
            or len(list(tree.find_all(exp.Select))) != 1
            or tree.args.get("distinct")
            or tree.args.get("with_")
        ):
            raise ValueError("projection augmentation cannot establish these row identities")
        source = tree.args.get("from_")
        tables = [source.this] if source is not None else []
        tables += [join.this for join in tree.args.get("joins", [])]
        if not tables or any(not isinstance(table, exp.Table) for table in tables):
            raise ValueError("row identities require enrolled base relations")
        aliases, fields, keys, extra = {}, {}, {}, set()
        for table in tables:
            alias, name = table.alias_or_name, table.name
            if alias in aliases:
                raise ValueError("ambiguous source alias")
            aliases[alias] = name
            columns = query._table_info(name)
            fields[alias] = tuple(column[1] for column in columns)
            schema = query.connection.execute(
                "SELECT type,sql FROM sqlite_schema WHERE name=?", (name,)
            ).fetchone()
            if schema is None or schema[0] != "table" or "VIRTUAL TABLE" in schema[1].upper():
                raise ValueError("relation requires its own identity integration")
            if "WITHOUT ROWID" not in schema[1].upper():
                identity = next(
                    (key for key in ("rowid", "_rowid_", "oid") if key not in fields[alias]), None
                )
                if identity is None:
                    raise ValueError("implicit row identity is shadowed")
                keys[alias] = (identity,)
            else:
                keys[alias] = tuple(
                    column[1] for column in sorted(columns, key=lambda c: c[5]) if column[5]
                )
                if not keys[alias]:
                    raise ValueError("source has no stable row identity")
                extra.update(SourceColumn(name, column) for column in keys[alias])

        coalesced, hidden = set(), {}
        available = set(fields[tables[0].alias_or_name])
        for join in tree.args.get("joins", []):
            alias = join.this.alias_or_name
            using = {item.name for item in join.args.get("using", [])}
            if join.args.get("method") == "NATURAL":
                using |= available & set(fields[alias])
            coalesced |= using
            hidden[alias] = using
            available.update(fields[alias])
        projections = []
        for node in tree.expressions:
            if isinstance(node, exp.Star):
                for alias, columns in fields.items():
                    for name in columns:
                        if name not in hidden.get(alias, set()):
                            projections.append(
                                exp.column(
                                    name, table=None if name in coalesced else alias, quoted=True
                                )
                            )
            elif isinstance(node, exp.Column) and node.is_star:
                projections.extend(
                    exp.column(name, table=node.table, quoted=True) for name in fields[node.table]
                )
            else:
                projections.append(node)
        tree.set("expressions", projections)
        projection_aliases = {
            node.alias: node.this for node in tree.expressions if isinstance(node, exp.Alias)
        }

        def roots(node, seen=(), prefer_alias=False, skip_windows=False):
            found = set()
            nodes = node.walk(prune=lambda item: skip_windows and isinstance(item, exp.Window))
            for column in nodes:
                if not isinstance(column, exp.Column):
                    continue
                if column.is_star:
                    raise ValueError("star projection needs schema expansion")
                if column.table:
                    if column.table not in aliases:
                        raise ValueError("unresolved column qualifier")
                    matches = [column.table]
                else:
                    matches = [alias for alias, names in fields.items() if column.name in names]
                    if (
                        (prefer_alias or not matches)
                        and column.name in projection_aliases
                        and column.name not in seen
                    ):
                        found.update(roots(projection_aliases[column.name], (*seen, column.name)))
                        continue
                    if len(matches) != 1 and column.name not in coalesced:
                        raise ValueError("unresolved or ambiguous column")
                for alias in matches:
                    name = column.name
                    if name not in fields[alias]:
                        if name.lower() not in {"rowid", "_rowid_", "oid"}:
                            raise ValueError("column is absent from source schema")
                        # A row identity selects a record of the table, so its
                        # catalog dependency remains the table's source columns.
                        found.update((alias, field) for field in fields[alias])
                    else:
                        found.add((alias, name))
            return found

        all_roots = tuple(tuple(sorted(roots(node))) for node in tree.expressions)
        controls = set()
        for name in ("where", "group", "having", "order", "qualify"):
            if tree.args.get(name) is not None:
                controls.update(roots(tree.args[name], prefer_alias=name == "order"))
                if name in {"group", "order"}:
                    for item in tree.args[name].expressions:
                        selected = item.this if isinstance(item, exp.Ordered) else item
                        if isinstance(selected, exp.Literal) and selected.is_int:
                            index = int(selected.this) - 1
                            if 0 <= index < len(tree.expressions):
                                controls.update(all_roots[index])
        for join in tree.args.get("joins", []):
            if join.args.get("on") is not None:
                controls.update(roots(join.args["on"]))
            for key in hidden.get(join.this.alias_or_name, set()):
                controls.update((alias, key) for alias, columns in fields.items() if key in columns)
        for window in tree.find_all(exp.Window):
            for name in ("partition_by", "order"):
                value = window.args.get(name)
                if isinstance(value, list):
                    for part in value:
                        controls.update(roots(part))
                elif value is not None:
                    controls.update(roots(value))

        def is_aggregate(node):
            return isinstance(node, exp.AggFunc) and not (
                isinstance(node, (exp.Min, exp.Max)) and node.expressions
            )

        aggregate = bool(tree.args.get("group")) or any(
            is_aggregate(node) and node.find_ancestor(exp.Window) is None
            for node in tree.find_all(exp.AggFunc)
        )
        if aggregate and any(tree.find_all(exp.Window)):
            raise ValueError("nested group/window support needs a separate materialization")
        projections = list(tree.expressions)
        metadata, indices = [], {}
        names = {node.name.lower() for node in tree.find_all(exp.Identifier)}
        names.update(name.lower() for columns in fields.values() for name in columns)

        def identity(alias, window=None):
            mode = "group" if aggregate else "row"
            if window is not None:
                mode = window.sql(dialect="sqlite")
            token = alias, mode
            if token in indices:
                return indices[token]
            key = exp.Anonymous(
                this="__tn_row_key",
                expressions=[
                    exp.column(column, table=alias, quoted=True) for column in keys[alias]
                ],
            )
            collected = exp.Anonymous(this="JSON_GROUP_ARRAY", expressions=[key])
            if window is not None:
                value = window.copy()
                if not is_aggregate(window.this):
                    # Ranking and navigation depend on their partition, including
                    # future rows. Retain the partition rather than a fake frame.
                    value.set("order", None)
                    value.set("spec", None)
                value.set("this", collected)
            else:
                value = collected if aggregate else key
            index = len(metadata)
            indices[token] = index
            metadata.append((alias, mode != "row"))
            name = f"__tn_lineage_{index}"
            while name.lower() in names:
                name += "_"
            names.add(name.lower())
            tree.select(exp.alias_(value, name, quoted=True), append=True, copy=False)
            return index

        maps = []
        for projection in projections:
            windows = list(projection.find_all(exp.Window))
            mapping = {}
            for alias, column in roots(projection, skip_windows=True):
                mapping.setdefault((alias, column), set()).add(identity(alias))
            for window in windows:
                for alias, column in roots(window):
                    mapping.setdefault((alias, column), set()).add(identity(alias, window))
            mapping = {source: tuple(sorted(indices)) for source, indices in mapping.items()}
            maps.append(mapping)
        control_map = {(alias, column): identity(alias) for alias, column in sorted(controls)}
        referenced = set(controls).union(*(set(items) for items in all_roots))
        extra.update(SourceColumn(aliases[alias], column) for alias, column in referenced)
        presence = []
        for alias, table in aliases.items():
            source = next((source for source in query.dependencies if source.table == table), None)
            if source is not None:
                presence.append((alias, source.column, identity(alias)))
        return cls(
            identifier="sqlite-ast",
            sql=tree.sql(dialect="sqlite", unsupported_level=ErrorLevel.RAISE),
            parameters=parameters,
            roots=tuple(maps),
            controls=tuple(control_map.items()),
            presence=tuple(presence),
            aliases=aliases,
            metadata=tuple(metadata),
            columns=len(projections),
            additional_sources=tuple(sorted(extra)),
            function_sources=tuple(
                sorted(
                    {
                        source
                        for function in query.used_functions
                        for source in function.dependencies
                    }
                )
            ),
        )

    def extract(self, columns, rows):
        self.identities = tuple(tuple(row[self.columns :]) for row in rows)
        return QueryRows(
            tuple(columns[: self.columns]), tuple(tuple(row[: self.columns]) for row in rows)
        )

    def manifest(self, binding, result):
        if self.identifier != "sqlite-ast":
            return contributor_manifest(binding, result)

        def members(raw, index):
            value = raw[index]
            if value is None:
                return []
            values = json.loads(value) if self.metadata[index][1] else [value]
            return [json.loads(item) for item in values if item is not None]

        cells = []
        for row, identities in enumerate(self.identities):
            for column, mapping in enumerate(self.roots):
                contributors = {}
                for (alias, field), indices in mapping.items():
                    for index in indices:
                        for key in members(identities, index):
                            item = {
                                "table": self.aliases[alias],
                                "column": field,
                                "role": "value",
                                "row_key": key,
                            }
                            contributors[json.dumps(item, sort_keys=True)] = item
                for (alias, field), index in self.controls:
                    for key in members(identities, index):
                        item = {
                            "table": self.aliases[alias],
                            "column": field,
                            "role": "control",
                            "row_key": key,
                        }
                        contributors[json.dumps(item, sort_keys=True)] = item
                for alias, field, index in self.presence:
                    for key in members(identities, index):
                        item = {
                            "table": self.aliases[alias],
                            "column": field,
                            "role": "presence",
                            "row_key": key,
                        }
                        contributors[json.dumps(item, sort_keys=True)] = item
                for source in self.function_sources:
                    item = Contributor(source.table, source.column).to_dict()
                    contributors[json.dumps(item, sort_keys=True)] = item
                cells.append(
                    {
                        "row": row,
                        "column": column,
                        "contributors": [contributors[key] for key in sorted(contributors)],
                    }
                )
        scopes = {(self.aliases[alias], column) for (alias, column), _ in self.controls}
        presence_scopes = {(self.aliases[alias], column) for alias, column, _ in self.presence}
        return {
            "precision": "conservative",
            "row_support": "partial" if self.function_sources else "known",
            "provider": "sqlite-ast",
            "cells": cells,
            "controls": [
                Contributor(table, column, role="control").to_dict()
                for table, column in sorted(scopes)
            ]
            + [
                Contributor(table, column, role="presence").to_dict()
                for table, column in sorted(presence_scopes)
            ]
            + [
                Contributor(source.table, source.column).to_dict()
                for source in self.function_sources
            ],
            "source_columns": [
                {key: source[key] for key in ("database", "table", "column")}
                for source in binding["sources"]
            ],
            "control_scope": "source-snapshot",
            "row_identity": "sqlite-rowid-or-primary-key",
        }
