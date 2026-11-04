
import polars as pl

from .release import PolicyDenied


class GovernedLazyFrame:
    """A Polars plan carrying the applicable policies and attributed claims."""

    def __init__(self, frame: pl.LazyFrame, policy, tn_governance: dict, evaluator,
                 sources=None, row_sources=None, label_map=None, tn_boundary=None, ordinary_rows=False, count_plan=None):
        self.frame = frame
        self.policy = policy
        self.tn_governance = dict(tn_governance)
        self.evaluator = evaluator
        self.label_map = label_map
        schema = frame.collect_schema()
        self.sources = {name: set(roots) for name, roots in sources.items()} if sources is not None else {
            name: {name} for name in schema.names()}
        self.row_sources = set(row_sources) if row_sources is not None else set()
        self._tn = tn_boundary
        # True only while every row is an original admitted row. Aggregate
        # policies asking for distinct source membership require independent evidence.
        self._ordinary_rows = ordinary_rows
        self._count_plan = count_plan

    def _child(self, frame, sources=None, row_sources=None, *, operation=None,
               tn_boundary=None, ordinary_rows=None, count_plan=None):
        boundary = tn_boundary if tn_boundary is not None else self._tn
        sources = sources if sources is not None else self.sources
        row_sources = row_sources if row_sources is not None else self.row_sources
        if boundary and operation:
            boundary.policies.decide(operation, boundary.use.application, sources, row_sources, boundary.use)
        return GovernedLazyFrame(frame, self.policy, self.tn_governance, self.evaluator,
            sources=sources, row_sources=row_sources, label_map=self.label_map, tn_boundary=boundary,
            ordinary_rows=self._ordinary_rows if ordinary_rows is None else ordinary_rows,
            count_plan=count_plan)

    def _field_rules(self, expression):
        names = expression.meta.root_names()
        if expression.meta.has_multiple_outputs() or not names:
            return set().union(*self.sources.values())
        return set().union(*(self.sources[name] for name in names))

    def _outputs(self, expression):
        names = self.frame.select(expression).collect_schema().names()
        rules = self._field_rules(expression)
        return [(name, rules) for name in names]

    def _aggregate_count_plan(self, expressions, keys=()):
        # On original admitted rows, a per-group count can satisfy a minimum
        # size rule without identifying any row. More general plans may overlap.
        if (not self._ordinary_rows or not expressions or not self._tn
                or not any(entry.policy.release for entry in self._tn.policies._entries.values())):
            return None
        counts = []
        for expr in expressions:
            expr = expr.meta.undo_aliases()
            roots = expr.meta.root_names()
            if expr.meta.eq(pl.len()):
                counts.append(pl.len())
            elif len(roots) == 1:
                column = pl.col(roots[0])
                reductions = (column.sum(), column.mean(), column.min(), column.max(),
                              column.median(), column.count())
                if not any(expr.meta.eq(candidate) for candidate in reductions):
                    return None
                counts.append(column.count())
            else:
                return None
        count_field = "__tn_policy_group_size"
        outputs = {name for expr in (*keys, *expressions) for name, _ in self._outputs(expr)}
        while count_field in outputs:
            count_field += "_"
        count = pl.min_horizontal(*counts).alias(count_field)
        if keys:
            plan = self.frame.group_by(keys).agg(*expressions, count)
        else:
            plan = self.frame.select(*expressions, count)
        return plan, count_field

    def select(self, *items):
        expressions = [pl.col(item) if isinstance(item, str) else item for item in items]
        traced = [item for expr in expressions for item in self._outputs(expr)]
        ordinary = self._ordinary_rows and all(expr.meta.is_column() for expr in expressions)
        return self._child(self.frame.select(expressions), dict(traced),
                           operation="select", ordinary_rows=ordinary,
                           count_plan=self._aggregate_count_plan(expressions))

    def with_columns(self, *expressions):
        sources = dict(self.sources)
        for expression in expressions:
            sources.update(self._outputs(expression))
        ordinary = self._ordinary_rows and all(expr.meta.is_column() for expr in expressions)
        return self._child(self.frame.with_columns(expressions), sources,
                           operation="with_columns", ordinary_rows=ordinary)

    def filter(self, predicate):
        roots = self._field_rules(predicate)
        return self._child(self.frame.filter(predicate), row_sources=self.row_sources | roots,
                           operation="filter")

    def join(self, other, on, how="inner"):
        if self._tn is not None or other._tn is not None:
            return self._join_tn(other, on, how)
        if other.policy.policy_ref != self.policy.policy_ref:
            raise PolicyDenied("cannot join frames governed by different TN policies")
        keys = [on] if isinstance(on, str) else list(on or ())
        sources = dict(self.sources)
        for name, roots in other.sources.items():
            target = name if name in keys or name not in sources else name + "_right"
            sources[target] = sources.get(target, set()) | roots
        row_sources = self.row_sources | other.row_sources
        for key in keys:
            row_sources |= self.sources.get(key, {key}) | other.sources.get(key, {key})
        joined = self.frame.join(other.frame, on=keys or None, how=how)
        names = joined.collect_schema().names()
        return self._child(joined, sources={name: sources[name] for name in names},
                           row_sources=row_sources, ordinary_rows=False)

    def _join_tn(self, other, on, how):
        from .tn_boundary import _refusal
        if self._tn is None or other._tn is None:
            raise _refusal("Both joined inputs must have native TN admission")
        keys = [on] if isinstance(on, str) else list(on or ())
        boundary = self._tn.include(other._tn)
        joined = self.frame.join(other.frame, on=keys or None, how=how)
        sources = {name: set(roots) for name, roots in self.sources.items()}
        if how not in {"semi", "anti"}:
            for name, roots in other.sources.items():
                # Polars coalesces equal-name keys except on full joins by default.
                if name in keys and how != "full":
                    sources[name] = sources.get(name, set()) | roots
                else:
                    target = name + "_right" if name in sources else name
                    sources[target] = set(roots)
        output_names = set(joined.collect_schema().names())
        sources = {name: roots for name, roots in sources.items() if name in output_names}
        if set(sources) != output_names:
            raise _refusal("The joined output schema has unclassified source columns")
        row_sources = self.row_sources | other.row_sources
        for key in keys:
            row_sources |= self.sources.get(key, set()) | other.sources.get(key, set())
        return self._child(joined, sources, row_sources, operation="join",
                           tn_boundary=boundary, ordinary_rows=False)

    def rename(self, mapping):
        sources = {mapping.get(name, name): roots for name, roots in self.sources.items()}
        return self._child(self.frame.rename(mapping), sources=sources, operation="rename")

    def drop(self, *names):
        sources = {name: roots for name, roots in self.sources.items() if name not in names}
        return self._child(self.frame.drop(*names), sources=sources, operation="drop")

    def sort(self, by, *, descending=False):
        keys = [by] if isinstance(by, str) else list(by)
        roots = set().union(*(self.sources[name] for name in keys))
        return self._child(self.frame.sort(keys, descending=descending),
                           row_sources=self.row_sources | roots, operation="sort")

    def head(self, n):
        return self._child(self.frame.head(n), operation="head")

    def _named_columns(self, columns):
        names = [columns] if isinstance(columns, str) else list(columns)
        if (not names or len(names) != len(set(names))
                or any(name not in self.sources for name in names)):
            raise ValueError("operation requires distinct business column names")
        return names

    def explode(self, columns):
        names = self._named_columns(columns)
        roots = set().union(*(self.sources[name] for name in names))
        return self._child(self.frame.explode(names),
            row_sources=self.row_sources | roots, operation="explode", ordinary_rows=False)

    def unnest(self, columns):
        names = self._named_columns(columns)
        schema = self.frame.collect_schema()
        sources = {}
        for name, roots in self.sources.items():
            if name in names:
                if not isinstance(schema[name], pl.Struct):
                    raise TypeError("unnest requires struct columns")
                sources.update({field.name: set(roots) for field in schema[name].fields})
            else:
                sources[name] = set(roots)
        return self._child(self.frame.unnest(names), sources=sources, operation="unnest")

    def unique(self, subset=None, *, keep="any", maintain_order=False):
        names = self._named_columns(list(self.sources) if subset is None else subset)
        roots = set().union(*(self.sources[name] for name in names))
        return self._child(self.frame.unique(subset=names, keep=keep, maintain_order=maintain_order),
            row_sources=self.row_sources | roots, operation="unique", ordinary_rows=False)

    def transform(self, registration, *other_frames):
        from .plans import transform
        return transform(self, registration, other_frames)

    def _materialize(self):
        if self._count_plan is not None:
            plan, field = self._count_plan
            counted = plan.collect()
            sizes = counted[field].to_list()
            return counted.drop(field), {"known": True, "aggregated": True,
                                         "group_sizes": sizes, "output_rows": counted.height}
        data = self.frame.collect()
        if self._ordinary_rows:
            return data, {"known": True, "aggregated": False, "group_sizes": [], "output_rows": data.height}
        return data, {"known": False}

    def collect(self):
        if self._tn is not None:
            raise PolicyDenied("native governed frames require release_tn before application transfer")
        return self.frame.collect()

    def group_by(self, *items):
        expressions = [pl.col(item) if isinstance(item, str) else item for item in items]
        parent = self._child(self.frame, operation="group_by") if self._tn else self
        return GovernedGroupBy(parent, expressions)

    @property
    def tn_object(self):
        """An independent native working copy; mutation cannot affect sibling frames."""
        return self._tn.data.copy() if self._tn else None

    def release_tn(self, *, use, to, decide, object_type=None, group=None, rows_field=None,
                   metadata_group=None):
        from .tn_boundary import release_tn
        return release_tn(self, use=use, to=to, decide=decide, object_type=object_type,
                          group=group, rows_field=rows_field, metadata_group=metadata_group)


class GovernedGroupBy:
    """Grouped expressions with governed output."""

    def __init__(self, parent, keys):
        self.parent = parent
        self.keys = keys

    def agg(self, *expressions):
        key_sources = dict(item for key in self.keys for item in self.parent._outputs(key))
        aggregate_sources = dict(item for expression in expressions
                                 for item in self.parent._outputs(expression))
        row_sources = set(self.parent.row_sources)
        if self.parent._tn:
            row_sources.update(root for roots in key_sources.values() for root in roots)
        return self.parent._child(
            self.parent.frame.group_by(self.keys).agg(*expressions),
            sources=key_sources | aggregate_sources,
            row_sources=row_sources, operation="aggregate", ordinary_rows=False,
            count_plan=self.parent._aggregate_count_plan(expressions, self.keys),
        )
