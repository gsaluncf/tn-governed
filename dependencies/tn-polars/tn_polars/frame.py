import hashlib
import io
import json
from pathlib import Path

import polars as pl

from .audit import expression_record
from .labels import sensitivity_block
from .policy import policy_sha256
from .release import PolicyDenied, ReleaseArtifact
from .sealing import CIPHER_NAME
from .support import Support, business_expressions, expression_kind, window_partitions
from uuid import uuid4


class GovernedLazyFrame:
    """A Polars plan carrying native source authority and contributor evidence."""

    def __init__(self, frame: pl.LazyFrame, policy, tn_governance: dict, evaluator,
                 sources=None, row_sources=None, label_map=None, tn_boundary=None, _support=None):
        self.frame = frame
        self.policy = policy
        self.tn_governance = dict(tn_governance)
        self.evaluator = evaluator
        self.label_map = label_map
        schema = frame.collect_schema()
        if any(name.startswith("__tn_support_") for name in schema.names()):
            raise PolicyDenied("source schema uses reserved aggregate support columns")
        self.sources = {name: set(roots) for name, roots in sources.items()} if sources is not None else {
            name: {name} for name in schema.names()}
        self.row_sources = set(row_sources) if row_sources is not None else set()
        self._tn = tn_boundary
        source = next(iter(tn_boundary.policies._entries.values())).source_ids if tn_boundary else None
        self._support = _support or Support.source(frame, next(iter(source)) if source else uuid4().hex,
            tn_boundary.policies.revision_ids if tn_boundary else [policy.policy_ref])

    def _child(self, frame, sources=None, row_sources=None, *, operation=None, parameters=None,
               tn_boundary=None, support=None):
        boundary = tn_boundary if tn_boundary is not None else self._tn.copy() if self._tn else None
        sources = sources if sources is not None else self.sources
        row_sources = row_sources if row_sources is not None else self.row_sources
        if boundary and operation:
            boundary.policies.decide(operation, boundary.use.application, sources, row_sources, boundary.use)
            boundary.policies.record_operation(operation, parameters)
        return GovernedLazyFrame(
            frame, self.policy, self.tn_governance, self.evaluator,
            sources=sources, row_sources=row_sources,
            label_map=self.label_map,
            tn_boundary=boundary,
            _support=support or self._support.apply(frame),
        )

    def _trace(self, expr):
        output = expr.meta.output_name()
        if any(name.startswith("__tn_support_") for name in [output, *expr.meta.root_names()]):
            raise PolicyDenied("expressions cannot access reserved aggregate support columns")
        roots = set()
        for root in expr.meta.root_names():
            roots |= self.sources.get(root, {root})
        return output, roots

    def _outputs(self, expression):
        names = self.frame.select(expression).collect_schema().names()
        roots = expression.meta.root_names()
        if any(name.startswith("__tn_support_") for name in [*names, *roots]):
            raise PolicyDenied("expressions cannot access reserved contributor columns")
        dependencies = set().union(*(self.sources.get(root, {root}) for root in roots))
        if not roots and expression.meta.has_multiple_outputs():
            if all(name in self.sources for name in names):
                return [(name, set(self.sources[name])) for name in names]
            dependencies = set().union(*self.sources.values())
        return [(name, set(dependencies)) for name in names]

    def select(self, *items):
        expressions = [pl.col(item) if isinstance(item, str) else item for item in items]
        traced = [item for expr in expressions for item in self._outputs(expr)]
        expressions = business_expressions(expressions, self.frame.collect_schema())
        kinds = [expression_kind(expr) for expr in expressions]
        windowed = self._support.windowed(expressions, project=True)
        if windowed is not None:
            support = windowed
        elif any(aggregate for aggregate, _ in kinds):
            support = self._support.aggregate([], expressions)
        elif all(known for _, known in kinds):
            support = self._support.project(expressions)
        else:
            support = self._support.unknown(self.frame.select(expressions))
        controls = set(self.row_sources)
        if windowed is not None:
            controls.update(root for keys in window_partitions(expressions) for key in keys
                            for root in self.sources[key])
        return self._child(support.frame.select(list(dict(traced))), dict(traced), controls,
                           operation="select",
                           parameters={"expressions": [expression_record(expr) for expr in expressions]}, support=support)

    def with_columns(self, *expressions):
        sources = dict(self.sources)
        for expression in expressions:
            sources.update(self._outputs(expression))
        expressions = business_expressions(expressions, self.frame.collect_schema())
        windowed = self._support.windowed(expressions)
        if windowed is not None:
            support = windowed
        elif all(not agg and known for agg, known in map(expression_kind, expressions)):
            support = self._support.apply(self._support.frame.with_columns(expressions))
        else:
            support = self._support.unknown(self.frame.with_columns(expressions))
        controls = set(self.row_sources)
        if windowed is not None:
            controls.update(root for keys in window_partitions(expressions) for key in keys
                            for root in self.sources[key])
        return self._child(support.frame.select(list(sources)), sources, controls,
                           operation="with_columns",
                           parameters={"expressions": [expression_record(expr) for expr in expressions]}, support=support)

    def filter(self, predicate):
        _, roots = self._trace(predicate)
        support = self._support.apply(self._support.frame.filter(predicate))
        if expression_kind(predicate) != (False, True):
            support = support.unknown(self.frame.filter(predicate))
        return self._child(support.frame.select(list(self.sources)), row_sources=self.row_sources | roots,
                           operation="filter", parameters={"predicate": expression_record(predicate)}, support=support)

    def join(self, other, on, how="inner"):
        if self._tn is not None or other._tn is not None:
            return self._join_tn(other, on, how)
        if other.policy.policy_ref != self.policy.policy_ref:
            raise PolicyDenied("cannot join frames governed by different TN policies")
        keys = [on] if isinstance(on, str) else list(on)
        sources = dict(self.sources)
        for name, roots in other.sources.items():
            target = name if name in keys or name not in sources else name + "_right"
            sources[target] = sources.get(target, set()) | roots
        row_sources = self.row_sources | other.row_sources
        for key in keys:
            row_sources |= self.sources.get(key, {key}) | other.sources.get(key, {key})
        support = self._support.joined(other._support, keys, how)
        names = self.frame.join(other.frame, on=keys, how=how).collect_schema().names()
        sources = {name: roots for name, roots in sources.items() if name in names}
        return self._child(support.frame.select(names), sources=sources,
                           row_sources=row_sources, support=support)

    def _join_tn(self, other, on, how):
        from .tn_boundary import _refusal
        if self._tn is None or other._tn is None:
            raise _refusal("Both joined inputs must have native TN admission")
        if how not in {"inner", "left", "right", "full", "semi", "anti"}:
            raise _refusal(f"TN lineage has no tested rule for join mode {how!r}")
        keys = [on] if isinstance(on, str) else list(on)
        boundary = self._tn.include(other._tn)
        joined = self.frame.join(other.frame, on=keys, how=how)
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
        support = self._support.joined(other._support, keys, how)
        return self._child(support.frame.select(list(sources)), sources, row_sources, operation="join",
                           parameters={"on": keys, "how": how,
                                       "left": list(self._tn.policies.audit.heads),
                                       "right": list(other._tn.policies.audit.heads)},
                           tn_boundary=boundary, support=support)

    def rename(self, mapping):
        sources = {mapping.get(name, name): roots for name, roots in self.sources.items()}
        support = self._support.apply(self._support.frame.rename(mapping))
        return self._child(support.frame.select(list(sources)), sources=sources, operation="rename",
                           parameters={"mapping": mapping}, support=support)

    def drop(self, *names):
        dropped = set(names)
        sources = {name: roots for name, roots in self.sources.items() if name not in dropped}
        support = self._support.apply(self._support.frame.drop(*names))
        return self._child(support.frame.select(list(sources)), sources=sources, operation="drop",
                           parameters={"columns": list(names)}, support=support)

    def sort(self, by, *, descending=False):
        keys = [by] if isinstance(by, str) else list(by)
        roots = set()
        for key in keys:
            roots |= self.sources.get(key, {key})
        support = self._support.apply(self._support.frame.sort(keys, descending=descending))
        return self._child(support.frame.select(list(self.sources)),
                           row_sources=self.row_sources | roots, operation="sort",
                           parameters={"by": keys, "descending": descending}, support=support)

    def head(self, n):
        support = self._support.apply(self._support.frame.head(n))
        return self._child(support.frame.select(list(self.sources)), operation="head",
                           parameters={"count": n}, support=support)

    def _named_columns(self, columns):
        names = [columns] if isinstance(columns, str) else list(columns)
        if (not names or len(names) != len(set(names))
                or any(name not in self.sources for name in names)):
            raise ValueError("operation requires distinct business column names")
        return names

    def explode(self, columns):
        names = self._named_columns(columns)
        roots = set().union(*(self.sources[name] for name in names))
        support = self._support.apply(self._support.frame.explode(names))
        return self._child(support.frame.select(list(self.sources)),
            row_sources=self.row_sources | roots, operation="explode",
            parameters={"columns": names}, support=support)

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
        support = self._support.apply(self._support.frame.unnest(names))
        return self._child(support.frame.select(list(sources)), sources=sources,
            operation="unnest", parameters={"columns": names}, support=support)

    def unique(self, subset=None, *, keep="any", maintain_order=False):
        names = self._named_columns(list(self.sources) if subset is None else subset)
        roots = set().union(*(self.sources[name] for name in names))
        support = self._support.unique(names, keep=keep, maintain_order=maintain_order)
        return self._child(support.frame.select(list(self.sources)),
            row_sources=self.row_sources | roots, operation="unique",
            parameters={"subset": names, "keep": keep, "maintain_order": maintain_order},
            support=support)

    def transform(self, registration, *other_frames):
        from .plans import transform
        return transform(self, registration, other_frames)

    def collect(self):
        if self._tn is not None:
            raise PolicyDenied("native governed frames require release_tn before application transfer")
        return self.frame.collect()

    def group_by(self, *items):
        expressions = [pl.col(item) if isinstance(item, str) else item for item in items]
        expressions = business_expressions(expressions, self.frame.collect_schema())
        parent = self._child(self.frame, operation="group_by",
                             parameters={"keys": [expression_record(expr) for expr in expressions]},
                             support=self._support) if self._tn else self
        return GovernedGroupBy(parent, expressions)

    def _classification(self, roots):
        if self._tn:
            return self._tn.policies.classification(roots)
        if any(self.policy.level(source) == "confidential" for source in roots):
            return "confidential"
        if any(self.policy.level(source) == "internal" for source in roots):
            return "internal"
        return "public"

    def _policy_input(self, audience, materialized=None):
        columns = [
            {"name": name, "sources": sorted(roots),
             "classification": self._classification(roots)}
            for name, roots in self.sources.items()
        ]
        return {
            "policy_ref": self.policy.policy_ref,
            "operation": "release",
            "audience": audience,
            "columns": columns,
            "row_selection_sources": sorted(self.row_sources),
            "aggregate_support": self._support.facts(materialized) if materialized is not None else {"known": False},
        }

    def covered_columns(self):
        """The output columns whose lineage reaches a non-public source."""
        return sorted(
            name for name, roots in self.sources.items()
            if self._classification(roots) != "public"
        )

    def _decide_release(self, to, materialized=None):
        if self._tn:
            raise PolicyDenied("Use release_tn for a native TN-bound frame; its signed release retains all contributing contracts")
        if self.tn_governance.get("policy") != self.policy.policy_ref:
            raise PolicyDenied("TN governance body and compiled policy reference differ")
        if materialized is None:
            materialized = self._support.frame.collect()
        decision = self.evaluator.decide(self._policy_input(to, materialized))
        if not decision.allow:
            raise PolicyDenied(decision.reason)
        return decision

    def release(self, path, *, to: str, label_map=None):
        materialized = self._support.frame.collect()
        decision = self._decide_release(to, materialized)
        return self._write_release(path, decision,
                                   label_map=label_map or self.label_map,
                                   materialized=materialized.select(list(self.sources)))

    @property
    def tn_object(self):
        """An independent native working copy; mutation cannot affect sibling frames."""
        return self._tn.data.copy() if self._tn else None

    def release_tn(self, *, use, to, decide, object_type=None, group=None, rows_field=None,
                   metadata_group=None):
        from .tn_boundary import release_tn
        return release_tn(self, use=use, to=to, decide=decide, object_type=object_type,
                          group=group, rows_field=rows_field, metadata_group=metadata_group)

    def release_delta(self, path, *, to: str):
        """Release to a Delta table whose commit log carries the governance basis."""
        from .delta import write_delta_release
        materialized = self._support.frame.collect()
        decision = self._decide_release(to, materialized)
        version = write_delta_release(self, path, decision, self.covered_columns(), materialized=materialized.select(list(self.sources)))
        return version

    def _write_release(self, path, decision, extra=None, cipher=None, seal_marker=None,
                       label_map=None, materialized=None):
        if materialized is None:
            materialized = self.frame.collect()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if cipher is not None:
            buffer = io.BytesIO()
            materialized.write_parquet(buffer)
            path.write_bytes(cipher.seal(buffer.getvalue(), seal_marker))
        else:
            materialized.write_parquet(path)
        manifest_path = Path(str(path) + ".gov.json")
        manifest = {
            "schema": "tn.polars-release.v1",
            "file": path.name,
            "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "policy_ref": self.policy.policy_ref,
            "compiled_policy_sha256": policy_sha256(self.policy),
            "tn_governance": self.tn_governance,
            "opa_decision": {
                "allow": decision.allow,
                "reason": decision.reason,
                "id": decision.decision_id,
            },
            "lineage": {name: sorted(roots) for name, roots in self.sources.items()},
            "row_selection_sources": sorted(self.row_sources),
            "covered_columns": self.covered_columns(),
            "sensitivity_label": sensitivity_block(self.covered_columns(), label_map),
        }
        if cipher is not None:
            manifest["sealed"] = {"cipher": CIPHER_NAME, "marker": seal_marker}
        manifest.update(extra or {})
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return ReleaseArtifact(path=path, manifest_path=manifest_path)


class GovernedGroupBy:
    """Grouped expressions with contributor and policy continuity."""

    def __init__(self, parent, keys):
        self.parent = parent
        self.keys = keys

    def agg(self, *expressions):
        key_sources = dict(item for key in self.keys for item in self.parent._outputs(key))
        aggregate_sources = dict(item for expression in expressions
                                 for item in self.parent._outputs(expression))
        row_sources = set(self.parent.row_sources)
        expressions = business_expressions(expressions, self.parent.frame.collect_schema())
        if self.parent._tn:
            row_sources.update(root for roots in key_sources.values() for root in roots)
        support = self.parent._support.aggregate(self.keys, expressions)
        return self.parent._child(
            support.frame.select(list(key_sources | aggregate_sources)),
            sources=key_sources | aggregate_sources,
            row_sources=row_sources, operation="aggregate", support=support,
            parameters={"keys": [expression_record(key) for key in self.keys],
                        "expressions": [expression_record(expr) for expr in expressions]},
        )
