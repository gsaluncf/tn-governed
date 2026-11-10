"""Run one measured SQL-to-report case without retrying a native request.

Both modes share SQL assignment, the governed dataframe with real OPA, native
publications, model service, recipient, and pending-review workflow. They differ
only in downstream scalar dispatch: overloaded primitives or explicit callbacks.
"""

from __future__ import annotations

import argparse
import gc
import importlib.metadata
import json
import platform
import sqlite3
import subprocess
import time
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import tn
import tn_llama_client
import tn_polars

import tn_governed.values as governed
from tn_governed.native_objects import NativeObjects
from tn_governed.native_run import governed_server, wsl_path
from tn_governed.publications import write_once
from tn_governed.values.catalog import AssignedRules
from tn_governed.values.evidence import EvidenceRecorder
from tn_governed.values.model import NativeModelEndpoint, digest, prepare_native_model
from tn_governed.values.provision import provision
from tn_governed.values.sql import GovernedSQL, source_identity

from .case_request import CaseRequest, Workload
from .case_study import (
    APPLICATION,
    MODEL_USE,
    NOTICE,
    PURPOSE,
    RECIPIENT_USE,
    REVIEW_ACTION,
    handle,
    policy,
)
from .dispatch import Operations
from .frames import DataframeContext, DataframeGovernance, dataframe_calculate
from .metrics import stage as profile_stage
from .performance_env import implementation_library, model_uses_wsl, native_module_path

CLAIM = "Suitable for identifying the synthetic company in this internal demonstration report."
PROMPT = (
    "Prepare a short internal HTML draft about the supplied synthetic calculation for a human reviewer. "
    "State the supplied demonstration amount without treating it as a market quote. "
    "Mark the report as requiring human review, using the exact carried review notice in a visible paragraph. "
    "Generate the report now; do not claim a human has reviewed it. Use no CSS, hidden content, or external resources."
)
VERIFICATION_FACTS = ("record_count", "record_kinds", "outputs",
                      "source_editions", "policy_revisions")


@contextmanager
def _timed(timings, name):
    with profile_stage(name):
        started = time.perf_counter()
        try:
            yield
        finally:
            timings[name] = timings.get(name, 0.0) + time.perf_counter() - started


def _error(exc, stage):
    # Exception strings can contain credentials or configuration data.
    return {"stage": stage, "type": type(exc).__name__, "native_code": getattr(exc, "code", None)}


def _adapter_sources(repository):
    """Identify the actual editable adapter and installed transport sources."""
    roots = {
        "tn_governed": repository / "src/tn_governed",
        "tn_polars": Path(tn_polars.__file__).resolve().parent,
        "tn_llama_client": Path(tn_llama_client.__file__).resolve().parent,
    }
    return {f"{name}/{path.relative_to(folder).as_posix()}": digest(path)
            for name, folder in roots.items() for path in sorted(folder.rglob("*.py"))}


def _experiment_sources():
    """Digest the evaluation modules and tn-governed's value modules."""
    folders = {"experiments/paper_evaluation/": Path(__file__).parent,
               "tn_governed/values/": Path(governed.__file__).parent}
    return {prefix + path.name: digest(path)
            for prefix, folder in folders.items() for path in sorted(folder.glob("*.py"))}


class _Case:
    """One case: its stages, its live sessions and values, and the evidence it retains."""

    def __init__(self, root, request, repository):
        self.root, self.request, self.repository = root, request, repository
        self.binary = Path(request.binary or repository / ".runtime/dependencies/tn-llama/llama-server").resolve()
        self.model_path = Path(request.model_path or repository / ".artifacts/models/Qwen3-4B-Q4_K_M.gguf").resolve()
        self.stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.workload = Workload.of(request)
        self.timings, self.stage = {}, "preflight"
        self.outputs, self.internal, self.brief, self.report, self.config_path = {}, None, None, None, None
        self.summary = self._summary()

    def run(self):
        """Run every stage once; a failure is recorded under its stage and never retried."""
        write_once(self.root / "case-request.json", json.dumps(
            {k: v for k, v in self.summary.items() if k not in {"timings_seconds", "error"}}, indent=2).encode())
        started = time.perf_counter()
        try:
            self._preflight()
            self._setup()
            with ExitStack() as stack:
                self._workflow(stack)
            self._verify()
        except Exception as exc:
            self.summary["error"] = _error(exc, self.stage)
            self.summary["completed"] = False
        finally:
            gc.unfreeze()
            self.timings["total"] = time.perf_counter() - started
            write_once(self.root / "case-summary.json", json.dumps(self.summary).encode())
        return self.summary

    @contextmanager
    def _step(self, name, timed=None):
        """Name the current stage for failures and accumulate its time."""
        self.stage = name
        with _timed(self.timings, timed or name):
            yield

    def _summary(self):
        request = self.request
        return {
            "schema": "tn.paper-case.v1", "run_directory": str(self.root), "created_utc": self.stamp,
            "mode": request.mode, "rows": request.rows, "depth": request.depth, "branches": request.branches,
            "with_model": bool(request.model), "with_claim": bool(request.claim), "completed": False,
            "verified": False, "timings_seconds": self.timings, "error": None,
            "publication_storage": request.storage, "working_representation": "native_objects",
            "sql_batch_size": request.sql_batch_size, "numeric_type": request.numeric_type,
            "expected_content": self.workload.expected_content,
        }

    def _preflight(self):
        """Refuse a TN runtime that differs from the build record, before any SQL runs."""
        record = Path(self.request.sdk_build_record or self.repository / "config/sdk-build.json").read_bytes()
        self.sdk = json.loads(record)
        self.native_module = native_module_path()
        if (importlib.metadata.version("tn-proto") != self.sdk["version"]
                or digest(self.native_module) != self.sdk["install"]["native_module_sha256"]):
            raise RuntimeError("installed TN runtime differs from the selected build record")
        write_once(self.root / "sdk-build.json", record)
        if self.request.model and (not self.binary.is_file() or not self.model_path.is_file()):
            raise FileNotFoundError("configured native model binary or GGUF is missing")
        self.model_wsl = model_uses_wsl(self.binary)
        self.implementation = implementation_library(self.binary) if self.request.model else None
        if self.request.mode == "explicit":
            from .explicit import ExplicitOperations  # noqa: F401 - Validate the adapter before provisioning.

    def _setup(self):
        with self._step("setup"):
            self.database = self.root / "market.sqlite"
            self.workload.write(self.database)
            self.paths = provision(self.root / "sessions", roles=["catalog", "gateway", "worker", "model-reader", "observer"],
                                   read_only_roles=("model-reader", "observer"))
            self.output_paths = provision(self.root / "output-sessions", roles=["model-writer", "recipient"],
                                          groups=["tn.agents", "default"], read_only_roles=("recipient",))
            self.store = NativeObjects()

    def _workflow(self, stack):
        """Open sessions, compute, generate, and complete; retain the evidence even after a failure."""
        self._open(stack)
        try:
            self._compute()
            if self.request.model:
                self._generate()
            if self.request.completion_handler is not None:
                self._complete()
            self.summary["completed"] = True
        except Exception as exc:
            self.summary["error"] = _error(exc, self.stage)
        finally:
            self._retain()

    def _open(self, stack):
        """Open each role's session, publish the column assignment, and build the SQL source."""
        stack.enter_context(self.store)
        self.sessions = {role: stack.enter_context(tn.Session.from_config(str(path)))
                         for role, path in {**self.paths, **self.output_paths}.items() if role != "observer"}
        catalog = self.sessions["catalog"]
        self.authority = catalog.did
        self.admin = catalog.policy("experiment.administration")
        self.audit_policy = catalog.policy("experiment.evidence")
        self.writers = [self.sessions[role].did for role in ("gateway", "worker")]
        self.catalog_name = "paper_" + uuid4().hex[:12]
        with _timed(self.timings, "assignment"):
            self.publisher = self._resolver("catalog")
            self.assignment_id = self._publish_assignment()
            self.contexts = {role: self._context(role) for role in ("gateway", "worker")}
        self.context = self.contexts["worker"]
        self.db = GovernedSQL(self.database, gateway=self.contexts["gateway"], consumer=self.context,
                              edition_publisher=self.publisher, directory=self.root / "editions",
                              detect_types=sqlite3.PARSE_DECLTYPES, batch_size=self.request.sql_batch_size)

    def _resolver(self, role):
        return DataframeGovernance(self.request.unity_url, self.catalog_name, session=self.sessions[role],
                                   authority=self.authority, administration=self.admin, store=self.store)

    def _publish_assignment(self):
        model = {"use": MODEL_USE, "recipient_use": RECIPIENT_USE,
                 "destinations": ["internal-model"], "report_destination": "internal-report",
                 "required_disclosure": NOTICE, "required_tool": "log_compliance_creation", "review": REVIEW_ACTION}
        columns = {column: {"kind": kind, "markdown": policy(column), "rule": {
            "destinations": ["internal-console"], "model": model, "additional_uses": [MODEL_USE, RECIPIENT_USE],
        }} for column, kind in (("name", "str"), ("value", self.request.numeric_type))}
        return self.publisher.publish_assignment(
            self.root / "assignment", table="market_data", source_identity=source_identity(self.database),
            application=APPLICATION, actors=["analyst"], purposes=[PURPOSE], columns=columns,
            decimal_precision=self.request.decimal_precision, decimal_scale=self.request.decimal_scale)

    def _context(self, role):
        resolution = self._resolver(role)
        rules = AssignedRules(resolution, actor="analyst", application=APPLICATION,
                              purpose=PURPOSE, writers=self.writers)
        recorder = EvidenceRecorder(self.sessions[role], self.store, self.audit_policy)
        return DataframeContext(self.sessions[role], recorder, rules, application=APPLICATION,
                                purpose=PURPOSE, actor="analyst", resolver=resolution)

    def _compute(self):
        """Query the source, attest the name, and compute the brief the model receives."""
        fetched = self._query()
        gc.freeze()
        if self.request.cell_reads:
            self._read_cells(fetched)
        name = self._attest(fetched[0][0])
        frame_rows = fetched.with_row(0, (name, fetched[0][1]))
        with self._step("dataframe"), self.context:
            amount = dataframe_calculate(self.context, frame_rows)
            self.outputs["dataframe_result"] = handle(amount)
            self.summary["dataframe"] = self.context.frame_runs
        self.brief = self._brief(name, amount)
        with self._step("console_disclosure"):
            self.internal = self.brief.reveal(self.context, destination="internal-console")
            if self.internal != self.summary["expected_content"]:
                raise RuntimeError("application calculation differs from its declared workload")

    def _query(self):
        rows = self.request.rows
        with self._step("query"):
            fetched = self.db.execute("SELECT name, value FROM market_data LIMIT ?", (rows,)).fetch_batches()
            if len(fetched) != rows:
                raise RuntimeError("SQL returned a different row count")
        return fetched

    def _read_cells(self, fetched):
        rows, reads = self.request.rows, self.request.cell_reads
        with self._step("cell_read"), self.context:
            ops = Operations(self.context, self.request.mode)
            for index in range(reads):
                ops.add_literal(fetched[index * rows // reads][1], 1)

    def _attest(self, name):
        with self._step("claim"), self.context:
            if self.request.claim:
                name = name.attest(CLAIM, self.context)
                for number in range(self.request.additional_claims):
                    name = name.attest(f"{CLAIM} Reviewed statement {number + 2}.", self.context)
                self.outputs["attested_name"] = handle(name)
        return name

    def _brief(self, name, amount):
        """Apply the requested depth and branches; return the brief that reaches the model."""
        with self._step("compute"), self.context:
            ops = Operations(self.context, self.request.mode)
            for _ in range(self.request.depth):
                amount = ops.add_literal(amount, 1)
            label = ops.upper(name)
            for part in [ops.prefix(name) for _ in range(self.request.branches - 1)]:
                label = ops.concat(ops.concat_literal(label, " / "), part)
            brief = ops.concat_literal(ops.concat(ops.concat_literal(label, ": "), ops.as_string(amount)),
                                       " demonstration cents")
            self.outputs.update(model_input=handle(brief), amount=handle(amount))
        return brief

    def _generate(self):
        """Prepare one native request, start one fresh server, and generate the report."""
        directory = self.root / "native-model"
        with self._step("native_prepare"):
            self.config_path, reader, requirements = prepare_native_model(
                self.brief, context=self.context, input_session=self.sessions["model-reader"],
                output_session=self.sessions["model-writer"], recipient_session=self.sessions["recipient"],
                input_config=self.paths["model-reader"], output_config=self.output_paths["model-writer"],
                directory=directory, model=self.model_path, binary=self.binary,
                translate=wsl_path if self.model_wsl else str, runtime_limits=self.request.runtime_limits)
        api_key = uuid4().hex
        with ExitStack() as model_stack:
            with self._step("server_start"):
                base_url = model_stack.enter_context(governed_server(
                    binary=self.binary, model=self.model_path, config=self.config_path, port=self.request.port,
                    api_key=api_key, wsl=self.model_wsl, gpu_layers=self.request.gpu_layers))
            endpoint = NativeModelEndpoint(context=self.context, value=self.brief, base_url=base_url,
                                           api_key=api_key, output_reader=reader, directory=directory,
                                           requirements=requirements, runtime_config=self.config_path)
            with self._step("generation"), self.context:
                self.report = endpoint.generate(self.brief, prompt=PROMPT)
            write_once(self.root / "report.html", self.report.report_html.encode())
            write_once(self.root / "review.json", json.dumps(self.report.review.to_dict(), indent=2).encode())

    def _complete(self):
        with self._step("completion", timed="completion_wall"):
            completion = self.request.completion_handler(self.context, self.report, self.brief, self.root)
        self.summary["completion"] = completion
        self.timings["tools"] = completion["processing_seconds"]
        if not completion.get("completed") or not completion.get("verified"):
            raise RuntimeError("completion handler did not produce verified output")

    def _retain(self):
        """Export publications and tapes, then write the run manifest the verifier reads."""
        recorder = self.context.recorder
        handoffs = [record for record in map(recorder.read, recorder.ids())
                    if record.body["kind"] == "ModelHandoff"]
        with _timed(self.timings, "export"):
            self.store.export(self.root / "publications")
            tapes = {role: {**context.recorder.export(self.root / "tapes" / role), "path": "tapes/" + role}
                     for role, context in self.contexts.items()}
        manifest = self._manifest(tapes)
        if handoffs:
            manifest["model"] = self._model_facts()
        write_once(self.root / "run.json", json.dumps(manifest).encode())

    def _manifest(self, tapes):
        request, db = self.request, self.db
        recipient_objects = []
        if self.brief is not None:
            carried = self.brief.publication
            bindings = self.context.session.governance(carried.object).governance.dataset_bindings
            recipient_objects = sorted({obj.id for obj in carried.objects()} | {
                self.assignment_id, *self.publisher.assignments[self.assignment_id]["revisions"],
                *(binding.edition_record_id for binding in bindings)})
        return {
            "schema": "tn.policy-run.v2", "created_utc": self.stamp,
            "execution": "live Java Unity, SQLite, governed Polars with OPA and native TN" + (
                ", governed model report and pending review" if request.model else ", scalar computation"),
            "unity": {"url": request.unity_url, "catalog": self.catalog_name,
                      "mode": "local development; authorization disabled"},
            "request": {"actor": "analyst", "application": APPLICATION, "purpose": PURPOSE,
                        "identity_source": "trusted local demonstration configuration"},
            "authority": self.authority, "writers": self.writers, "audit_policy": self.audit_policy.fields,
            "administration_policy": self.admin.fields, "assignment_id": self.assignment_id,
            "source": source_identity(self.database), "observer_config": "sessions/observer/tn.yaml",
            "tapes": tapes, "source_editions": db.editions, "recipient_objects": recipient_objects,
            "outputs": self.outputs,
            "console_disclosures": {"internal": self.internal}, "sql_executions": db.executions,
            "unity_resolutions": {role: ctx.resolver.requests for role, ctx in self.contexts.items()},
            "runtime": self._runtime_facts(),
            "evaluation": self._evaluation_facts(),
        }

    def _runtime_facts(self):
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repository,
                                text=True, capture_output=True, check=True).stdout.strip()
        return {
            "python": platform.python_version(), "platform": platform.platform(),
            "tn_proto": self.sdk["version"], "native_module_sha256": digest(self.native_module),
            "wheel_sha256": self.sdk["wheel_sha256"], "repository_commit": commit,
            "dependency_versions": {name: importlib.metadata.version(name) for name in
                                    ("polars", "tn-polars", "tn-llama-client", "wasmtime")},
            "sdk_build_record": "sdk-build.json",
            "sdk_build_record_sha256": digest(self.root / "sdk-build.json"),
            "uv_lock_sha256": digest(self.repository / "uv.lock"),
            "pyproject_sha256": digest(self.repository / "pyproject.toml"),
            "adapter_source_sha256": _adapter_sources(self.repository),
            "experiment_source_sha256": _experiment_sources(),
        }

    def _evaluation_facts(self):
        request = self.request
        return {
            "mode": request.mode, "rows": request.rows, "depth": request.depth, "branches": request.branches,
            "publication_storage": request.storage, "working_representation": "native_objects",
            "claim": bool(request.claim), "requested_model": bool(request.model),
            "error": self.summary["error"], "expected_content": self.summary["expected_content"],
            "comparison_scope": "Shared governed dataframe; automatic versus explicit downstream scalar propagation",
            "dataframe": self.context.frame_runs,
        }

    def _model_facts(self):
        report = self.report
        return {
            "completed": report is not None, "required_disclosure": NOTICE,
            "input_object_id": self.brief.reference.object_id,
            "output_object_id": report.object.id if report else None,
            "writer": self.sessions["model-writer"].did, "use": MODEL_USE,
            "recipient_use": RECIPIENT_USE, "destination": "internal-report",
            "recipient_config": "output-sessions/recipient/tn.yaml",
            "model_reader_config": "sessions/model-reader/tn.yaml",
            "runtime_config": "native-model/runtime.json", "runtime_config_sha256": digest(self.config_path),
            "model_path": str(self.model_path), "model_sha256": digest(self.model_path),
            "binary_path": str(self.binary), "binary_sha256": digest(self.binary),
            "implementation_path": str(self.implementation),
            "implementation_sha256": digest(self.implementation),
            "tool_object_ids": [obj.id for obj in report.release.tool_objects] if report else [],
            "result_record_id": report.result_record_id if report else None,
            "review": report.review.to_dict() if report and report.review else None,
        }

    def _verify(self):
        """Verify the retained run; a verification failure leaves the case incomplete."""
        self.stage = "verification"
        from tn_governed.values.verify import verify

        from .verify_frame import verify_frame
        gc.freeze()
        try:
            with _timed(self.timings, self.stage):
                verification = verify(self.root)
                if self.outputs.get("dataframe_result"):
                    self.summary["dataframe_verification"] = verify_frame(self.root)
                self._check_claims(verification)
            self.summary["verified"] = True
            self.summary["verification"] = {key: verification[key] for key in VERIFICATION_FACTS}
            if "model" in verification:
                self.summary["model"] = verification["model"]
        except Exception as exc:
            self.summary["verification_error"] = _error(exc, self.stage)
            self.summary["completed"] = False

    def _check_claims(self, verification):
        """The model input, and a completed model result, keep the original claim."""
        if not (self.request.claim and self.outputs.get("model_input")):
            return
        outputs = verification["outputs"]
        required = set(outputs["attested_name"]["claims"])
        if not required or any(not required <= set(outputs[name]["claims"])
                               for name in ("dataframe_result", "amount", "model_input")):
            raise RuntimeError("a calculated output omitted an original claim")
        if verification.get("model", {}).get("completed") and not required <= set(verification["model"]["source_claim_ids"]):
            raise RuntimeError("required original claim is absent from model result evidence")


def run_case(root, mode, **options):
    """Return a case summary and preserve the verifier's run manifest.

    Options are the fields of `CaseRequest`. A model attempt uses one fresh server
    and one native request. Failures remain failures; no retry, fallback, or
    fabricated report is performed here.
    """
    request = CaseRequest(mode, **options).checked()
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=False)
    return _Case(root, request, Path(__file__).resolve().parents[2]).run()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--numeric-type", choices=["int", "float", "Decimal"], default="int")
    parser.add_argument("--storage", choices=["files"], default="files",
                        help="Archive format at the completed application boundary")
    parser.add_argument("--decimal-precision", type=int, default=38)
    parser.add_argument("--decimal-scale", type=int, default=4)
    parser.add_argument("--mode", choices=("primitive", "explicit"), required=True)
    parser.add_argument("--rows", type=int, default=1)
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument("--branches", type=int, default=1)
    parser.add_argument("--with-model", action="store_true")
    parser.add_argument("--without-claim", action="store_true")
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--unity-url", default="http://127.0.0.1:8080")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--model-path", type=Path)
    parser.add_argument("--port", type=int, default=18325)
    parser.add_argument("--gpu-layers", type=int)
    parser.add_argument("--sdk-build-record", type=Path,
                        help="Expected native build record (default: repository's pinned build)")
    args = parser.parse_args()
    summary = run_case(args.run_directory, args.mode, rows=args.rows, depth=args.depth,
        branches=args.branches, model=args.with_model, claim=not args.without_claim,
        unity_url=args.unity_url, binary=args.binary, model_path=args.model_path, port=args.port, numeric_type=args.numeric_type,
        decimal_precision=args.decimal_precision, decimal_scale=args.decimal_scale, storage=args.storage,
        sdk_build_record=args.sdk_build_record, gpu_layers=args.gpu_layers)
    print(json.dumps(summary, indent=2))
    return 0 if summary["completed"] and summary["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
