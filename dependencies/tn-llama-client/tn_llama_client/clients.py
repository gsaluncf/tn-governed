"""HTTP clients for governed tn-llama requests and recipient admission."""

import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

import tn.reader
from tn.canonical import _canonical_bytes
from tn.trust import parse_ed25519_did_key

from .protocol import (
    EncryptedReportRelease,
    NativeModelRelease,
    ReportRelease,
    SourceRecord,
    _without_duplicate_keys,
    build_governed_request,
    build_model_request,
)
from .tool_evidence import ToolEvidenceExpectation
from .transcript import HttpTranscript


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())
_HTTP_CLOCK = [0.0]


def model_http_seconds():
    """Wall-clock seconds this process has spent waiting on model-server responses."""
    return _HTTP_CLOCK[0]
_FOUNDATIONAL_OUTPUT_GOVERNANCE = frozenset(
    {
        "instruction",
        "use_for",
        "do_not_use_for",
        "consequences",
        "on_violation_or_error",
        "policy",
    }
)


def _reject_duplicate_aad_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, member in pairs:
        if key in value:
            raise ValueError("release TN AAD contains duplicate JSON keys")
        value[key] = member
    return value


class GovernedRequestDenied(Exception):
    def __init__(self, status: int, code: str, body: bytes) -> None:
        self.status = status
        self.code = code
        self.body = body
        super().__init__(f"governed request denied: {status} {code}")


class TnOutputReader:
    """Open released groups through the official TN recipient-reader API."""

    def __init__(self, key_dir: Path, ledger_path: Path) -> None:
        self.key_dir = key_dir
        self.ledger_path = ledger_path

    def open(
        self, encrypted: EncryptedReportRelease, transcript: HttpTranscript
    ) -> ReportRelease:
        group = "tn.agents"
        stage = "aad_profile"
        prior_size: int | None = None
        try:
            aad_marker = self._validated_aad_marker(encrypted)
            stage = "recipient_open"
            prior_size = self._append_candidate(encrypted)
            transcript.log_state(
                "encrypted_release_appended",
                output_event_id=encrypted.output_event_id,
                output_row_hash=encrypted.output_row_hash,
                ledger_path=str(self.ledger_path),
                prior_bytes=prior_size,
                appended_bytes=len(encrypted.output_ndjson.encode("utf-8")),
            )
            opened = {}
            for group in ("tn.agents", "default"):
                opened[group] = self._open_group(
                    self.ledger_path, group, encrypted, transcript
                )
            stage = "payload_validation"
            default = opened["default"].get("default")
            if not isinstance(default, dict) or not isinstance(
                default.get("report_html"), str
            ):
                raise ValueError(
                    "opened default group must contain default.report_html"
                )
            governance = opened["tn.agents"]
            missing = sorted(
                name
                for name in _FOUNDATIONAL_OUTPUT_GOVERNANCE
                if not isinstance(governance.get(name), str)
                or not governance[name]
            )
            if missing:
                raise ValueError(
                    "opened tn.agents omitted foundational governance: "
                    + ", ".join(missing)
                )
            stage = "governance_binding"
            if governance["policy"] != aad_marker["policy"]:
                raise ValueError(
                    "authenticated AAD policy does not match opened tn.agents.policy"
                )
            release = ReportRelease(
                run_id=encrypted.run_id,
                source_event_id=encrypted.source_event_id,
                source_row_hash=encrypted.source_row_hash,
                output_event_id=encrypted.output_event_id,
                output_row_hash=encrypted.output_row_hash,
                output_ndjson=encrypted.output_ndjson,
                trace=encrypted.trace,
                report_html=default["report_html"],
                governance=governance,
            )
            transcript.log_state(
                "encrypted_release_verified",
                output_event_id=encrypted.output_event_id,
                output_row_hash=encrypted.output_row_hash,
            )
        except Exception as error:
            if prior_size is not None:
                self._rollback_candidate(prior_size)
            transcript.log_state(
                "encrypted_release_rejected",
                stage=stage,
                group=group,
                error_type=type(error).__name__,
                output_row_hash=encrypted.output_row_hash,
                ledger_rolled_back=prior_size is not None,
            )
            raise
        return release

    @staticmethod
    def _validated_aad_marker(
        encrypted: EncryptedReportRelease,
    ) -> dict[str, str]:
        raw = encrypted.row["tn_aad"]
        try:
            aad = json.loads(raw, object_pairs_hook=_reject_duplicate_aad_keys)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError("release TN AAD is not canonical JSON") from error
        if _canonical_bytes(aad) != raw.encode("utf-8"):
            raise ValueError("release TN AAD is not canonical JSON")
        if not isinstance(aad, dict) or set(aad) != {"default", "tn.agents"}:
            raise ValueError("release TN AAD does not cover the encrypted groups")
        marker = aad["tn.agents"]
        if (
            not isinstance(marker, dict)
            or set(marker) != {"governed_by", "policy"}
            or aad["default"] != marker
            or not all(isinstance(value, str) and value for value in marker.values())
        ):
            raise ValueError("release TN AAD governance marker is invalid")
        try:
            parse_ed25519_did_key(marker["governed_by"])
        except Exception as error:
            raise ValueError("release TN AAD governing DID is invalid") from error
        identity, separator, digest = marker["policy"].rpartition("#sha256:")
        if (
            not separator
            or not identity
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("release TN AAD policy reference is invalid")
        return marker

    def _append_candidate(self, encrypted: EncryptedReportRelease) -> int:
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        prior_size = self.ledger_path.stat().st_size if self.ledger_path.exists() else 0
        if prior_size:
            with self.ledger_path.open("rb") as ledger:
                ledger.seek(-1, 2)
                if ledger.read(1) != b"\n":
                    raise ValueError("received-output ledger is not valid NDJSON")
        with self.ledger_path.open("ab") as ledger:
            ledger.write(encrypted.output_ndjson.encode("utf-8"))
            ledger.flush()
        return prior_size

    def _rollback_candidate(self, prior_size: int) -> None:
        with self.ledger_path.open("r+b") as ledger:
            ledger.truncate(prior_size)

    def _open_group(
        self,
        row_path: Path,
        group: str,
        encrypted: EncryptedReportRelease,
        transcript: HttpTranscript,
    ) -> dict[str, object]:
        entries = list(
            tn.reader.read_as_recipient(
                row_path,
                self.key_dir,
                group=group,
                verify_signatures=True,
            )
        )
        if not entries:
            raise ValueError(
                f"official TN reader returned no rows for {group}"
            )
        for entry in entries:
            valid = entry.get("valid")
            if not isinstance(valid, dict) or not all(
                valid.get(name) is True
                for name in ("record", "row_hash", "signature", "chain", "aad")
            ):
                raise ValueError(f"official TN reader rejected release group {group}")
        entry = entries[-1]
        if entry.get("envelope") != encrypted.row:
            raise ValueError("official TN reader did not return the exact release row")
        plaintext = entry.get("plaintext")
        body = plaintext.get(group) if isinstance(plaintext, dict) else None
        if not isinstance(body, dict) or any(
            marker in body for marker in ("$decrypt_error", "$no_read_key")
        ):
            raise ValueError(f"official TN reader could not open release group {group}")
        transcript.log_state(
            "release_group_opened",
            group=group,
            output_row_hash=encrypted.output_row_hash,
            row_hash=True,
            signature=True,
            chain=True,
            aad=True,
        )
        return body


class NativeOutputReader:
    """Admit a report only after its configured tool evidence has been verified.

    Tool expectations validate supplied completions. Required tools name the
    subset whose evidence must be present before report content is opened.
    Pass ToolEvidenceExpectation records in tool_expectations and their names
    in required_tools. Each record binds a name, input sections, and publication
    type; the reader also checks the source, release context, and run identity.
    Supplied completions must use distinct call identities and one request digest.

    required_tools defaults to empty for workflows without required tool calls.
    The legacy expected_tool_name/sections/object_type arguments configure one
    optional expectation; name it in required_tools to require its completion.
    expected_request_digest binds completion to a trusted submitted request and
    requires signed tool evidence. An open-call digest cannot replace a different
    configured digest. Leaving both unset preserves workflows without tool calls.
    """

    def __init__(
        self, session, *, expected_source, expected_writer, use, destination,
        catalog, policy_dag, decide, resolve_ancestor=None, release_use=None, carried_policy=False,
        expected_source_view=None, source_edition_id=None,
        expected_object_type="report.generated",
        expected_tool_object_type="compliance.creation.logged",
        expected_tool_name=None,
        expected_tool_sections=None,
        tool_expectations=(),
        required_tools=(),
        expected_request_digest=None,
        lineage_max_objects=1024,
        lineage_max_depth=64,
    ):
        import tn
        if not isinstance(expected_source, tn.GovernedObject) or not isinstance(use, tn.UseContext):
            raise TypeError("recipient requires its exact native source and UseContext")
        if release_use is not None and not isinstance(release_use, tn.UseContext):
            raise TypeError("release use must be a native UseContext")
        if (type(lineage_max_objects) is not int or not 1 <= lineage_max_objects <= 65536
                or type(lineage_max_depth) is not int or not 1 <= lineage_max_depth <= 256):
            raise ValueError("lineage limits require 1..65536 objects and 1..256 depth")
        self.lineage_verifier = tn.LineageVerifier(max_objects=lineage_max_objects,
                                                  max_depth=lineage_max_depth)
        self.session = session
        self.expected_source = expected_source
        self.expected_writer = expected_writer
        self.use = use
        self.destination = destination
        self.catalog = catalog
        self.policy_dag = policy_dag
        if carried_policy:
            from tn.governed import GovernanceView
            if not isinstance(expected_source_view, GovernanceView) or expected_source_view.object.id != expected_source.id:
                raise ValueError("carried-policy recipient requires the verified view of its exact model input")
        self.source_binding = None
        if source_edition_id is not None:
            if not carried_policy:
                raise ValueError("a source edition requires a current policy carrier")
            edition = catalog.get(source_edition_id)
            if edition is None:
                raise ValueError("source edition was not admitted by this recipient")
            selection = catalog.select(edition.dataset, edition.edition, source_edition_id, use)
            selection.verify_source(expected_source_view, use, edition.source_groups)
            self.source_binding = selection.binding
        self.expected_source_view = expected_source_view
        self.carried_policy = carried_policy
        self.resolve_ancestor = resolve_ancestor
        self.decide = decide
        self.release_use = release_use
        self.expected_object_type = expected_object_type
        self.expected_tool_object_type = expected_tool_object_type
        self.expected_tool_name = expected_tool_name
        self.expected_tool_sections = (
            None if expected_tool_sections is None else tuple(expected_tool_sections)
        )
        expectations = {}
        for expectation in tool_expectations:
            if not isinstance(expectation, ToolEvidenceExpectation):
                raise TypeError("tool expectations must be ToolEvidenceExpectation records")
            if expectation.name in expectations:
                raise ValueError("tool expectations must have unique names")
            expectations[expectation.name] = expectation
        if expected_tool_name is not None or expected_tool_sections is not None:
            legacy = ToolEvidenceExpectation(
                expected_tool_name, self.expected_tool_sections, expected_tool_object_type,
            )
            configured = expectations.get(legacy.name)
            if configured is not None and configured != legacy:
                raise ValueError("tool expectation differs from the single-tool configuration")
            expectations[legacy.name] = legacy
        if isinstance(required_tools, str):
            raise TypeError("required tools must be a sequence of configured names")
        required = tuple(required_tools)
        if any(not isinstance(name, str) or name not in expectations for name in required):
            raise ValueError("every required tool must have a configured evidence expectation")
        if len(set(required)) != len(required):
            raise ValueError("required tools must have unique names")
        if required and release_use is None:
            raise ValueError("required tool evidence needs the expected release use")
        self.tool_expectations = MappingProxyType(expectations)
        self.required_tools = frozenset(required)
        self.expected_request_digest = self._request_digest(expected_request_digest)

    @staticmethod
    def _request_digest(value):
        if value is not None and (not isinstance(value, str)
                                  or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)):
            raise ValueError("expected request digest must be a canonical sha256 identity")
        return value

    @staticmethod
    def _has_exact_sources(sources, expected_objects) -> bool:
        return len(sources) == len(expected_objects) and all(
            sum(reference.references(object) for reference in sources) == 1
            for object in expected_objects
        )

    @staticmethod
    def _matches_references(actual, expected):
        return len(actual) == len(expected) and all(
            any(ref.references_with_policy(view.object, view.governance)
                and set(ref.groups).issubset(view.object.group_names) for ref in actual)
            for view in expected
        )

    @staticmethod
    def _has_same_contracts(actual, expected, source_binding=None) -> bool:
        actual_contracts = actual.governance.policies
        expected_contracts = expected.governance.policies
        return (
            actual.governance.matches_contract(expected.governance)
            and len(actual_contracts) == len(expected_contracts)
            and all(
                sum(contract.matches_contract(source) for source in expected_contracts) == 1
                for contract in actual_contracts
            )
            and all(
                sum(contract.matches_contract(source) for contract in actual_contracts) == 1
                for source in expected_contracts
            )
            and actual.governance.dataset_bindings
            == ([source_binding] if source_binding is not None else expected.governance.dataset_bindings)
        )

    def _has_expected_release_context(self, view) -> bool:
        context = view.governance.get("release_context")
        return (
            isinstance(context, dict)
            and context.get("destination") == self.destination
            and (
                self.release_use is None
                or all(
                    context.get(key) == getattr(self.release_use, key)
                    for key in ["application", "purpose", "operation"]
                )
            )
        )

    def _accept(self, admission, object) -> bool:
        return (
            admission.writer == self.expected_writer
            and admission.object.id == object.id
            and admission.use_context == self.use
            and self.catalog.accepts(admission, self.policy_dag)
            and self.decide(admission)
        )

    def _validate_tool_payload(self, release, tool, payload):
        required = {
            "run_id", "request_digest", "tool_name", "model_tool_call_id",
            "source_object_id", "source_writer", "source_type",
            "selected_sections", "action",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise ValueError("native tool payload does not have the exact configured shape")
        strings = required - {"selected_sections"}
        if any(not isinstance(payload[name], str) or not payload[name] for name in strings):
            raise ValueError("native tool payload requires nonempty string fields")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", payload["request_digest"]):
            raise ValueError("native tool payload request digest is not canonical")
        if any(ord(character) < 32 or ord(character) == 127
               for character in payload["model_tool_call_id"]):
            raise ValueError("native tool payload call identity contains controls")
        expectation = self.tool_expectations.get(payload["tool_name"])
        if expectation is None:
            raise PermissionError("native tool is not configured for recipient admission")
        if tool.object_type != expectation.object_type:
            raise ValueError("native tool publication type differs from its configured tool")
        expected_action = self.release_use.operation if self.release_use is not None else None
        expected = {
            "run_id": release.run_id,
            "tool_name": expectation.name,
            "source_object_id": self.expected_source.id,
            "source_writer": self.expected_source.writer,
            "source_type": self.expected_source.object_type,
            "selected_sections": list(expectation.selected_sections),
            "action": expected_action,
        }
        if expected_action is None or any(payload[name] != value for name, value in expected.items()):
            raise ValueError("native tool payload differs from the configured request")
        return expectation.name, payload["model_tool_call_id"], payload["request_digest"]

    def open(self, release: NativeModelRelease, *, expected_request_digest=None):
        import tn
        expected_digest = self._request_digest(expected_request_digest)
        if (expected_digest is not None and self.expected_request_digest is not None
                and expected_digest != self.expected_request_digest):
            raise ValueError("open request digest differs from the configured request digest")
        expected_digest = expected_digest or self.expected_request_digest
        if not isinstance(release, NativeModelRelease):
            raise TypeError("native recipient requires a version 2 release")
        output = release.output_object
        if not isinstance(output, tn.GovernedObject):
            raise TypeError("native release requires a verified GovernedObject")
        if (release.source_object_id != self.expected_source.id
                or release.output_object_id != output.id):
            raise ValueError("native release does not match the expected input/output identities")
        if output.writer != self.expected_writer:
            raise PermissionError("native report writer is not the configured model publisher")
        if output.object_type != self.expected_object_type:
            raise ValueError("native report does not match the configured report object type")
        if set(output.group_names) != {"default", "tn.agents"}:
            raise ValueError("native report must contain only the configured default report group")
        view = self.session.governance(output)
        if not self._has_expected_release_context(view):
            raise PermissionError("signed report use differs from the expected model operation")
        tool_objects = release.tool_objects
        if (
            not isinstance(tool_objects, tuple)
            or any(not isinstance(tool, tn.GovernedObject) for tool in tool_objects)
            or len({tool.id for tool in tool_objects}) != len(tool_objects)
        ):
            raise TypeError("native release tools must be unique verified GovernedObjects")
        if self.required_tools and not tool_objects:
            raise PermissionError("native report lacks required tool completion evidence")
        if expected_digest is not None and not tool_objects:
            raise PermissionError("native report lacks signed request binding evidence")
        expected_parents = (self.expected_source, *tool_objects)
        sources = view.governance.sources
        if not self._has_exact_sources(sources, expected_parents):
            raise PermissionError(
                "native report does not reference the exact input and tool publications"
            )

        source_view = (self.expected_source_view if self.carried_policy
                       else self.resolve_ancestor(self.expected_source.id))
        if source_view.object.id != self.expected_source.id:
            raise PermissionError("ancestor resolver substituted the expected model input")
        tool_views = {}
        for tool in tool_objects:
            if tool.writer != self.expected_writer:
                raise PermissionError("native tool writer is not the configured model publisher")
            if not any(tool.object_type == expected.object_type
                       for expected in self.tool_expectations.values()):
                raise ValueError("native tool publication has an unconfigured object type")
            if set(tool.group_names) != {"default", "tn.agents"}:
                raise ValueError("native tool publication must contain only default and tn.agents")
            tool_view = self.session.governance(tool)
            if not self._has_expected_release_context(tool_view):
                raise PermissionError("signed tool use differs from the expected model operation")
            if not self._has_exact_sources(
                tool_view.governance.sources, (self.expected_source,)
            ):
                raise PermissionError("native tool does not reference the exact model input")
            if self.carried_policy and not self._matches_references(tool_view.governance.sources, (source_view,)):
                raise PermissionError("native tool input does not match its signed source policy")
            if not self._has_same_contracts(tool_view, source_view, self.source_binding):
                raise PermissionError("native tool did not preserve source contracts and bindings")
            if not self.carried_policy:
                self.lineage_verifier.verify(
                    tool_view, self.catalog, self.policy_dag, self.resolve_ancestor,
                )
            tool_views[tool.id] = tool_view

        if self.carried_policy:
            if not self._matches_references(sources, (source_view, *tool_views.values())):
                raise PermissionError("native report inputs do not match their signed source policies")
            # The catalog validates the complete content of each signed revision on
            # admission. The report must still carry every revision and edition of
            # the exact input whose authorized use it records.
            required = {policy.revision_id for policy in source_view.governance.policies}
            actual = {policy.revision_id for policy in view.governance.policies}
            if not required.issubset(actual) or any(
                binding not in view.governance.dataset_bindings
                for binding in ([self.source_binding] if self.source_binding is not None else source_view.governance.dataset_bindings)
            ):
                raise PermissionError("native report did not preserve source contracts and bindings")
        else:
            def resolve(identity):
                if identity in tool_views:
                    return tool_views[identity]
                return self.resolve_ancestor(identity)

            self.lineage_verifier.verify(view, self.catalog, self.policy_dag, resolve)
        completed, call_ids, request_digests = set(), set(), set()
        for tool in tool_objects:
            admitted = self.session.receive(
                tool,
                use=self.use,
                groups=["default"],
                decide=lambda admission, tool=tool: self._accept(admission, tool),
            )
            name, call_id, request_digest = self._validate_tool_payload(
                release, tool, admitted.data,
            )
            if expected_digest is not None and request_digest != expected_digest:
                raise ValueError("native tool request digest differs from the trusted submitted request")
            if call_id in call_ids:
                raise ValueError("native tool completions reuse a model call identity")
            call_ids.add(call_id)
            request_digests.add(request_digest)
            if len(request_digests) != 1:
                raise ValueError("native tool completions have different request digests")
            completed.add(name)
        if not self.required_tools.issubset(completed):
            raise PermissionError("native report lacks required tool completion evidence")

        return self.session.receive(
            output,
            use=self.use,
            groups=["default"],
            decide=lambda admission: self._accept(admission, output),
        )


class GovernedLlamaClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        transcript: HttpTranscript,
        output_reader: TnOutputReader | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.transcript = transcript
        self.output_reader = output_reader

    def submit(self, source: SourceRecord, prompt: str) -> ReportRelease:
        body = build_governed_request(source, prompt)
        return self.submit_request(body)

    def submit_model(self, object, prompt: str, use, *, destination: str) -> NativeModelRelease:
        return self.submit_request(build_model_request(object, prompt, use, destination=destination))

    def submit_request(self, body: bytes) -> ReportRelease | NativeModelRelease:
        value = json.loads(body, object_pairs_hook=_without_duplicate_keys)
        protocol = value.get("protocol") if isinstance(value, dict) else None
        if protocol not in {"tn.llama.request.v1", "tn.llama.request.v2"}:
            raise ValueError("request has an unsupported explicit protocol")
        expected_source = None
        if protocol == "tn.llama.request.v2":
            import tn
            expected_source = tn.GovernedObject.parse(value["tn_object"]).id
        request = urllib.request.Request(
            self.base_url + "/v1/tn/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        self.transcript.log_request("llama", request, body)
        started = time.perf_counter()
        try:
            with _OPENER.open(request) as response:
                response_body = response.read()
                _HTTP_CLOCK[0] += time.perf_counter() - started
                self.transcript.log_response(
                    "llama",
                    request.full_url,
                    response,
                    response_body,
                    method=request.get_method(),
                )
        except urllib.error.HTTPError as error:
            response_body = error.read()
            self.transcript.log_response(
                "llama",
                request.full_url,
                error,
                response_body,
                method=request.get_method(),
            )
            raise GovernedRequestDenied(
                error.code, _denial_code(response_body), response_body
            ) from error
        self.transcript.log_state(
            "encrypted_release_received", response_bytes=len(response_body)
        )
        if protocol == "tn.llama.request.v2":
            release = NativeModelRelease.from_http_json(response_body)
            if release.source_object_id != expected_source:
                raise ValueError("native report response names a different model input")
            self.transcript.log_state(
                "native_release_parsed", source_object_id=release.source_object_id,
                output_object_id=release.output_object_id,
            )
            return release
        encrypted = EncryptedReportRelease.from_http_json(response_body)
        self.transcript.log_state(
            "encrypted_release_parsed",
            output_event_id=encrypted.output_event_id,
            output_row_hash=encrypted.output_row_hash,
        )
        if self.output_reader is None:
            raise ValueError("encrypted release requires a TN output reader")
        return self.output_reader.open(encrypted, self.transcript)


def _denial_code(body: bytes) -> str:
    try:
        value = json.loads(body)
    except json.JSONDecodeError:
        return "http_error"
    error = value.get("error") if isinstance(value, dict) else None
    if isinstance(error, dict) and isinstance(error.get("code"), str):
        return error["code"]
    return "http_error"
