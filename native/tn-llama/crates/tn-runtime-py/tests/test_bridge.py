"""Run with the built wheel and TN_VLLM_FIXTURE pointing to a native fixture."""
import json
import os
from pathlib import Path
import unittest
import subprocess

import tn_runtime_native as native


class NativeBridgeTests(unittest.TestCase):
    def test_backend_refuses_unknown_revision(self):
        with self.assertRaises(ValueError):
            native.VllmBackend("engine", "a" * 64, "b" * 64, "c" * 64, "hermes", "unknown")

    def test_constructor_rejects_invalid_config(self):
        backend = native.VllmBackend("engine", "a" * 64, "b" * 64, "c" * 64, "hermes", native.VLLM_REVISION)
        with self.assertRaises(ValueError):
            native.Runtime(b"{}", backend)

    def test_tool_call_owns_arguments(self):
        call = native.ToolCall("one", "select_sections", b'{"a":1}')
        self.assertEqual(call.arguments, b'{"a":1}')
        self.assertEqual(call.name, "select_sections")

    def test_complete_standalone_native_session(self):
        root = Path(__file__).resolve().parents[3]
        result = subprocess.run(["cargo", "run", "--quiet", "-p", "tn-runtime", "--example", "vllm_fixture"], cwd=root, check=True, capture_output=True, text=True)
        fixture = Path(result.stdout.strip())
        backend = native.VllmBackend("bridge-test", "a" * 64, "b" * 64, "c" * 64, "hermes", native.VLLM_REVISION)
        runtime = native.Runtime((fixture / "runtime-config-v2.json").read_bytes(), backend)
        session = runtime.start_session((fixture / "request-v2.json").read_bytes())
        release = None
        phases = []
        for ordinal in range(1):
            turn = session.next_turn()
            phases.append(turn.phase)
            body = json.loads(turn.request_json)
            name = body["tools"][0]["function"]["name"]
            control = json.loads(body["messages"][1]["content"])
            self.assertNotIn("get_governance", turn.request_json.decode())
            self.assertNotIn("continue_with_governance", turn.request_json.decode())
            self.assertTrue(control["applicable_source_governance"])
            self.assertEqual(name, "emit_governed_record")
            self.assertIn("selected_values", control)
            self.assertIn("applicable_source_governance", control)
            self.assertTrue(control["applicable_source_governance"])
            arguments = {"report_html": "<p>Maximum drawdown: 25%.</p>"}
            manifest = {
                "schema": "tn.vllm.execution.v1", "engine_instance": "bridge-test",
                "model_bundle_sha256": "a" * 64, "tokenizer_sha256": "b" * 64,
                "template_sha256": "c" * 64, "parser": "hermes",
                "request_id": f"internal-{ordinal}", "external_request_id": f"external-{ordinal}",
                "prompt_token_ids": [1, 2, 3], "sampling_params": {
                    **{key: None for key in native.SAMPLING_FIELDS},
                    "n": 1, "max_tokens": body["max_tokens"], "temperature": 0.0,
                    "output_kind": 2, "detokenize": True, "skip_clone": False},
                "reasoning_ended": None, "reasoning_parser_kwargs": None,
                "arrival_time": 1.0, "priority": 0, "resumable": False, "abort_immediately": False,
                **{key: None for key in ("trace_headers", "cache_salt", "data_parallel_rank", "mm_features", "pooling_params", "lora_request", "prompt_embeds", "prompt_is_token_ids", "session_id")}}
            encoded = json.dumps(manifest).encode()
            identity = {key: manifest[key] for key in ("engine_instance", "request_id", "external_request_id")}
            identity.update(client_index=0, destination="engine-0", wave=0)
            turn.prepare(b"test renderer", encoded)
            turn.begin(b"test renderer", encoded, json.dumps(identity).encode())
            release = session.accept(turn, [native.ToolCall(f"call-{ordinal}", name, json.dumps(arguments).encode())], b"", b"engine double output")
        self.assertEqual(phases, ["governed_action"])
        self.assertEqual(session.state, "complete")
        output = fixture / "bridge-release.json"
        output.write_bytes(release)
        verified = subprocess.run(["cargo", "run", "--quiet", "-p", "tn-runtime", "--example", "vllm_verify", "--", str(fixture), str(output)], cwd=root, check=True, capture_output=True, text=True)
        self.assertTrue(json.loads(verified.stdout)["verified"])


if __name__ == "__main__":
    unittest.main()
