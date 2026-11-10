"""Select SSH model-process launchers while keeping the benchmark calculations intact."""

import hashlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def configure(host):
    from experiments.paper_evaluation import performance, performance_model, run

    run.governed_server = host.governed
    performance_model.ordinary_server = host.plain
    performance._model_version = host.version
    original = performance.environment_manifest

    def environment_manifest(args, profile):
        manifest = original(args, profile)
        manifest["remote_model"] = {
            key: value for key, value in host.settings.items() if key != "identity_file"
        }
        manifest["transport_source_sha256"] = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (Path(__file__), Path(__file__).with_name("remote_model.py"))
        }
        return manifest

    performance.environment_manifest = environment_manifest


def main():
    from deployment.remote_model import RemoteHost
    from experiments.paper_evaluation import performance

    configure(RemoteHost(os.environ["TN_REMOTE_MODEL_CONFIG"]))
    return performance.main()


if __name__ == "__main__":
    raise SystemExit(main())
