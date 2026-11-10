"""Command-line entry point for the governed workflow."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

_CONTAINMENT_ENVIRONMENT = (
    "PYTHONDONTWRITEBYTECODE",
    "TN_NO_LINK",
    "TN_NO_STDOUT",
    "TN_AUTOINIT_QUIET",
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tn-governed")
    commands = parser.add_subparsers(dest="command", required=True)
    native = commands.add_parser(
        "governed-path",
        help="run signed editions through native TN, Polars, calculations and tn-llama",
    )
    native.add_argument("--run-directory", required=True, type=Path)
    native.add_argument("--unity-url", default="http://127.0.0.1:8080")
    native.add_argument("--server-binary", required=True, type=Path)
    native.add_argument("--model", required=True, type=Path)
    native.add_argument("--llama-port", default=18280, type=int)
    native.add_argument("--wsl", action="store_true")
    native.add_argument("--resume", action="store_true")
    native.add_argument("--check-refusals", action="store_true")
    return parser


@contextmanager
def contained_tn_environment() -> Iterator[None]:
    """Set the containment variables for one run and restore each one afterwards."""
    previous = {name: os.environ.get(name) for name in _CONTAINMENT_ENVIRONMENT}
    try:
        for name in _CONTAINMENT_ENVIRONMENT:
            os.environ[name] = "1"
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def main(argv: Sequence[str] | None = None) -> int:
    """Run the governed path without accepting secrets as arguments."""
    parser = _parser()
    arguments = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    api_key = os.environ.get("TN_LLAMA_API_KEY", "")
    if not api_key.strip():
        parser.error("TN_LLAMA_API_KEY must be set to a nonempty local API key")
    from .native_run import run_native_reference

    with contained_tn_environment():
        report_path, summary_path = run_native_reference(
            directory=arguments.run_directory,
            unity_url=arguments.unity_url,
            binary=arguments.server_binary,
            model=arguments.model,
            port=arguments.llama_port,
            api_key=api_key,
            wsl=arguments.wsl,
            resume=arguments.resume,
            check_refusals=arguments.check_refusals,
        )
    print(f"Verified report: {report_path}")
    print(f"Factual run summary: {summary_path}")
    return 0
