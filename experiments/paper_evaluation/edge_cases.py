"""Dataframe edge cases and the Decimal report through the governed path.

The measured workloads use positive ascending values, so their filter drops no row
and their sort moves none. These fixtures exercise both, plus duplicate values with
sort ties and an empty selection. Expected amounts are computed here in Python,
independently of the governed Polars plan, and the offline verifiers replay each run.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .run import run_case

CASES = (
    ("negative-amounts", [("ACME", 1250), ("Kilo", -75), ("Zulu", 1251), ("Beta", -3),
                          ("Mike", 0), ("Quebec", 1252), ("Delta", -999), ("Yankee", 1253)]),
    ("unsorted-names", [("Zulu", 100), ("ACME", 200), ("Mike", 300), ("Beta", 400),
                        ("Yankee", 500), ("Delta", 600), ("Quebec", 700), ("Kilo", 800)]),
    ("duplicate-ties", [("ACME", 100), ("ACME", 100), ("Beta", 200),
                        ("ACME", 200), ("Beta", 100), ("Beta", 200)]),
    ("all-negative", [("ACME", -1), ("Beta", -2), ("Delta", -3), ("Zulu", -4)]),
)


def recalculate(fixture):
    kept = [value for _, value in fixture if value >= 0]
    return {"retained_rows": len(kept), "amount": sum(value + 250 for value in kept) + 1}


def result_claims(root):
    """Return the claims reachable from the governed dataframe result."""
    return json.loads((root / "verification.json").read_text())["outputs"]["dataframe_result"]["claims"]


def edge_case(root, name, fixture, unity_url):
    expected = recalculate(fixture)
    company = fixture[0][0].upper()
    summary = run_case(root / name, "primitive", fixture=fixture, model=False, claim=True,
                       unity_url=unity_url)
    return {"case": name, "rows": len(fixture), **expected,
            "expected_matches": summary["expected_content"]
            == f"{company}: {expected['amount']} demonstration cents",
            "sort_moves_rows": [n for n, _ in fixture] != sorted(n for n, _ in fixture),
            "completed": summary["completed"], "verified": summary["verified"],
            "dataframe_result_claims": len(result_claims(root / name)) if summary["verified"] else 0,
            "record_count": summary.get("verification", {}).get("record_count"),
            "error": summary.get("error"), "verification_error": summary.get("verification_error")}


def decimal_report(root, unity_url, port, **server):
    """A Decimal amount through the report path; ``server`` names the binary, model, and build record."""
    summary = run_case(root / "decimal-report", "primitive", rows=3, model=True, claim=True,
                       unity_url=unity_url, numeric_type="Decimal", port=port, **server)
    model = summary.get("model", {})
    return {"case": "decimal-report", "expected_content": summary["expected_content"],
            "completed": summary["completed"], "verified": summary["verified"],
            "model_completed": model.get("completed"),
            "policies": len(model.get("source_policy_revisions") or ()),
            "claims": len(model.get("source_claim_ids") or ()),
            "tool_objects": len(model.get("tool_object_ids") or ()),
            "review": (model.get("review") or {}).get("status"),
            "error": summary.get("error"), "verification_error": summary.get("verification_error")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--unity-url", default="http://127.0.0.1:18080")
    parser.add_argument("--with-model", action="store_true", help="Also run the Decimal report")
    parser.add_argument("--port", type=int, default=18326)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--model-path", type=Path)
    parser.add_argument("--sdk-build-record", type=Path)
    args = parser.parse_args()
    if args.with_model and not (args.binary and args.model_path and args.sdk_build_record):
        parser.error("--with-model needs --binary, --model-path, and --sdk-build-record")
    root = args.run_directory.resolve()
    root.mkdir(parents=True, exist_ok=True)
    cases = [edge_case(root, name, fixture, args.unity_url) for name, fixture in CASES]
    limits = json.loads(Path("config/performance.json").read_text(encoding="utf-8"))["runtime_limits"]
    report = decimal_report(root, args.unity_url, args.port, binary=args.binary, model_path=args.model_path,
                            sdk_build_record=args.sdk_build_record,
                            runtime_limits=limits) if args.with_model else None
    output = {"cases": cases, "decimal_report": report}
    (root / "results.json").write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    print(json.dumps(output, indent=2, default=str))
    passed = all(c["completed"] and c["verified"] and c["expected_matches"] for c in cases)
    return 0 if passed and (report is None or report["verified"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
