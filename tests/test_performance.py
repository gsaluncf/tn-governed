import importlib.util
import math

import pytest


def module():
    assert importlib.util.find_spec("experiments.pvldb_evaluation.performance") is not None
    from experiments.pvldb_evaluation import performance

    return performance


def test_profile_requires_distinct_positive_sizes_and_explicit_model_mode():
    perf = module()
    valid = {
        "rows": [1000, 10000, 100000],
        "recipients": [1, 4, 8],
        "tool_depths": [1, 3, 5],
        "recipient_rows": 10000,
        "tool_rows": 1000,
        "repetitions": 5,
        "recipient_repetitions": 30,
        "warmups": 1,
        "model": True,
        "sql_batch_size": 256,
    }
    perf.validate_profile(valid)
    for change in (
        {"rows": [0]},
        {"rows": [1, 1]},
        {"repetitions": 0},
        {"warmups": -1},
        {"model": "false"},
        {"recipients": [True]},
        {"sql_batch_size": 64},
        {"sql_batch_size": 0},
        {"gpu_layers": 0},
    ):
        with pytest.raises(ValueError):
            perf.validate_profile(valid | change)


def test_statistics_use_raw_samples_and_nearest_rank_p95():
    perf = module()
    stats = perf.statistics_summary(list(range(1, 21)))
    assert stats == {"n": 20, "median": 10.5, "p95": 19, "min": 1, "max": 20}
    assert perf.statistics_summary([]) is None
    for invalid in ([math.nan], [math.inf], [-1]):
        with pytest.raises(ValueError):
            perf.statistics_summary(invalid)


def test_timing_boundaries_exclude_startup_and_offline_verification():
    perf = module()
    times = {
        "setup": 100,
        "assignment": 100,
        "server_start": 100,
        "verification": 100,
        "query": 1,
        "claim": 2,
        "dataframe": 3,
        "compute": 4,
        "console_disclosure": 5,
        "native_prepare": 6,
        "generation": 7,
        "total": 428,
    }
    # Generation holds model inference, which is reported beside processing, never in it.
    assert perf.elapsed_processing(times, model=True) == 15
    assert perf.elapsed_processing(times, model=False) == 15
    with pytest.raises(ValueError, match="generation"):
        perf.elapsed_processing({"query": 1}, model=True)


def test_failed_pair_has_no_overhead_ratio():
    perf = module()
    rows = [
        {"rows": 1000, "mode": "tn", "ok": False, "seconds": 1, "warmup": False},
        {"rows": 1000, "mode": "plain", "ok": True, "seconds": 2, "warmup": False},
    ]
    assert perf.summarize_scale(rows)[0]["tn_plain_ratio"] is None
    rows[0]["ok"] = True
    rows.append({"rows": 1000, "mode": "tn", "ok": True, "seconds": 100, "warmup": True})
    assert perf.summarize_scale(rows)[0]["tn_plain_ratio"] == 0.5


def test_case_rejects_invalid_completion_handler_before_creating_run(tmp_path):
    from experiments.pvldb_evaluation.run import run_case

    with pytest.raises(ValueError, match="completion_handler"):
        run_case(tmp_path / "run", "primitive", completion_handler=True)
    assert not (tmp_path / "run").exists()


def test_revision_check_accepts_git_abbreviations_without_accepting_other_commits():
    perf = module()
    for revision in ("3f545be", "3f545becc", "3f545beccee69d9975f466ec7e45fd9aacd8ba90"):
        version = f"version: 0.2.0 (build 1, commit {revision})"
        assert perf.validate_model_revision(version) == revision
    for text in ("version: commit 3f545bf", "commit 3f545b", "3f545be unrelated text"):
        with pytest.raises(ValueError):
            perf.validate_model_revision(text)
