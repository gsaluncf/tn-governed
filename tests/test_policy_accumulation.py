import pytest

from experiments.pvldb_evaluation.policy_accumulation import CASES, run_case


@pytest.mark.parametrize(("rows", "survivors", "sources"), CASES)
def test_filter_retains_source_policies_claims_and_disclosure_conditions(
    tmp_path, rows, survivors, sources,
):
    observed = run_case(tmp_path / "case", rows=rows, survivors=survivors, sources=sources)
    assert observed["policy_count"] == sources * 2
    assert observed["policy_revisions"] == observed["input_policy_revisions"]
    assert observed["input_reference_count"] == rows * 2
    assert observed["origin_count"] == rows * 2
    assert observed["claim_count"] == 1
    assert observed["opa_decision_count"] == sources * 12
    assert observed["claimed_row_survived"] is (survivors == rows)
    assert observed["repeated_input"] == {
        "policy_count": sources * 2, "claim_count": 1,
        "direct_input_count": 2, "distinct_input_count": 1,
    }
    assert observed["disclosures"]["review-console"] == {
        "outcome": "permitted", "value": survivors * 251, "content_opens": 1,
    }
    if sources > 1:
        assert observed["restricted_source_survivors"] == 0
        assert observed["disclosures"]["analysis-console"] == {
            "outcome": "refused", "content_opens": 0,
        }
    else:
        assert observed["disclosures"]["analysis-console"] == {
            "outcome": "permitted", "value": survivors * 251, "content_opens": 1,
        }
