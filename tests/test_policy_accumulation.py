import pytest

from experiments.paper_evaluation.policy_accumulation import run_case


@pytest.mark.parametrize(("rows", "survivors", "sources"), [(2, 0, 1), (4, 1, 2), (4, 4, 2)])
def test_filter_retains_source_policies_claims_and_disclosure_conditions(
    tmp_path, rows, survivors, sources,
):
    observed = run_case(tmp_path / "case", rows=rows, survivors=survivors, sources=sources)
    assert observed["policy_count"] == sources * 2
    assert observed["policy_revisions"] == observed["input_policy_revisions"]
    assert observed["claim_count"] == 1
    assert observed["repeated_input"] == {
        "policy_count": sources * 2, "claim_count": 1, "value": survivors * 502,
    }
    assert observed["disclosures"]["review-console"] == {
        "outcome": "permitted", "value": survivors * 251, "content_opens": 1,
    }
    if sources > 1:
        assert observed["disclosures"]["analysis-console"] == {
            "outcome": "refused", "content_opens": 0,
        }
    else:
        assert observed["disclosures"]["analysis-console"] == {
            "outcome": "permitted", "value": survivors * 251, "content_opens": 1,
        }
