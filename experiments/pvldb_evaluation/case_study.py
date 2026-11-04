"""The case study's synthetic market-data policy, uses, and required review notice.

The SQL rows are synthetic Bloomberg-style demonstration data, not a Bloomberg
feed or an interpretation of a vendor license.
"""

NOTICE = ("REVIEW REQUIRED: This AI-generated report uses synthetic Bloomberg-style market data. "
          "Human review is pending. Internal use only.")
REVIEW_ACTION = {"action": "human_review", "assignee": "internal-reviewer",
                 "reason": "LLM use of governed market data requires a human to review the report."}
APPLICATION, PURPOSE = "bloomberg-example", "internal-analytics"
MODEL_USE = {"application": "primitive-model", "purpose": PURPOSE, "operation": "generate_report"}
RECIPIENT_USE = {"application": "primitive-recipient", "purpose": PURPOSE, "operation": "read_report"}


def policy(column):
    return f"""## experiment.primitive
### instruction
Synthetic Bloomberg-style {column} data for internal analytics.
### use_for
Internal calculations and LLM reports. Notify the LLM to mark its report with: {NOTICE}
Generate the report now and request human review; review may remain pending.
### do_not_use_for
Claiming a pending report was reviewed or these synthetic values are market quotes.
### consequences
Carry these conditions through derivatives. Send the exact report to internal-reviewer.
### on_violation_or_error
Record outstanding actions and retain the report's source lineage.
"""


def handle(value):
    """The exported handle of a governed value: its reference and the records that produced it."""
    return {"reference": value.reference.to_dict(), "decision_id": value.decision_id,
            "result_id": value.result_id, "kind": type(value).__name__}
