"""Report evidence counts visible body text and excludes document metadata."""

import pytest

from tn_governed.values.evidence import EvidenceError
from tn_governed.values.report_profile import PlainReportText


def visible(html):
    parser = PlainReportText()
    parser.feed(html)
    parser.close()
    return " ".join("".join(parser.parts).split())


def test_document_title_does_not_replace_visible_report_content():
    assert visible(
        "<html><head><title>Internal Review Report</title></head>"
        "<body><p><strong>Review required.</strong></p><p>ACME: 1999501 cents</p>"
        "</body></html>"
    ) == "Review required. ACME: 1999501 cents"


def test_disclosure_in_title_is_not_visible_report_evidence():
    assert "Review required." not in visible(
        "<html><head><title>Review required.</title></head>"
        "<body><p>ACME: 1999501 cents</p></body></html>"
    )


@pytest.mark.parametrize("html", [
    "<head><script>document.write('Review required.')</script></head><p>value</p>",
    "<head><style>p { display:none }</style></head><p>Review required.</p>",
    "<p style='display:none'>Review required.</p>",
    "<p hidden>Review required.</p>",
    "<p>Review required.</p><img src='http://collector.invalid/x'>",
    "<head hidden><title>Review required.</title></head><p>value</p>",
    "<body><title>Review required.</title></body>",
    "<head><title>Review required.</head><p>value</p>",
    "<head><title>Review required.</title><p>value</p>",
    "<head>Review required.</head><p>value</p>",
    "<head><title>title</title>",
    "<title>title</title><p>value</p>",
    "<head/><p>Review required.</p>",
    "<head><title/>Review required.</head><p>value</p>",
    "<p>value</p><head><title>Review required.</title></head>",
])
def test_hidden_content_and_ambiguous_header_structure_are_rejected(html):
    with pytest.raises(EvidenceError):
        visible(html)


def test_body_fragment_and_line_breaks_remain_visible():
    assert visible("<p>Review required.<br/>ACME: 10 cents</p>") == (
        "Review required. ACME: 10 cents"
    )
