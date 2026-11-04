"""The report inspection profile shared by the endpoint and the offline verifier."""

from html.parser import HTMLParser

from .evidence import require


class PlainReportText(HTMLParser):
    """Inspect unstyled body text, excluding document titles and refusing CSS/scripts."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self._head_seen = False
        self._head_open = False
        self._title_open = False
        self._visible_started = False

    def handle_starttag(self, tag, attrs):
        require(tag in {"html", "head", "title", "body", "p", "div", "span", "br",
                        "h1", "h2", "h3", "h4",
                        "ul", "ol", "li", "strong", "b", "em", "i", "code", "pre",
                        "table", "thead", "tbody", "tr", "th", "td"} and not attrs,
                "report is outside the unstyled, visible-element inspection profile")
        if tag == "head":
            require(not self._head_seen and not self._visible_started,
                    "ambiguous document header structure")
            self._head_seen = self._head_open = True
            return
        if tag == "title":
            require(self._head_open and not self._title_open,
                    "ambiguous document title structure")
            self._title_open = True
            return
        require(not self._head_open, "visible element inside document header")
        if tag != "html":
            self._visible_started = True
        if tag in {"p", "div", "br", "li", "h1", "h2", "h3", "td"}:
            self.parts.append(" ")

    def handle_startendtag(self, tag, attrs):
        require(tag not in {"head", "title"}, "self-closing document header or title")
        super().handle_startendtag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "title":
            require(self._head_open and self._title_open,
                    "ambiguous document title structure")
            self._title_open = False
            return
        if tag == "head":
            require(self._head_open and not self._title_open,
                    "ambiguous document header structure")
            self._head_open = False
            return
        require(not self._head_open, "unexpected closing element inside document header")
        if tag in {"p", "div", "li", "h1", "h2", "h3", "td"}:
            self.parts.append(" ")

    def handle_data(self, data):
        if self._head_open:
            require(self._title_open or not data.strip(),
                    "non-title text inside document header")
            return
        if data.strip():
            self._visible_started = True
        self.parts.append(data)

    def close(self):
        super().close()
        require(not self._head_open and not self._title_open,
                "unclosed document header or title")


def visible_text(html):
    """Return the report's visible text, or raise if it leaves the profile."""
    parser = PlainReportText()
    parser.feed(html)
    parser.close()
    return " ".join("".join(parser.parts).split())
