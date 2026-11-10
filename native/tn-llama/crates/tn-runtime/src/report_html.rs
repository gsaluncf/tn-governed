//! The accepted report markup: a fixed set of elements without attributes, read as visible text.
//!
//! A report is accepted only in this narrow language, so no styling, script, or hidden
//! element can carry or conceal an attribution. The offline verifier applies the same
//! profile (`tn_governed.values.report_profile`). Document titles are not visible text;
//! comments and declarations carry none.

use crate::model_protocol::session_error;
use crate::TnLlamaError;

/// The elements a report may use; none may carry an attribute.
pub(crate) const ALLOWED_ELEMENTS: [&str; 27] = [
    "html", "head", "title", "body", "p", "div", "span", "br", "h1", "h2", "h3", "h4", "ul", "ol",
    "li", "strong", "b", "em", "i", "code", "pre", "table", "thead", "tbody", "tr", "th", "td",
];
const BLOCK_START: [&str; 8] = ["p", "div", "br", "li", "h1", "h2", "h3", "td"];
const BLOCK_END: [&str; 7] = ["p", "div", "li", "h1", "h2", "h3", "td"];

#[derive(Default)]
struct Reader {
    parts: String,
    head_seen: bool,
    head_open: bool,
    title_open: bool,
    visible_started: bool,
}

/// The report's visible text with whitespace collapsed, or a refusal if it leaves the profile.
pub(crate) fn visible_report_text(html: &str) -> Result<String, TnLlamaError> {
    let mut reader = Reader::default();
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        reader.text(&rest[..start])?;
        rest = reader.markup(&rest[start..])?;
    }
    reader.text(rest)?;
    if reader.head_open || reader.title_open {
        return Err(profile_error("unclosed document header or title"));
    }
    Ok(reader
        .parts
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" "))
}

/// Collapse whitespace the way the visible text is collapsed, for comparing attributions.
pub(crate) fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Reader {
    fn text(&mut self, raw: &str) -> Result<(), TnLlamaError> {
        let data = decode_entities(raw)?;
        if self.head_open {
            if !self.title_open && !data.trim().is_empty() {
                return Err(profile_error("non-title text inside document header"));
            }
            return Ok(());
        }
        if !data.trim().is_empty() {
            self.visible_started = true;
        }
        self.parts.push_str(&data);
        Ok(())
    }

    /// Consume one comment, declaration, or tag at the start of `input`; return the rest.
    fn markup<'a>(&mut self, input: &'a str) -> Result<&'a str, TnLlamaError> {
        if let Some(comment) = input.strip_prefix("<!--") {
            let end = comment
                .find("-->")
                .ok_or_else(|| profile_error("unterminated comment"))?;
            return Ok(&comment[end + 3..]);
        }
        let end = input
            .find('>')
            .ok_or_else(|| profile_error("unterminated element"))?;
        let body = &input[1..end];
        if body.starts_with('!')
            && body[1..]
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("doctype")
        {
            return Ok(&input[end + 1..]);
        }
        self.tag(body)?;
        Ok(&input[end + 1..])
    }

    fn tag(&mut self, body: &str) -> Result<(), TnLlamaError> {
        let closing = body.starts_with('/');
        let inner = body.strip_prefix('/').unwrap_or(body);
        let self_closing = !closing && inner.trim_end().ends_with('/');
        let name = inner.trim_end().trim_end_matches('/').trim_end();
        if name.is_empty()
            || !name.chars().all(|c| c.is_ascii_alphanumeric())
            || !ALLOWED_ELEMENTS.contains(&name.to_ascii_lowercase().as_str())
        {
            return Err(profile_error(
                "report is outside the unstyled, visible-element inspection profile",
            ));
        }
        let name = name.to_ascii_lowercase();
        if closing {
            return self.end(&name);
        }
        if self_closing && matches!(name.as_str(), "head" | "title") {
            return Err(profile_error("self-closing document header or title"));
        }
        self.start(&name)?;
        if self_closing {
            self.end(&name)?;
        }
        Ok(())
    }

    fn start(&mut self, name: &str) -> Result<(), TnLlamaError> {
        match name {
            "head" if self.head_seen || self.visible_started => {
                Err(profile_error("ambiguous document header structure"))
            }
            "head" => {
                self.head_seen = true;
                self.head_open = true;
                Ok(())
            }
            "title" if !self.head_open || self.title_open => {
                Err(profile_error("ambiguous document title structure"))
            }
            "title" => {
                self.title_open = true;
                Ok(())
            }
            _ if self.head_open => Err(profile_error("visible element inside document header")),
            _ => {
                if name != "html" {
                    self.visible_started = true;
                }
                if BLOCK_START.contains(&name) {
                    self.parts.push(' ');
                }
                Ok(())
            }
        }
    }

    fn end(&mut self, name: &str) -> Result<(), TnLlamaError> {
        match name {
            "title" if !self.head_open || !self.title_open => {
                Err(profile_error("ambiguous document title structure"))
            }
            "title" => {
                self.title_open = false;
                Ok(())
            }
            "head" if !self.head_open || self.title_open => {
                Err(profile_error("ambiguous document header structure"))
            }
            "head" => {
                self.head_open = false;
                Ok(())
            }
            _ if self.head_open => Err(profile_error(
                "unexpected closing element inside document header",
            )),
            _ => {
                if BLOCK_END.contains(&name) {
                    self.parts.push(' ');
                }
                Ok(())
            }
        }
    }
}

/// Decode character references. A bare `&` stays text, as in HTML; a named reference
/// outside the common five is refused rather than read differently from the verifier.
fn decode_entities(raw: &str) -> Result<String, TnLlamaError> {
    let mut decoded = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find('&') {
        decoded.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        match reference(tail) {
            Some(name) => {
                decoded.push(entity(name)?);
                rest = &tail[name.len() + 1..];
            }
            None => {
                decoded.push('&');
                rest = tail;
            }
        }
    }
    decoded.push_str(rest);
    Ok(decoded)
}

/// The name of a `;`-terminated character reference at the start of `tail`, if one is there.
fn reference(tail: &str) -> Option<&str> {
    let end = tail.find(';')?;
    let name = &tail[..end];
    let named = name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name.chars().all(|c| c.is_ascii_alphanumeric());
    let numeric = name.strip_prefix('#').is_some_and(|digits| {
        let hex = digits.strip_prefix(['x', 'X']);
        match hex {
            Some(hex) => !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()),
            None => !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()),
        }
    });
    (named || numeric).then_some(name)
}

fn entity(name: &str) -> Result<char, TnLlamaError> {
    let code = match name {
        "amp" => Some('&' as u32),
        "lt" => Some('<' as u32),
        "gt" => Some('>' as u32),
        "quot" => Some('"' as u32),
        "apos" => Some('\'' as u32),
        _ => name
            .strip_prefix('#')
            .and_then(|digits| match digits.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => digits.parse::<u32>().ok(),
            }),
    };
    code.and_then(char::from_u32)
        .ok_or_else(|| profile_error("report uses a character reference outside the profile"))
}

fn profile_error(message: &'static str) -> TnLlamaError {
    session_error("tn_report_markup_invalid", message)
}

#[cfg(test)]
mod tests {
    use super::{normalized, visible_report_text};

    #[test]
    fn visible_text_excludes_titles_and_collapses_block_whitespace() {
        let html = "<!DOCTYPE html><html><head><title>Hidden</title></head><body>\
                    <h1>Report</h1><p>Amount: 7&amp;8 for S&P</p><!-- note --><ul><li>a</li><li>b</li></ul></body></html>";
        assert_eq!(
            visible_report_text(html).unwrap(),
            "Report Amount: 7&8 for S&P a b"
        );
        assert_eq!(visible_report_text("<p>Source").unwrap(), "Source");
        assert_eq!(normalized("  Source:\n A  "), "Source: A");
    }

    #[test]
    fn attributes_styles_scripts_and_unknown_elements_are_refused() {
        for html in [
            "<p style=\"opacity:0\">Source</p>",
            "<p hidden>Source</p>",
            "<span aria-hidden=\"true\">Source</span>",
            "<style>p{font-size:0}</style><p>Source</p>",
            "<script>x</script>",
            "<template><p>Source</p></template>",
            "<details><p>Source</p></details>",
            "<svg><text>Source</text></svg>",
            "<p>Source &copy;</p>",
            "<p>Source <!-- open",
        ] {
            assert_eq!(
                visible_report_text(html).unwrap_err().code(),
                "tn_report_markup_invalid",
                "{html}"
            );
        }
    }

    #[test]
    fn header_structure_matches_the_verifier_profile() {
        for html in [
            "<p>a</p><head><title>t</title></head>",
            "<head><p>a</p></head>",
            "<head>text</head>",
            "<title>t</title>",
            "<head><title>t</title>",
            "<head/>",
        ] {
            assert_eq!(
                visible_report_text(html).unwrap_err().code(),
                "tn_report_markup_invalid",
                "{html}"
            );
        }
    }
}
