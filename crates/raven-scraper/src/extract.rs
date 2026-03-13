//! HTML and content-body extraction utilities.

use scraper::{Html, Selector};

/// Extract plain text from an HTML document.
///
/// Removes `<script>` and `<style>` tags, then walks every remaining text node
/// inside `<body>`, deduplicating whitespace.
pub fn extract_text(html: &str) -> String {
    let doc = Html::parse_document(html);

    // Selectors are cheap to build; cache if this becomes a hot path.
    let body_sel = Selector::parse("body").unwrap();

    let body = match doc.select(&body_sel).next() {
        Some(b) => b,
        None    => return strip_tags_fallback(html),
    };

    let mut out = String::with_capacity(html.len() / 4);

    for node in body.descendants() {
        // Skip subtrees that are inside ignored elements.
        if let Some(elem) = node.value().as_element() {
            let tag = elem.name();
            if matches!(tag, "script" | "style" | "noscript") {
                continue;
            }
        }

        if let Some(text) = node.value().as_text() {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                out.push_str(trimmed);
                out.push(' ');
            }
        }
    }

    // Collapse repeated whitespace.
    let collapsed: String = out
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    collapsed
}

/// Fallback for pages with no `<body>` — strip all angle-bracket tags naively.
fn strip_tags_fallback(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ─────────────────────────────────────────────────────────────────────────────

/// Determine whether the response body looks like JSON.
pub fn is_json(content_type: &str) -> bool {
    content_type.contains("application/json") || content_type.contains("+json")
}

/// Truncate text to `max_chars`, appending `…` if truncated.
pub fn truncate(text: &str, max_chars: usize) -> String {
    if text.len() <= max_chars {
        text.to_owned()
    } else {
        let mut s = text[..max_chars].to_owned();
        s.push('…');
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_scripts() {
        let html = r#"<html><body>Hello <script>bad()</script> World</body></html>"#;
        let text = extract_text(html);
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
        assert!(!text.contains("bad()"));
    }

    #[test]
    fn truncate_works() {
        assert_eq!(truncate("abcde", 3), "abc…");
        assert_eq!(truncate("ab", 5), "ab");
    }
}
