//! HTML and content-body extraction utilities.

use scraper::{Html, Selector};

/// Extract plain text from an HTML document.
///
/// Skips any text node whose ancestor chain contains a `<script>`, `<style>`,
/// or `<noscript>` element. This ancestor-check approach is correct and simple:
/// no depth counters needed.
pub fn extract_text(html: &str) -> String {
    let doc = Html::parse_document(html);

    let body_sel = Selector::parse("body").unwrap();

    let body = match doc.select(&body_sel).next() {
        Some(b) => b,
        None => return strip_tags_fallback(html),
    };

    let mut out = String::with_capacity(html.len() / 4);

    for node in body.descendants() {
        // Only process text nodes — skip element/comment nodes entirely.
        let text = match node.value().as_text() {
            Some(t) => t,
            None => continue,
        };

        // Check every ancestor: if any is a blocked tag, skip this text node.
        let inside_blocked = node.ancestors().any(|ancestor| {
            ancestor
                .value()
                .as_element()
                .map(|e| matches!(e.name(), "script" | "style" | "noscript"))
                .unwrap_or(false)
        });

        if inside_blocked {
            continue;
        }

        let trimmed = text.trim();
        if !trimmed.is_empty() {
            out.push_str(trimmed);
            out.push(' ');
        }
    }

    out.split_whitespace().collect::<Vec<_>>().join(" ")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_scripts() {
        let html = r#"<html><body>Hello <script>bad()</script> World</body></html>"#;
        let text = extract_text(html);
        assert!(text.contains("Hello"), "expected Hello in: {text}");
        assert!(text.contains("World"), "expected World in: {text}");
        assert!(!text.contains("bad()"), "script leaked into: {text}");
    }

    #[test]
    fn strips_style_content() {
        let html = r#"<html><body>Text <style>.bad{}</style> More</body></html>"#;
        let text = extract_text(html);
        assert!(text.contains("Text"), "expected Text in: {text}");
        assert!(text.contains("More"), "expected More in: {text}");
        assert!(!text.contains(".bad"), "style leaked into: {text}");
    }

    #[test]
    fn strips_nested_script() {
        let html = r#"<html><body><div>Visible <script><div>hidden()</div></script> end</div></body></html>"#;
        let text = extract_text(html);
        assert!(text.contains("Visible"), "expected Visible in: {text}");
        assert!(text.contains("end"), "expected end in: {text}");
        assert!(!text.contains("hidden()"), "nested script leaked into: {text}");
    }

    #[test]
    fn empty_body_returns_empty() {
        let html = r#"<html><body></body></html>"#;
        assert!(extract_text(html).is_empty());
    }

    #[test]
    fn no_body_uses_fallback() {
        let html = r#"<p>Hello</p><script>bad()</script>"#;
        assert!(extract_text(html).contains("Hello"));
    }

    #[test]
    fn truncate_works() {
        assert_eq!(truncate("abcde", 3), "abc…");
        assert_eq!(truncate("ab", 5), "ab");
    }
}