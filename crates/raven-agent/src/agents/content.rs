//! `ContentAnalyzerAgent` — scans the page body and response headers for
//! patterns commonly associated with phishing, malware distribution, or spam.

use async_trait::async_trait;
use raven_core::{AgentPlugin, AgentReport, OsintError, ScraperOutput};

// ─────────────────────────────────────────────────────────────────────────────
// Pattern lists
// ─────────────────────────────────────────────────────────────────────────────

/// Keywords strongly associated with phishing / social-engineering lures.
const PHISHING_KEYWORDS: &[&str] = &[
    "verify your account",
    "confirm your identity",
    "update your payment",
    "your account has been suspended",
    "click here urgently",
    "unusual activity detected",
    "your password will expire",
    "you have won",
    "claim your prize",
    "wire transfer",
    "bitcoin wallet",
    "send funds",
];

/// Patterns that suggest obfuscated or malicious JavaScript.
const SUSPICIOUS_JS_PATTERNS: &[&str] = &[
    "eval(unescape",
    "eval(atob",
    "document.write(unescape",
    "fromcharcode",
    r"window\.location\s*=",
    "document.cookie",
    ".replace(/./g,",
];

/// Security headers whose *absence* is a mild negative signal.
const EXPECTED_SECURITY_HEADERS: &[&str] = &[
    "x-frame-options",
    "x-content-type-options",
    "content-security-policy",
];

// ─────────────────────────────────────────────────────────────────────────────

pub struct ContentAnalyzerAgent;

#[async_trait]
impl AgentPlugin for ContentAnalyzerAgent {
    fn name(&self) -> &str {
        "content_analyzer"
    }

    async fn run(&self, input: &ScraperOutput) -> Result<AgentReport, OsintError> {
        let body_lower = input.body_text.to_lowercase();

        // ── Phishing keyword scan ─────────────────────────────────────────────
        let phishing_hits: Vec<&str> = PHISHING_KEYWORDS
            .iter()
            .copied()
            .filter(|&kw| body_lower.contains(kw))
            .collect();
        let phishing_count = phishing_hits.len();

        // ── Suspicious JS pattern scan ────────────────────────────────────────
        let js_hits: Vec<&str> = SUSPICIOUS_JS_PATTERNS
            .iter()
            .copied()
            .filter(|&pat| body_lower.contains(&pat.to_lowercase()))
            .collect();
        let js_suspicious = !js_hits.is_empty();

        // ── Missing security headers ──────────────────────────────────────────
        let missing_headers: Vec<&str> = EXPECTED_SECURITY_HEADERS
            .iter()
            .copied()
            .filter(|&h| !input.headers.contains_key(h))
            .collect();
        let missing_count = missing_headers.len();

        // ── JS redirect (window.location in body text) ────────────────────────
        let js_redirect = body_lower.contains("window.location")
            || body_lower.contains("meta http-equiv=\"refresh\"");

        // ── Very thin content (possible doorway / parked page) ────────────────
        let thin_content = input.body_text.split_whitespace().count() < 50;

        // ── Scoring ───────────────────────────────────────────────────────────
        let mut delta: f32 = 0.0;
        if phishing_count >= 3 {
            delta -= 0.40;
        } else if phishing_count >= 1 {
            delta -= 0.15 * phishing_count as f32;
        }
        if js_suspicious {
            delta -= 0.25;
        }
        if js_redirect {
            delta -= 0.10;
        }
        if thin_content {
            delta -= 0.05;
        }
        // Missing security headers are a weak signal — partial penalty.
        delta -= 0.03 * missing_count as f32;

        // Bonus: no phishing hits and all security headers present.
        if phishing_count == 0 && !js_suspicious && missing_count == 0 {
            delta += 0.15;
        }

        let passed = phishing_count == 0 && !js_suspicious && !js_redirect;

        let report = AgentReport::new("content_analyzer")
            .passed(passed)
            .delta(delta.clamp(-1.0, 1.0))
            .detail("phishing_keywords_found", phishing_count.to_string())
            .detail("phishing_keywords", phishing_hits.join(", "))
            .detail("suspicious_js", js_suspicious.to_string())
            .detail("js_patterns_found", js_hits.join(", "))
            .detail("js_redirect", js_redirect.to_string())
            .detail("thin_content", thin_content.to_string())
            .detail("missing_security_headers", missing_headers.join(", "));

        Ok(report)
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn make_output(body: &str) -> ScraperOutput {
        ScraperOutput {
            job_id: Uuid::new_v4(),
            url: "https://example.com".into(),
            final_url: "https://example.com".into(),
            status_code: 200,
            headers: HashMap::new(),
            body_text: body.into(),
            ssl_valid: Some(true),
            ssl_expiry_days: None,
            ssl_issuer: None,
            latency_ms: 100,
            scraped_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn clean_body_passes() {
        let body = "Welcome to our website. We sell widgets and gadgets. ".repeat(10);
        let r = ContentAnalyzerAgent.run(&make_output(&body)).await.unwrap();
        assert!(r.passed);
    }

    #[tokio::test]
    async fn phishing_body_fails() {
        let body = "verify your account now! Your account has been suspended. \
                    Unusual activity detected. Click here urgently to confirm your identity.";
        let r = ContentAnalyzerAgent.run(&make_output(body)).await.unwrap();
        assert!(!r.passed);
        assert!(r.confidence_delta < 0.0);
    }

    #[tokio::test]
    async fn suspicious_js_fails() {
        let body = "loading... <script>eval(atob('dGVzdA=='))</script>";
        let r = ContentAnalyzerAgent.run(&make_output(body)).await.unwrap();
        assert!(r.details.get("suspicious_js").map(String::as_str) == Some("true"));
    }
}
