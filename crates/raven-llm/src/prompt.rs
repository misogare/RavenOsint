//! Tera-based prompt rendering helpers.

use raven_core::OsintError;
use tera::{Context, Tera};

// ─────────────────────────────────────────────────────────────────────────────
// Templates (embedded — no filesystem access needed at runtime)
// ─────────────────────────────────────────────────────────────────────────────

/// System prompt for the site-legitimacy verification task.
pub const SYSTEM_PROMPT: &str = "\
You are an expert OSINT and cyber threat intelligence analyst. \
Your task is to evaluate whether a website is legitimate or potentially malicious \
based on HTTP metadata and page content provided to you. \
You must respond with ONLY a valid JSON object — no markdown, no code fences, no extra text.";

/// User prompt template for verification (Tera syntax).
pub const VERIFY_TEMPLATE: &str = r#"
Evaluate the following website for legitimacy and threat level.

## Target
URL: {{ url }}

## Agent Findings
{{ agent_summary }}

## Page Content Snippet
{{ body_snippet }}

Respond with ONLY this JSON structure:
{
  "status": "<active|suspicious|down|malicious|unknown>",
  "confidence": <float 0.0 to 1.0>,
  "reasoning": "<one or two concise sentences>"
}
"#;

/// User prompt template for threat analysis.
pub const THREAT_TEMPLATE: &str = r#"
Perform a threat intelligence analysis on the following site.

## Target
URL: {{ url }}

## Raw Agent Reports
{{ agent_summary }}

## Content
{{ body_snippet }}

Identify any indicators of compromise (IOCs), threat actor TTPs, or risk factors.
Respond with ONLY this JSON structure:
{
  "status": "<active|suspicious|down|malicious|unknown>",
  "confidence": <float 0.0 to 1.0>,
  "reasoning": "<detailed threat analysis>"
}
"#;

// ─────────────────────────────────────────────────────────────────────────────

/// Render the verification prompt with the given variables.
pub fn render_verify(
    url: &str,
    agent_summary: &str,
    body_snippet: &str,
) -> Result<String, OsintError> {
    render(VERIFY_TEMPLATE, url, agent_summary, body_snippet)
}

/// Render the threat-analysis prompt with the given variables.
pub fn render_threat(
    url: &str,
    agent_summary: &str,
    body_snippet: &str,
) -> Result<String, OsintError> {
    render(THREAT_TEMPLATE, url, agent_summary, body_snippet)
}

fn render(
    template: &str,
    url: &str,
    agent_summary: &str,
    body_snippet: &str,
) -> Result<String, OsintError> {
    let mut ctx = Context::new();
    ctx.insert("url", url);
    ctx.insert("agent_summary", agent_summary);
    ctx.insert("body_snippet", body_snippet);

    // `Tera::one_off` renders a single template string without a file system.
    Tera::one_off(template, &ctx, /* autoescape */ false)
        .map_err(|e| OsintError::Llm(format!("template render error: {e}")))
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_template_renders() {
        let out = render_verify("https://example.com", "agent: passed", "Hello world").unwrap();
        assert!(out.contains("https://example.com"));
        assert!(out.contains("agent: passed"));
    }
}
