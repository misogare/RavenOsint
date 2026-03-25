use raven_core::{AgentReport, OsintError, SiteStatus};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct LlmRawResponse {
    pub status: String,
    pub confidence: f32,
    pub reasoning: String,
}

/// Parse the raw JSON block the LLM returns.
/// The LLM is prompted to return clean JSON, but may wrap it in ```json fences.
pub fn parse_llm_response(raw: &str) -> Result<LlmRawResponse, OsintError> {
    let stripped = raw
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let start = stripped
        .find('{')
        .ok_or_else(|| OsintError::LlmParse("no JSON object in LLM response".into()))?;
    let end = stripped
        .rfind('}')
        .ok_or_else(|| OsintError::LlmParse("malformed JSON object in LLM response".into()))?;

    let json_slice = &stripped[start..=end];
    serde_json::from_str::<LlmRawResponse>(json_slice)
        .map_err(|e| OsintError::LlmParse(format!("JSON parse failed: {e}\nRaw: {json_slice}")))
}

pub fn parse_status(s: &str) -> SiteStatus {
    match s.to_lowercase().as_str() {
        "active" => SiteStatus::Active,
        "suspicious" => SiteStatus::Suspicious,
        "down" => SiteStatus::Down,
        "malicious" => SiteStatus::Malicious,
        _ => SiteStatus::Unknown,
    }
}

pub fn format_agent_summary(summary: &str) -> String {
    if summary.len() > 2000 {
        format!("{}...", &summary[..2000])
    } else {
        summary.to_string()
    }
}

pub fn build_agent_summary(reports: &[AgentReport]) -> String {
    reports
        .iter()
        .map(|r| {
            let status = if r.passed { "PASS" } else { "FAIL" };
            let details = r
                .details
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "[{}] {} | delta={:.2} | {}",
                status, r.agent_name, r.confidence_delta, details
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clean_json() {
        let raw = r#"{"status":"active","confidence":0.9,"reasoning":"looks fine"}"#;
        let r = parse_llm_response(raw).unwrap();
        assert_eq!(r.status, "active");
        assert!((r.confidence - 0.9).abs() < 0.001);
    }

    #[test]
    fn parses_json_with_fences() {
        let raw = "```json\n{\"status\":\"malicious\",\"confidence\":0.95,\"reasoning\":\"phishing\"}\n```";
        let r = parse_llm_response(raw).unwrap();
        assert_eq!(r.status, "malicious");
    }

    #[test]
    fn parses_json_embedded_in_prose() {
        let raw = "Here is my analysis: {\"status\":\"suspicious\",\"confidence\":0.7,\"reasoning\":\"odd\"} - done.";
        let r = parse_llm_response(raw).unwrap();
        assert_eq!(r.status, "suspicious");
    }

    #[test]
    fn status_mapping() {
        assert_eq!(parse_status("malicious"), SiteStatus::Malicious);
        assert_eq!(parse_status("ACTIVE"), SiteStatus::Active);
        assert_eq!(parse_status("gibberish"), SiteStatus::Unknown);
    }
}
