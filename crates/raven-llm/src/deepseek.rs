//! `DeepSeekProvider` — LLM backend using the DeepSeek API.
//!
//! Uses `async-openai` with a custom `base_url` so we speak the OpenAI Chat
//! Completions API dialect that DeepSeek exposes at `https://api.deepseek.com/v1`.

use crate::prompt;
use async_openai::{
    config::OpenAIConfig,
    types::{
        ChatCompletionRequestMessage, ChatCompletionRequestSystemMessage,
        ChatCompletionRequestSystemMessageContent, ChatCompletionRequestUserMessage,
        ChatCompletionRequestUserMessageContent, CreateChatCompletionRequestArgs,
    },
    Client,
};
use async_trait::async_trait;
use raven_core::{
    config::LlmConfig, AgentReport, LlmContext, LlmProvider, LlmVerdict, OsintError, SiteStatus,
};
use serde::Deserialize;
use tracing::{debug, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Raw JSON response shape from the LLM
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct LlmRawResponse {
    status:     String,
    confidence: f32,
    reasoning:  String,
}

// ─────────────────────────────────────────────────────────────────────────────

pub struct DeepSeekProvider {
    client:      Client<OpenAIConfig>,
    model:       String,
    max_tokens:  u32,
    temperature: f32,
}

impl DeepSeekProvider {
    /// Construct from `LlmConfig`.
    ///
    /// The `api_key` field is expected to come from the environment variable
    /// `RAVEN__LLM__API_KEY` — never hard-coded.
    pub fn new(cfg: &LlmConfig) -> Result<Self, OsintError> {
        if cfg.api_key.is_empty() {
            warn!("LLM api_key is empty — set RAVEN__LLM__API_KEY env var");
        }

        let config = OpenAIConfig::new()
            .with_api_base(&cfg.base_url)
            .with_api_key(&cfg.api_key);

        let client = Client::with_config(config);

        Ok(Self {
            client,
            model:       cfg.model.clone(),
            max_tokens:  cfg.max_tokens,
            temperature: cfg.temperature,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl LlmProvider for DeepSeekProvider {
    fn name(&self) -> &str {
        "deepseek"
    }

    async fn verify(&self, ctx: &LlmContext) -> Result<LlmVerdict, OsintError> {
        // Build a concise agent summary string for the prompt.
        let agent_summary = format_agent_summary(&ctx.agent_summary);

        // Render prompt from Tera template.
        let user_prompt =
            prompt::render_verify(&ctx.url, &agent_summary, &ctx.body_snippet)?;

        debug!(
            job_id = %ctx.job_id,
            model  = %self.model,
            "llm: sending verification request"
        );

        let request = CreateChatCompletionRequestArgs::default()
            .model(&self.model)
            .messages(vec![
                ChatCompletionRequestMessage::System(ChatCompletionRequestSystemMessage {
                    content: ChatCompletionRequestSystemMessageContent::Text(
                        prompt::SYSTEM_PROMPT.to_string(),
                    ),
                    name: None,
                }),
                ChatCompletionRequestMessage::User(ChatCompletionRequestUserMessage {
                    content: ChatCompletionRequestUserMessageContent::Text(user_prompt),
                    name: None,
                }),
            ])
            .temperature(self.temperature)
            .max_tokens(self.max_tokens as u16)
            .build()
            .map_err(|e| OsintError::Llm(e.to_string()))?;

        let response = self
            .client
            .chat()
            .create(request)
            .await
            .map_err(|e| OsintError::Llm(e.to_string()))?;

        // Extract the text content from the first choice.
        let content = response
            .choices
            .into_iter()
            .next()
            .and_then(|c| c.message.content)
            .ok_or_else(|| OsintError::Llm("LLM returned no content".into()))?;

        debug!(job_id = %ctx.job_id, raw = %content, "llm: raw response");

        parse_llm_response(&content)
            .map(|raw| {
                info!(
                    job_id     = %ctx.job_id,
                    status     = %raw.status,
                    confidence = %raw.confidence,
                    "llm: verdict"
                );
                LlmVerdict {
                    status:     parse_status(&raw.status),
                    confidence: raw.confidence.clamp(0.0, 1.0),
                    reasoning:  raw.reasoning,
                }
            })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse the raw JSON block the LLM returns.
/// The LLM is prompted to return clean JSON, but may wrap it in ```json fences.
fn parse_llm_response(raw: &str) -> Result<LlmRawResponse, OsintError> {
    // Strip common markdown code fences.
    let stripped = raw
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    // Find the first `{` and last `}` to extract just the JSON object.
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

/// Map the LLM's string status to our `SiteStatus` enum.
fn parse_status(s: &str) -> SiteStatus {
    match s.to_lowercase().as_str() {
        "active"     => SiteStatus::Active,
        "suspicious" => SiteStatus::Suspicious,
        "down"       => SiteStatus::Down,
        "malicious"  => SiteStatus::Malicious,
        _            => SiteStatus::Unknown,
    }
}

/// Turn the agent_summary field (already a string in `LlmContext`) into a
/// prompt-friendly string.  Truncates to avoid token overflows.
fn format_agent_summary(summary: &str) -> String {
    if summary.len() > 2000 {
        format!("{}…", &summary[..2000])
    } else {
        summary.to_string()
    }
}

/// Helper for callers: build a human-readable agent summary from reports.
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
            format!("[{}] {} | delta={:.2} | {}", status, r.agent_name, r.confidence_delta, details)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────

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
        assert_eq!(parse_status("malicious"),  SiteStatus::Malicious);
        assert_eq!(parse_status("ACTIVE"),     SiteStatus::Active);
        assert_eq!(parse_status("gibberish"),  SiteStatus::Unknown);
    }
}
