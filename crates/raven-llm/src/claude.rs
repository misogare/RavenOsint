use async_trait::async_trait;
use raven_core::{config::LlmConfig, LlmContext, LlmProvider, LlmVerdict, OsintError};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::{
    prompt,
    response::{format_agent_summary, parse_llm_response, parse_status},
};

pub struct ClaudeProvider {
    client: Client,
    base_url: String,
    api_key: String,
    model: String,
    max_tokens: u32,
    temperature: f32,
}

impl ClaudeProvider {
    pub fn new(cfg: &LlmConfig) -> Result<Self, OsintError> {
        let base_url = if cfg.base_url.trim().is_empty() {
            "https://api.anthropic.com/v1".into()
        } else {
            cfg.base_url.clone()
        };

        Ok(Self {
            client: Client::new(),
            base_url,
            api_key: cfg.api_key.clone(),
            model: cfg.model.clone(),
            max_tokens: cfg.max_tokens,
            temperature: cfg.temperature,
        })
    }
}

#[derive(Debug, Serialize)]
struct ClaudeMessagesRequest {
    model: String,
    #[serde(rename = "max_tokens")]
    max_tokens: u32,
    temperature: f32,
    system: String,
    messages: Vec<ClaudeMessage>,
}

#[derive(Debug, Serialize)]
struct ClaudeMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ClaudeMessagesResponse {
    content: Vec<ClaudeContentBlock>,
}

#[derive(Debug, Deserialize)]
struct ClaudeContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    text: Option<String>,
}

#[async_trait]
impl LlmProvider for ClaudeProvider {
    fn name(&self) -> &str {
        "claude"
    }

    async fn verify(&self, ctx: &LlmContext) -> Result<LlmVerdict, OsintError> {
        let agent_summary = format_agent_summary(&ctx.agent_summary);
        let user_prompt = prompt::render_verify(&ctx.url, &agent_summary, &ctx.body_snippet)?;

        let endpoint = format!("{}/messages", self.base_url.trim_end_matches('/'));
        let payload = ClaudeMessagesRequest {
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            temperature: self.temperature,
            system: prompt::SYSTEM_PROMPT.to_string(),
            messages: vec![ClaudeMessage {
                role: "user".into(),
                content: user_prompt,
            }],
        };

        debug!(job_id = %ctx.job_id, model = %self.model, "claude: sending verification request");

        let response = self
            .client
            .post(endpoint)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(OsintError::Llm(format!(
                "claude request failed ({status}): {body}"
            )));
        }

        let parsed: ClaudeMessagesResponse = response.json().await?;
        let content = parsed
            .content
            .into_iter()
            .filter(|b| b.block_type == "text")
            .filter_map(|b| b.text)
            .collect::<Vec<_>>()
            .join("\n");

        if content.trim().is_empty() {
            return Err(OsintError::Llm("Claude returned no text content".into()));
        }

        debug!(job_id = %ctx.job_id, raw = %content, "claude: raw response");

        parse_llm_response(&content).map(|raw| {
            info!(
                job_id = %ctx.job_id,
                status = %raw.status,
                confidence = %raw.confidence,
                "claude: verdict"
            );
            LlmVerdict {
                status: parse_status(&raw.status),
                confidence: raw.confidence.clamp(0.0, 1.0),
                reasoning: raw.reasoning,
            }
        })
    }
}
