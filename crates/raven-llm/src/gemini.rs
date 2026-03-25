use async_trait::async_trait;
use raven_core::{config::LlmConfig, LlmContext, LlmProvider, LlmVerdict, OsintError};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::{
    prompt,
    response::{format_agent_summary, parse_llm_response, parse_status},
};

pub struct GeminiProvider {
    client: Client,
    base_url: String,
    api_key: String,
    model: String,
    max_tokens: u32,
    temperature: f32,
}

impl GeminiProvider {
    pub fn new(cfg: &LlmConfig) -> Result<Self, OsintError> {
        let base_url = if cfg.base_url.trim().is_empty() {
            "https://generativelanguage.googleapis.com/v1beta".into()
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
struct GeminiGenerateRequest {
    #[serde(rename = "systemInstruction")]
    system_instruction: GeminiInstruction,
    contents: Vec<GeminiContent>,
    #[serde(rename = "generationConfig")]
    generation_config: GeminiGenerationConfig,
}

#[derive(Debug, Serialize)]
struct GeminiInstruction {
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize)]
struct GeminiContent {
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize)]
struct GeminiPart {
    text: String,
}

#[derive(Debug, Serialize)]
struct GeminiGenerationConfig {
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
    temperature: f32,
}

#[derive(Debug, Deserialize)]
struct GeminiGenerateResponse {
    candidates: Option<Vec<GeminiCandidate>>,
}

#[derive(Debug, Deserialize)]
struct GeminiCandidate {
    content: Option<GeminiResponseContent>,
}

#[derive(Debug, Deserialize)]
struct GeminiResponseContent {
    parts: Option<Vec<GeminiResponsePart>>,
}

#[derive(Debug, Deserialize)]
struct GeminiResponsePart {
    text: Option<String>,
}

#[async_trait]
impl LlmProvider for GeminiProvider {
    fn name(&self) -> &str {
        "gemini"
    }

    async fn verify(&self, ctx: &LlmContext) -> Result<LlmVerdict, OsintError> {
        let agent_summary = format_agent_summary(&ctx.agent_summary);
        let user_prompt = prompt::render_verify(&ctx.url, &agent_summary, &ctx.body_snippet)?;

        let endpoint = format!(
            "{}/models/{}:generateContent",
            self.base_url.trim_end_matches('/'),
            self.model
        );

        let payload = GeminiGenerateRequest {
            system_instruction: GeminiInstruction {
                parts: vec![GeminiPart {
                    text: prompt::SYSTEM_PROMPT.to_string(),
                }],
            },
            contents: vec![GeminiContent {
                parts: vec![GeminiPart { text: user_prompt }],
            }],
            generation_config: GeminiGenerationConfig {
                max_output_tokens: self.max_tokens,
                temperature: self.temperature,
            },
        };

        debug!(job_id = %ctx.job_id, model = %self.model, "gemini: sending verification request");

        let response = self
            .client
            .post(endpoint)
            .query(&[("key", self.api_key.as_str())])
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(OsintError::Llm(format!(
                "gemini request failed ({status}): {body}"
            )));
        }

        let parsed: GeminiGenerateResponse = response.json().await?;
        let content = parsed
            .candidates
            .unwrap_or_default()
            .into_iter()
            .flat_map(|c| c.content.into_iter())
            .flat_map(|c| c.parts.unwrap_or_default().into_iter())
            .filter_map(|p| p.text)
            .collect::<Vec<_>>()
            .join("\n");

        if content.trim().is_empty() {
            return Err(OsintError::Llm("Gemini returned no text content".into()));
        }

        debug!(job_id = %ctx.job_id, raw = %content, "gemini: raw response");

        parse_llm_response(&content).map(|raw| {
            info!(
                job_id = %ctx.job_id,
                status = %raw.status,
                confidence = %raw.confidence,
                "gemini: verdict"
            );
            LlmVerdict {
                status: parse_status(&raw.status),
                confidence: raw.confidence.clamp(0.0, 1.0),
                reasoning: raw.reasoning,
            }
        })
    }
}
