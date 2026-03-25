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
use raven_core::{config::LlmConfig, LlmContext, LlmProvider, LlmVerdict, OsintError};
use tracing::{debug, info};

use crate::{
    prompt,
    response::{format_agent_summary, parse_llm_response, parse_status},
};

pub struct OpenAiCompatibleProvider {
    provider_name: String,
    client: Client<OpenAIConfig>,
    model: String,
    max_tokens: u32,
    temperature: f32,
}

impl OpenAiCompatibleProvider {
    pub fn new(provider_name: impl Into<String>, cfg: &LlmConfig) -> Result<Self, OsintError> {
        let provider_name = provider_name.into();

        let config = OpenAIConfig::new()
            .with_api_base(&cfg.base_url)
            .with_api_key(&cfg.api_key);

        let client = Client::with_config(config);
        Ok(Self {
            provider_name,
            client,
            model: cfg.model.clone(),
            max_tokens: cfg.max_tokens,
            temperature: cfg.temperature,
        })
    }
}

#[async_trait]
impl LlmProvider for OpenAiCompatibleProvider {
    fn name(&self) -> &str {
        &self.provider_name
    }

    async fn verify(&self, ctx: &LlmContext) -> Result<LlmVerdict, OsintError> {
        let agent_summary = format_agent_summary(&ctx.agent_summary);
        let user_prompt = prompt::render_verify(&ctx.url, &agent_summary, &ctx.body_snippet)?;

        debug!(
            provider = %self.provider_name,
            job_id = %ctx.job_id,
            model = %self.model,
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

        let content = response
            .choices
            .into_iter()
            .next()
            .and_then(|c| c.message.content)
            .ok_or_else(|| OsintError::Llm("LLM returned no content".into()))?;

        debug!(
            provider = %self.provider_name,
            job_id = %ctx.job_id,
            raw = %content,
            "llm: raw response"
        );

        parse_llm_response(&content).map(|raw| {
            info!(
                provider = %self.provider_name,
                job_id = %ctx.job_id,
                status = %raw.status,
                confidence = %raw.confidence,
                "llm: verdict"
            );

            LlmVerdict {
                status: parse_status(&raw.status),
                confidence: raw.confidence.clamp(0.0, 1.0),
                reasoning: raw.reasoning,
            }
        })
    }
}
