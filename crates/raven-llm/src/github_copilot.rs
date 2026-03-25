use async_trait::async_trait;
use raven_core::{config::LlmConfig, LlmContext, LlmProvider, LlmVerdict, OsintError};

use crate::openai_compatible::OpenAiCompatibleProvider;

pub struct GithubCopilotProvider {
    inner: OpenAiCompatibleProvider,
}

impl GithubCopilotProvider {
    pub fn new(cfg: &LlmConfig) -> Result<Self, OsintError> {
        let mut adjusted = cfg.clone();
        if adjusted.base_url.trim().is_empty() {
            adjusted.base_url = "https://models.inference.ai.azure.com".into();
        }

        Ok(Self {
            inner: OpenAiCompatibleProvider::new("github_copilot", &adjusted)?,
        })
    }
}

#[async_trait]
impl LlmProvider for GithubCopilotProvider {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn verify(&self, ctx: &LlmContext) -> Result<LlmVerdict, OsintError> {
        self.inner.verify(ctx).await
    }
}
