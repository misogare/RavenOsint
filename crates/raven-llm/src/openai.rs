use async_trait::async_trait;
use raven_core::{config::LlmConfig, LlmContext, LlmProvider, LlmVerdict, OsintError};

use crate::openai_compatible::OpenAiCompatibleProvider;

pub struct OpenAiProvider {
    inner: OpenAiCompatibleProvider,
}

impl OpenAiProvider {
    pub fn new(cfg: &LlmConfig) -> Result<Self, OsintError> {
        let mut adjusted = cfg.clone();
        if adjusted.base_url.trim().is_empty() {
            adjusted.base_url = "https://api.openai.com/v1".into();
        }

        Ok(Self {
            inner: OpenAiCompatibleProvider::new("openai", &adjusted)?,
        })
    }
}

#[async_trait]
impl LlmProvider for OpenAiProvider {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn verify(&self, ctx: &LlmContext) -> Result<LlmVerdict, OsintError> {
        self.inner.verify(ctx).await
    }
}
