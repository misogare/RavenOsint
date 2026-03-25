use async_trait::async_trait;
use raven_core::{config::LlmConfig, LlmContext, LlmProvider, LlmVerdict, OsintError};

use crate::openai_compatible::OpenAiCompatibleProvider;

pub struct KimiProvider {
    inner: OpenAiCompatibleProvider,
}

impl KimiProvider {
    pub fn new(cfg: &LlmConfig) -> Result<Self, OsintError> {
        let mut adjusted = cfg.clone();
        if adjusted.base_url.trim().is_empty() {
            adjusted.base_url = "https://api.moonshot.cn/v1".into();
        }

        Ok(Self {
            inner: OpenAiCompatibleProvider::new("kimi", &adjusted)?,
        })
    }
}

#[async_trait]
impl LlmProvider for KimiProvider {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn verify(&self, ctx: &LlmContext) -> Result<LlmVerdict, OsintError> {
        self.inner.verify(ctx).await
    }
}
