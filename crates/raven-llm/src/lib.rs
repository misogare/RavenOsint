//! raven-llm — LLM provider integration.
//!
//! ## Supported providers
//! - **DeepSeek** (OpenAI-compatible API)
//! - **OpenAI**
//! - **Kimi** (Moonshot)
//! - **GitHub Copilot / GitHub Models**
//! - **Gemini** (native Google API)
//! - **Claude** (native Anthropic API)
//!
//! ## Extension
//! Implement `LlmProvider` from `raven-core` and pass your type as `DynLlm`.

pub mod claude;
pub mod deepseek;
pub mod gemini;
pub mod github_copilot;
pub mod kimi;
pub mod openai;
pub mod openai_compatible;
pub mod prompt;
pub mod response;

use std::sync::Arc;

use raven_core::{config::LlmConfig, DynLlm, OsintError};
use tracing::warn;

pub use deepseek::DeepSeekProvider;
pub use response::build_agent_summary;

/// Build an LLM provider implementation from runtime configuration.
///
/// Returns `Ok(None)` when the provider is disabled due to missing API key.
pub fn build_provider(cfg: &LlmConfig) -> Result<Option<DynLlm>, OsintError> {
    if cfg.api_key.trim().is_empty() {
        warn!(provider = %cfg.provider, "llm provider disabled: empty api_key");
        return Ok(None);
    }

    let provider = cfg.provider.trim().to_ascii_lowercase();
    let llm: DynLlm = match provider.as_str() {
        "deepseek" => Arc::new(DeepSeekProvider::new(cfg)?),
        "openai" => Arc::new(openai::OpenAiProvider::new(cfg)?),
        "kimi" | "moonshot" => Arc::new(kimi::KimiProvider::new(cfg)?),
        "github_copilot" | "copilot" | "github" | "github_models" => {
            Arc::new(github_copilot::GithubCopilotProvider::new(cfg)?)
        }
        "gemini" | "google" => Arc::new(gemini::GeminiProvider::new(cfg)?),
        "claude" | "anthropic" => Arc::new(claude::ClaudeProvider::new(cfg)?),
        other => {
            return Err(OsintError::Config(format!(
				"unsupported llm provider '{other}'. Supported: deepseek, openai, kimi, github_copilot, gemini, claude"
			)));
        }
    };

    Ok(Some(llm))
}
