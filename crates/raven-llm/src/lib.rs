//! raven-llm — LLM provider integration.
//!
//! ## Supported providers (P0)
//! - **DeepSeek** via `async-openai` with a custom `base_url`
//!   (`https://api.deepseek.com/v1`).
//!
//! ## Extension
//! Implement `LlmProvider` from `raven-core` and pass your type as `DynLlm`.

pub mod deepseek;
pub mod prompt;

pub use deepseek::{build_agent_summary, DeepSeekProvider};
