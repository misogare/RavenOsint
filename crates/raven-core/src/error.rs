//! Structured error type for the entire RavenOSINT framework.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OsintError {
    // ── I/O & network ─────────────────────────────────────────────────────────
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    InvalidUrl(#[from] url::ParseError),

    // ── Scraper ───────────────────────────────────────────────────────────────
    #[error("Scraper error: {0}")]
    Scraper(String),

    #[error("Rate limit exceeded for domain: {0}")]
    RateLimit(String),

    // ── Discovery ─────────────────────────────────────────────────────────────
    #[error("Discovery error: {0}")]
    Discovery(String),

    #[error("Invalid discovery pattern: {0}")]
    DiscoveryPattern(String),

    // ── Agent ─────────────────────────────────────────────────────────────────
    #[error("Agent '{name}' failed: {reason}")]
    Agent { name: String, reason: String },

    #[error("Agent orchestrator error: {0}")]
    Orchestrator(String),

    // ── LLM ───────────────────────────────────────────────────────────────────
    #[error("LLM provider error: {0}")]
    Llm(String),

    #[error("LLM response parse error: {0}")]
    LlmParse(String),

    // ── Storage ───────────────────────────────────────────────────────────────
    #[error("Database error: {0}")]
    Database(String),

    #[error("Record not found: {0}")]
    NotFound(String),

    // ── Config ────────────────────────────────────────────────────────────────
    #[error("Configuration error: {0}")]
    Config(String),

    // ── Bus ────────────────────────────────────────────────────────────────────
    #[error("Event bus error: {0}")]
    Bus(String),

    // ── Generic ───────────────────────────────────────────────────────────────
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialisation error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl From<anyhow::Error> for OsintError {
    fn from(e: anyhow::Error) -> Self {
        OsintError::Other(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, OsintError>;
