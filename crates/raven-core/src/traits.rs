//! Trait contracts — every plugin/provider implements one of these.

use crate::{
    AgentReport, DiscoveredUrl, DiscoveryRequest, DiscoveryResult, LlmContext, LlmVerdict,
    OsintError, ScraperOutput,
};
use async_trait::async_trait;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// Scraper plugin
// ─────────────────────────────────────────────────────────────────────────────

/// A pluggable scraper that fetches and extracts data from a URL.
#[async_trait]
pub trait ScraperPlugin: Send + Sync + 'static {
    /// Human-readable name (e.g. "generic_http", "shodan").
    fn name(&self) -> &str;

    /// Return true if this scraper can handle the given URL scheme/domain.
    fn can_handle(&self, url: &str) -> bool;

    /// Perform the scrape and return structured output.
    async fn scrape(&self, url: &str) -> Result<ScraperOutput, OsintError>;
}

/// Convenience alias for a heap-allocated, dynamically-dispatched scraper.
pub type DynScraper = Arc<dyn ScraperPlugin>;

// ─────────────────────────────────────────────────────────────────────────────
// Agent plugin
// ─────────────────────────────────────────────────────────────────────────────

/// A validation agent that inspects a `ScraperOutput` and produces a report.
#[async_trait]
pub trait AgentPlugin: Send + Sync + 'static {
    fn name(&self) -> &str;

    /// IDs / names of other agents whose reports must be ready before this one runs.
    fn depends_on(&self) -> Vec<String> {
        vec![]
    }

    async fn run(&self, input: &ScraperOutput) -> Result<AgentReport, OsintError>;
}

pub type DynAgent = Arc<dyn AgentPlugin>;

// ─────────────────────────────────────────────────────────────────────────────
// LLM provider
// ─────────────────────────────────────────────────────────────────────────────

/// An LLM backend that can verify / classify OSINT findings.
#[async_trait]
pub trait LlmProvider: Send + Sync + 'static {
    fn name(&self) -> &str;

    async fn verify(&self, ctx: &LlmContext) -> Result<LlmVerdict, OsintError>;
}

pub type DynLlm = Arc<dyn LlmProvider>;

// ─────────────────────────────────────────────────────────────────────────────
// Search providers
// ─────────────────────────────────────────────────────────────────────────────

/// A query-driven discovery source, such as Serper or Exa.
#[async_trait]
pub trait SearchProvider: Send + Sync + 'static {
    fn name(&self) -> &str;

    async fn search(&self, request: &DiscoveryRequest) -> Result<Vec<DiscoveredUrl>, OsintError>;
}

pub type DynSearchProvider = Arc<dyn SearchProvider>;

// ─────────────────────────────────────────────────────────────────────────────
// Discovery plugins
// ─────────────────────────────────────────────────────────────────────────────

/// A discovery plugin that expands a request into a set of candidate URLs.
#[async_trait]
pub trait DiscoveryPlugin: Send + Sync + 'static {
    fn name(&self) -> &str;

    async fn discover(&self, request: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError>;
}

pub type DynDiscovery = Arc<dyn DiscoveryPlugin>;
