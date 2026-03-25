//! All shared domain types used across the framework.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Site status
// ─────────────────────────────────────────────────────────────────────────────

/// High-level classification of a scanned target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SiteStatus {
    Active,
    Suspicious,
    Down,
    Malicious,
    #[default]
    Unknown,
}

impl std::fmt::Display for SiteStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SiteStatus::Active => write!(f, "Active"),
            SiteStatus::Suspicious => write!(f, "Suspicious"),
            SiteStatus::Down => write!(f, "Down"),
            SiteStatus::Malicious => write!(f, "Malicious"),
            SiteStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery types
// ─────────────────────────────────────────────────────────────────────────────

/// High-level discovery source/provider type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryProviderKind {
    #[default]
    Serper,
    Exa,
    SeedFile,
    Censys,
    VirusTotal,
    Other,
}

/// How a URL was discovered.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryType {
    SearchResult,
    DomainScopedSearch,
    SeedFile,
    CensysAsset,
    VirusTotalPivot,
    Redirect,
    InPageLink,
    #[default]
    Other,
}

/// Request payload for a discovery job.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DiscoveryRequest {
    pub job_id: Uuid,
    /// Free-form search query or a seed term.
    pub query: String,
    /// Optional domain scope, such as `example.com`.
    pub site: Option<String>,
    /// Which provider should service the request.
    pub provider: DiscoveryProviderKind,
    /// Maximum number of candidate URLs to return.
    pub limit: usize,
    /// Optional country hint passed to providers that support geo-localization.
    pub country: Option<String>,
    /// Optional language hint.
    pub lang: Option<String>,
    /// Whether subdomains should be included when `site` is set.
    pub include_subdomains: bool,
    /// Whether discovered URLs should be immediately fed into validation.
    pub validate: bool,
    pub requested_at: DateTime<Utc>,
}

impl DiscoveryRequest {
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            job_id: Uuid::new_v4(),
            query: query.into(),
            site: None,
            provider: DiscoveryProviderKind::default(),
            limit: 25,
            country: None,
            lang: None,
            include_subdomains: true,
            validate: false,
            requested_at: Utc::now(),
        }
    }
}

/// A normalized candidate URL emitted by discovery.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DiscoveredUrl {
    pub url: String,
    pub domain: String,
    pub title: Option<String>,
    pub snippet: Option<String>,
    pub provider: DiscoveryProviderKind,
    pub discovery_type: DiscoveryType,
    pub source_query: String,
    pub source_url: Option<String>,
    pub rank: Option<u32>,
    pub confidence: f32,
    pub discovered_at: DateTime<Utc>,
}

/// Result of a full discovery job.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DiscoveryResult {
    pub job_id: Uuid,
    pub request: DiscoveryRequest,
    pub urls: Vec<DiscoveredUrl>,
    pub total_discovered: usize,
    pub completed_at: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Input target
// ─────────────────────────────────────────────────────────────────────────────

/// A URL target submitted for OSINT analysis.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OsintTarget {
    /// Unique job identifier.
    pub id: Uuid,
    /// The URL to analyse.
    pub url: String,
    /// Optional tags for grouping / filtering.
    pub tags: Vec<String>,
    /// Arbitrary key-value metadata (e.g. source IP, reporter).
    pub metadata: HashMap<String, String>,
    /// When the job was submitted.
    pub submitted_at: DateTime<Utc>,
}

impl OsintTarget {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            url: url.into(),
            tags: Vec::new(),
            metadata: HashMap::new(),
            submitted_at: Utc::now(),
        }
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scraper output
// ─────────────────────────────────────────────────────────────────────────────

/// Everything the scraper extracts from a single HTTP fetch.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScraperOutput {
    pub job_id: Uuid,
    pub url: String,
    /// Final URL after redirect chain.
    pub final_url: String,
    pub status_code: u16,
    /// Selected response headers (Content-Type, Server, X-Frame-Options, etc.)
    pub headers: HashMap<String, String>,
    /// Plain-text body (HTML stripped or raw if JSON/XML).
    pub body_text: String,
    /// Whether TLS was used and whether the certificate is currently valid.
    pub ssl_valid: Option<bool>,
    /// Days until SSL cert expiry (None if HTTP or cert parse failed).
    pub ssl_expiry_days: Option<i64>,
    /// TLS issuer organisation string.
    pub ssl_issuer: Option<String>,
    /// Round-trip time in milliseconds.
    pub latency_ms: u64,
    pub scraped_at: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent report
// ─────────────────────────────────────────────────────────────────────────────

/// Result produced by a single validation agent.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AgentReport {
    pub agent_name: String,
    /// Whether the agent's check passed (true = looks healthy/benign).
    pub passed: bool,
    /// Human-readable findings. Key = finding name, value = detail string.
    pub details: HashMap<String, String>,
    /// Amount by which this agent adjusts the global confidence score.
    /// Positive delta = more confident the site is legitimate.
    pub confidence_delta: f32,
}

impl AgentReport {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            agent_name: name.into(),
            passed: false,
            details: HashMap::new(),
            confidence_delta: 0.0,
        }
    }

    pub fn passed(mut self, v: bool) -> Self {
        self.passed = v;
        self
    }

    pub fn delta(mut self, d: f32) -> Self {
        self.confidence_delta = d;
        self
    }

    pub fn detail(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.details.insert(k.into(), v.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LLM types
// ─────────────────────────────────────────────────────────────────────────────

/// Input context passed to the LLM for verification.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LlmContext {
    pub job_id: Uuid,
    pub url: String,
    /// Truncated body text (first ~4 000 chars / ~1 000 tokens).
    pub body_snippet: String,
    /// Brief summary of agent findings, injected into the prompt.
    pub agent_summary: String,
}

/// Structured verdict returned by the LLM.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LlmVerdict {
    pub status: SiteStatus,
    /// 0.0 (no confidence) → 1.0 (fully confident).
    pub confidence: f32,
    pub reasoning: String,
}

impl Default for LlmVerdict {
    fn default() -> Self {
        Self {
            status: SiteStatus::Unknown,
            confidence: 0.0,
            reasoning: "LLM not invoked".into(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Final validation result
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated result for a single OSINT job, stored and returned via API.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidationResult {
    pub job_id: Uuid,
    pub target: OsintTarget,
    pub scraper_output: Option<ScraperOutput>,
    pub agent_reports: Vec<AgentReport>,
    pub llm_verdict: LlmVerdict,
    /// Final status — last-writer-wins: LLM overrides agents, agents override scraper.
    pub status: SiteStatus,
    /// Aggregate confidence 0.0–1.0.
    pub confidence: f32,
    pub completed_at: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Bus events (re-exported for bus crate)
// ─────────────────────────────────────────────────────────────────────────────

/// Events published on the internal message bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BusEvent {
    TargetQueued(OsintTarget),
    DiscoveryQueued(DiscoveryRequest),
    DiscoveryUrlsFound {
        job_id: Uuid,
        urls: Vec<DiscoveredUrl>,
    },
    DiscoveryComplete(DiscoveryResult),
    DiscoveryFailed {
        job_id: Uuid,
        error: String,
    },
    ScrapeDone(ScraperOutput),
    AgentDone {
        job_id: Uuid,
        reports: Vec<AgentReport>,
    },
    LlmVerified {
        job_id: Uuid,
        verdict: LlmVerdict,
    },
    PipelineComplete {
        job_id: Uuid,
        result: ValidationResult,
    },
    PipelineFailed {
        job_id: Uuid,
        error: String,
    },
}
