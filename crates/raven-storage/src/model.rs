//! Shared serialisation helpers used by both SQLite and PostgreSQL backends.

use raven_core::{
    AgentReport, DiscoveredUrl, DiscoveryResult, LlmVerdict, OsintError, ScraperOutput, SiteStatus,
    ValidationResult,
};
use std::collections::HashMap;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Row types (flat structs that map directly to SQL columns)
// ─────────────────────────────────────────────────────────────────────────────

pub struct JobRow {
    pub id: String,
    pub url: String,
    pub tags: String,         // JSON
    pub metadata: String,     // JSON
    pub submitted_at: String, // ISO-8601
    pub completed_at: Option<String>,
    pub status: String,
}

pub struct ResultRow {
    pub job_id: String,
    pub status: String,
    pub confidence: f64,
    pub llm_status: String,
    pub llm_confidence: f64,
    pub llm_reasoning: String,
    pub scraper_output: Option<String>, // JSON
    pub completed_at: String,
}

pub struct AgentRow {
    pub id: String,
    pub job_id: String,
    pub agent_name: String,
    pub passed: i64,
    pub confidence_delta: f64,
    pub details: String, // JSON
}

pub struct DiscoveryJobRow {
    pub job_id: String,
    pub request_json: String,
    pub total_discovered: i64,
    pub completed_at: String,
}

pub struct DiscoveredUrlRow {
    pub id: String,
    pub job_id: String,
    pub payload: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Serialisation helpers
// ─────────────────────────────────────────────────────────────────────────────

pub fn status_to_str(s: &SiteStatus) -> &'static str {
    match s {
        SiteStatus::Active => "active",
        SiteStatus::Suspicious => "suspicious",
        SiteStatus::Down => "down",
        SiteStatus::Malicious => "malicious",
        SiteStatus::Unknown => "unknown",
    }
}

pub fn str_to_status(s: &str) -> SiteStatus {
    match s {
        "active" => SiteStatus::Active,
        "suspicious" => SiteStatus::Suspicious,
        "down" => SiteStatus::Down,
        "malicious" => SiteStatus::Malicious,
        _ => SiteStatus::Unknown,
    }
}

pub fn result_to_rows(
    r: &ValidationResult,
) -> Result<(JobRow, ResultRow, Vec<AgentRow>), OsintError> {
    let job = JobRow {
        id: r.job_id.to_string(),
        url: r.target.url.clone(),
        tags: serde_json::to_string(&r.target.tags)?,
        metadata: serde_json::to_string(&r.target.metadata)?,
        submitted_at: r.target.submitted_at.to_rfc3339(),
        completed_at: Some(r.completed_at.to_rfc3339()),
        status: status_to_str(&r.status).to_string(),
    };

    let scraper_json = r
        .scraper_output
        .as_ref()
        .map(|s| serde_json::to_string(s))
        .transpose()?;

    let result = ResultRow {
        job_id: r.job_id.to_string(),
        status: status_to_str(&r.status).to_string(),
        confidence: r.confidence as f64,
        llm_status: status_to_str(&r.llm_verdict.status).to_string(),
        llm_confidence: r.llm_verdict.confidence as f64,
        llm_reasoning: r.llm_verdict.reasoning.clone(),
        scraper_output: scraper_json,
        completed_at: r.completed_at.to_rfc3339(),
    };

    let agents: Result<Vec<AgentRow>, OsintError> = r
        .agent_reports
        .iter()
        .map(|ar| {
            Ok(AgentRow {
                id: Uuid::new_v4().to_string(),
                job_id: r.job_id.to_string(),
                agent_name: ar.agent_name.clone(),
                passed: ar.passed as i64,
                confidence_delta: ar.confidence_delta as f64,
                details: serde_json::to_string(&ar.details)?,
            })
        })
        .collect();

    Ok((job, result, agents?))
}

/// Reconstruct a `ValidationResult` from flat row data.
/// `agent_rows` must already be filtered to this job.
pub fn rows_to_result(
    job: JobRow,
    result: ResultRow,
    agent_rows: Vec<AgentRow>,
) -> Result<ValidationResult, OsintError> {
    let tags: Vec<String> = serde_json::from_str(&job.tags).unwrap_or_default();
    let metadata: HashMap<String, String> = serde_json::from_str(&job.metadata).unwrap_or_default();
    let submitted_at = chrono::DateTime::parse_from_rfc3339(&job.submitted_at)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| OsintError::Database(format!("submitted_at parse: {e}")))?;
    let completed_at = chrono::DateTime::parse_from_rfc3339(&result.completed_at)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| OsintError::Database(format!("completed_at parse: {e}")))?;

    let job_id =
        Uuid::parse_str(&job.id).map_err(|e| OsintError::Database(format!("uuid parse: {e}")))?;

    let target = raven_core::OsintTarget {
        id: job_id,
        url: job.url,
        tags,
        metadata,
        submitted_at,
    };

    let scraper_output: Option<ScraperOutput> = result
        .scraper_output
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| OsintError::Database(format!("scraper_output parse: {e}")))?;

    let agent_reports: Result<Vec<AgentReport>, OsintError> = agent_rows
        .into_iter()
        .map(|ar| {
            let details: HashMap<String, String> =
                serde_json::from_str(&ar.details).unwrap_or_default();
            Ok(AgentReport {
                agent_name: ar.agent_name,
                passed: ar.passed != 0,
                confidence_delta: ar.confidence_delta as f32,
                details,
            })
        })
        .collect();

    let llm_verdict = LlmVerdict {
        status: str_to_status(&result.llm_status),
        confidence: result.llm_confidence as f32,
        reasoning: result.llm_reasoning,
    };

    Ok(ValidationResult {
        job_id,
        target,
        scraper_output,
        agent_reports: agent_reports?,
        llm_verdict,
        status: str_to_status(&result.status),
        confidence: result.confidence as f32,
        completed_at,
    })
}

pub fn discovery_to_rows(
    result: &DiscoveryResult,
) -> Result<(DiscoveryJobRow, Vec<DiscoveredUrlRow>), OsintError> {
    let job = DiscoveryJobRow {
        job_id: result.job_id.to_string(),
        request_json: serde_json::to_string(&result.request)?,
        total_discovered: result.total_discovered as i64,
        completed_at: result.completed_at.to_rfc3339(),
    };

    let urls: Result<Vec<DiscoveredUrlRow>, OsintError> = result
        .urls
        .iter()
        .map(|url| {
            Ok(DiscoveredUrlRow {
                id: Uuid::new_v4().to_string(),
                job_id: result.job_id.to_string(),
                payload: serde_json::to_string(url)?,
            })
        })
        .collect();

    Ok((job, urls?))
}

pub fn rows_to_discovery(
    job: DiscoveryJobRow,
    url_rows: Vec<DiscoveredUrlRow>,
) -> Result<DiscoveryResult, OsintError> {
    let request = serde_json::from_str(&job.request_json)
        .map_err(|e| OsintError::Database(format!("discovery request parse: {e}")))?;
    let completed_at = chrono::DateTime::parse_from_rfc3339(&job.completed_at)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| OsintError::Database(format!("discovery completed_at parse: {e}")))?;
    let job_id = Uuid::parse_str(&job.job_id)
        .map_err(|e| OsintError::Database(format!("discovery uuid parse: {e}")))?;

    let urls: Result<Vec<DiscoveredUrl>, OsintError> = url_rows
        .into_iter()
        .map(|row| {
            serde_json::from_str(&row.payload)
                .map_err(|e| OsintError::Database(format!("discovered url parse: {e}")))
        })
        .collect();

    Ok(DiscoveryResult {
        job_id,
        request,
        urls: urls?,
        total_discovered: job.total_discovered as usize,
        completed_at,
    })
}
