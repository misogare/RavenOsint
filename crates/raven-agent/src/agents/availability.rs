//! `AvailabilityAgent` — checks whether the target is reachable and returning
//! a healthy HTTP status code.

use async_trait::async_trait;
use raven_core::{AgentPlugin, AgentReport, OsintError, ScraperOutput};

pub struct AvailabilityAgent;

#[async_trait]
impl AgentPlugin for AvailabilityAgent {
    fn name(&self) -> &str {
        "availability"
    }

    async fn run(&self, input: &ScraperOutput) -> Result<AgentReport, OsintError> {
        let status = input.status_code;
        let ok = (200..=299).contains(&status);

        // Redirect sanity: flag if the final URL domain differs significantly
        // from the original (could signal a suspicious redirect).
        let suspicious_redirect = {
            let original_host = extract_host(&input.url);
            let final_host = extract_host(&input.final_url);
            original_host != final_host
        };

        let latency_grade = match input.latency_ms {
            0..=500 => "fast",
            501..=2000 => "normal",
            _ => "slow",
        };

        let delta = if ok && !suspicious_redirect {
            0.20
        } else if ok && suspicious_redirect {
            -0.10
        } else {
            // 4xx / 5xx
            -0.30
        };

        let report = AgentReport::new("availability")
            .passed(ok)
            .delta(delta)
            .detail("status_code", status.to_string())
            .detail("final_url", input.final_url.clone())
            .detail("latency_ms", input.latency_ms.to_string())
            .detail("latency_grade", latency_grade.to_string())
            .detail("suspicious_redirect", suspicious_redirect.to_string());

        Ok(report)
    }
}

/// Extract just the hostname from a URL string; falls back to the full string.
fn extract_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h: &str| h.to_lowercase()))
        .unwrap_or_else(|| url.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn make_output(status: u16, url: &str, final_url: &str) -> ScraperOutput {
        ScraperOutput {
            job_id: Uuid::new_v4(),
            url: url.into(),
            final_url: final_url.into(),
            status_code: status,
            headers: HashMap::new(),
            body_text: String::new(),
            ssl_valid: None,
            ssl_expiry_days: None,
            ssl_issuer: None,
            latency_ms: 120,
            scraped_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn marks_200_as_passed() {
        let out = make_output(200, "https://example.com", "https://example.com");
        let r = AvailabilityAgent.run(&out).await.unwrap();
        assert!(r.passed);
        assert!(r.confidence_delta > 0.0);
    }

    #[tokio::test]
    async fn marks_404_as_failed() {
        let out = make_output(404, "https://example.com", "https://example.com");
        let r = AvailabilityAgent.run(&out).await.unwrap();
        assert!(!r.passed);
        assert!(r.confidence_delta < 0.0);
    }

    #[tokio::test]
    async fn detects_suspicious_redirect() {
        let out = make_output(200, "https://legit.com", "https://evil.com/page");
        let r = AvailabilityAgent.run(&out).await.unwrap();
        assert_eq!(
            r.details.get("suspicious_redirect").map(String::as_str),
            Some("true")
        );
    }
}
