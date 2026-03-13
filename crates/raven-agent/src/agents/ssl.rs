//! `SslAgent` — validates HTTPS/TLS health of the target.

use async_trait::async_trait;
use raven_core::{AgentPlugin, AgentReport, OsintError, ScraperOutput};

pub struct SslAgent;

#[async_trait]
impl AgentPlugin for SslAgent {
    fn name(&self) -> &str {
        "ssl"
    }

    async fn run(&self, input: &ScraperOutput) -> Result<AgentReport, OsintError> {
        let is_https = input.url.starts_with("https://");

        // If not HTTPS at all, fail immediately.
        if !is_https {
            return Ok(AgentReport::new("ssl")
                .passed(false)
                .delta(-0.15)
                .detail("verdict", "site uses plain HTTP — no TLS")
                .detail("https", "false"));
        }

        // rustls already rejected invalid certs, so reaching here means valid.
        let cert_valid = input.ssl_valid.unwrap_or(false);

        // Check for HSTS (Strict-Transport-Security) header.
        let hsts = input
            .headers
            .get("strict-transport-security")
            .map(|v| v.as_str())
            .unwrap_or("");
        let has_hsts = !hsts.is_empty();

        // Check for expiry proximity (None in P0 — cert introspection is P1).
        let expiry_warning = match input.ssl_expiry_days {
            Some(days) if days < 7  => Some("critical — cert expires in < 7 days"),
            Some(days) if days < 30 => Some("warning — cert expires in < 30 days"),
            _ => None,
        };
        let expiry_days_str = input
            .ssl_expiry_days
            .map(|d| d.to_string())
            .unwrap_or_else(|| "unknown".into());

        let passed = cert_valid && expiry_warning.is_none();

        // Delta: full HTTPS + HSTS is the ideal case.
        let delta = if !cert_valid {
            -0.35
        } else if expiry_warning.is_some() {
            -0.10
        } else if has_hsts {
            0.20
        } else {
            0.10
        };

        let mut report = AgentReport::new("ssl")
            .passed(passed)
            .delta(delta)
            .detail("https",        "true")
            .detail("cert_valid",   cert_valid.to_string())
            .detail("hsts",         has_hsts.to_string())
            .detail("issuer",       input.ssl_issuer.clone().unwrap_or_else(|| "unknown".into()))
            .detail("expiry_days",  expiry_days_str);

        if let Some(warn) = expiry_warning {
            report = report.detail("expiry_warning", warn.to_string());
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn make_output(url: &str, ssl_valid: Option<bool>) -> ScraperOutput {
        ScraperOutput {
            job_id:          Uuid::new_v4(),
            url:             url.into(),
            final_url:       url.into(),
            status_code:     200,
            headers:         HashMap::new(),
            body_text:       String::new(),
            ssl_valid,
            ssl_expiry_days: None,
            ssl_issuer:      None,
            latency_ms:      100,
            scraped_at:      Utc::now(),
        }
    }

    #[tokio::test]
    async fn http_site_fails() {
        let out = make_output("http://example.com", None);
        let r = SslAgent.run(&out).await.unwrap();
        assert!(!r.passed);
        assert!(r.confidence_delta < 0.0);
    }

    #[tokio::test]
    async fn valid_https_passes() {
        let out = make_output("https://example.com", Some(true));
        let r = SslAgent.run(&out).await.unwrap();
        assert!(r.passed);
    }

    #[tokio::test]
    async fn hsts_boosts_delta() {
        let mut out = make_output("https://example.com", Some(true));
        out.headers.insert(
            "strict-transport-security".into(),
            "max-age=31536000; includeSubDomains".into(),
        );
        let r = SslAgent.run(&out).await.unwrap();
        assert_eq!(r.details.get("hsts").map(String::as_str), Some("true"));
        assert!(r.confidence_delta >= 0.20);
    }
}
