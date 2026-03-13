//! `RavenScraper` — the default HTTP scraper implementing `ScraperPlugin`.

use crate::{
    extract::{extract_text, is_json},
    rate_limit::DomainRateLimiter,
};
use async_trait::async_trait;
use chrono::Utc;
use raven_core::{config::ScraperConfig, OsintError, ScraperOutput, ScraperPlugin};
use reqwest::{Client, Proxy};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Instant;
use tracing::{debug, info};
use url::Url;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Security headers we capture in `ScraperOutput.headers`
// ─────────────────────────────────────────────────────────────────────────────

const CAPTURED_HEADERS: &[&str] = &[
    "content-type",
    "server",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "content-security-policy",
    "x-powered-by",
    "location",
    "set-cookie",
];

// ─────────────────────────────────────────────────────────────────────────────
// RavenScraper
// ─────────────────────────────────────────────────────────────────────────────

/// The default OSINT HTTP scraper.
///
/// - Rotates user-agents and proxy clients in round-robin fashion.
/// - Enforces per-domain rate limits with `governor`.
/// - Validates TLS via `rustls` (invalid certs → request error).
pub struct RavenScraper {
    /// One `reqwest::Client` per configured proxy (or exactly one if no proxies).
    clients:      Vec<Client>,
    client_idx:   AtomicUsize,
    rate_limiter: Arc<DomainRateLimiter>,
    user_agents:  Vec<String>,
    ua_idx:       AtomicUsize,
}

impl RavenScraper {
    /// Build a new scraper from `ScraperConfig`.
    pub fn new(cfg: &ScraperConfig) -> Result<Self, OsintError> {
        let timeout   = std::time::Duration::from_secs(cfg.timeout_secs);
        let redirects = cfg.max_redirects as usize;

        // Build one client per proxy entry (empty list → single no-proxy client).
        let proxy_urls: Vec<&str> = if cfg.proxies.is_empty() {
            vec![] // will produce exactly one client with no proxy
        } else {
            cfg.proxies.iter().map(String::as_str).collect()
        };

        let mut clients = Vec::new();

        let build_client = |proxy: Option<&str>| -> Result<Client, OsintError> {
            let mut b = Client::builder()
                .timeout(timeout)
                .redirect(reqwest::redirect::Policy::limited(redirects))
                .use_rustls_tls()
                // Don't send referrer — reduces fingerprint.
                .referer(false);

            if let Some(url) = proxy {
                b = b.proxy(
                    Proxy::all(url)
                        .map_err(|e| OsintError::Config(format!("invalid proxy URL '{url}': {e}")))?,
                );
            }

            b.build().map_err(OsintError::Http)
        };

        if proxy_urls.is_empty() {
            clients.push(build_client(None)?);
        } else {
            for p in &proxy_urls {
                clients.push(build_client(Some(p))?);
            }
        }

        Ok(Self {
            clients,
            client_idx:   AtomicUsize::new(0),
            rate_limiter: Arc::new(DomainRateLimiter::new(cfg.rate_rpm)),
            user_agents:  cfg.user_agents.clone(),
            ua_idx:       AtomicUsize::new(0),
        })
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    fn next_client(&self) -> &Client {
        let i = self.client_idx.fetch_add(1, Ordering::Relaxed);
        &self.clients[i % self.clients.len()]
    }

    fn next_ua(&self) -> &str {
        if self.user_agents.is_empty() {
            return "RavenOSINT/0.1";
        }
        let i = self.ua_idx.fetch_add(1, Ordering::Relaxed);
        &self.user_agents[i % self.user_agents.len()]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScraperPlugin impl
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl ScraperPlugin for RavenScraper {
    fn name(&self) -> &str {
        "generic_http"
    }

    fn can_handle(&self, url: &str) -> bool {
        url.starts_with("http://") || url.starts_with("https://")
    }

    async fn scrape(&self, url: &str) -> Result<ScraperOutput, OsintError> {
        let parsed = Url::parse(url).map_err(OsintError::InvalidUrl)?;
        let scheme = parsed.scheme().to_string();
        let domain = parsed
            .host_str()
            .unwrap_or("unknown")
            .to_string();

        // Enforce per-domain rate limit.
        self.rate_limiter.acquire(&domain).await;

        let ua     = self.next_ua();
        let client = self.next_client();

        debug!(url = %url, ua = %ua, "scraping");

        let t0  = Instant::now();
        let res = client
            .get(url)
            .header("User-Agent", ua)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Language", "en-US,en;q=0.5")
            .send()
            .await
            .map_err(OsintError::Http)?;
        let latency_ms = t0.elapsed().as_millis() as u64;

        let status_code = res.status().as_u16();
        let final_url   = res.url().to_string();

        // Capture selected response headers.
        let mut headers = std::collections::HashMap::new();
        for &name in CAPTURED_HEADERS {
            if let Some(val) = res.headers().get(name) {
                if let Ok(s) = val.to_str() {
                    headers.insert(name.to_string(), s.to_string());
                }
            }
        }

        let content_type = headers
            .get("content-type")
            .cloned()
            .unwrap_or_default();

        // Consume body.
        let raw_body = res.text().await.map_err(OsintError::Http)?;

        // Extract readable text.
        let body_text = if is_json(&content_type) {
            raw_body.clone()
        } else {
            extract_text(&raw_body)
        };

        // SSL validity: rustls rejects invalid certs by default, so reaching
        // here with HTTPS means the cert was valid at request time.
        // Expiry days / issuer require a separate TLS handshake inspection (P1).
        let ssl_valid = if scheme == "https" { Some(true) } else { None };

        info!(
            url = %url,
            final_url = %final_url,
            status = status_code,
            latency_ms = latency_ms,
            "scrape complete"
        );

        Ok(ScraperOutput {
            job_id:          Uuid::new_v4(), // caller should overwrite with real job id
            url:             url.to_string(),
            final_url,
            status_code,
            headers,
            body_text,
            ssl_valid,
            ssl_expiry_days: None, // TODO P1: TLS cert introspection
            ssl_issuer:      None, // TODO P1: TLS cert introspection
            latency_ms,
            scraped_at:      Utc::now(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::config::ScraperConfig;

    fn default_cfg() -> ScraperConfig {
        ScraperConfig::default()
    }

    #[test]
    fn builds_without_proxies() {
        let s = RavenScraper::new(&default_cfg()).expect("build failed");
        assert_eq!(s.clients.len(), 1);
    }

    #[test]
    fn builds_with_proxies() {
        let mut cfg = default_cfg();
        cfg.proxies = vec!["socks5://127.0.0.1:9050".into()];
        let s = RavenScraper::new(&cfg).expect("build with proxy failed");
        assert_eq!(s.clients.len(), 1);
    }

    #[test]
    fn can_handle_http_urls() {
        let s = RavenScraper::new(&default_cfg()).unwrap();
        assert!(s.can_handle("https://example.com"));
        assert!(s.can_handle("http://example.com"));
        assert!(!s.can_handle("ftp://example.com"));
    }

    #[test]
    fn ua_rotates() {
        let mut cfg = default_cfg();
        cfg.user_agents = vec!["UA-A".into(), "UA-B".into()];
        let s = RavenScraper::new(&cfg).unwrap();
        assert_eq!(s.next_ua(), "UA-A");
        assert_eq!(s.next_ua(), "UA-B");
        assert_eq!(s.next_ua(), "UA-A"); // wraps
    }
}
