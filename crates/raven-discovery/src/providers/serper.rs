use async_trait::async_trait;
use chrono::Utc;
use raven_core::{
    config::DiscoveryConfig, DiscoveredUrl, DiscoveryPlugin, DiscoveryProviderKind,
    DiscoveryRequest, DiscoveryResult, DiscoveryType, OsintError, SearchProvider,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::normalize::{extract_domain, normalize_url};

/// Maximum results per request on Serper's free tier.
/// Paid tiers support higher values; this constant is used to emit a warning,
/// not to hard-block. If you are on a paid tier you can raise this constant or
/// remove the guard entirely.
const SERPER_FREE_TIER_MAX: usize = 10;

/// Serper-backed Google-style search discovery.
///
/// Docs: <https://serper.dev/api-reference>
/// Auth: `X-API-KEY` header — set via `RAVEN__DISCOVERY__SERPER__API_KEY` env var,
/// never commit real keys to source.
pub struct SerperSearchProvider {
    client: Client,
    api_key: String,
    base_url: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Serper wire types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct SerperRequestBody {
    q: String,
    num: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    gl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct SerperResponse {
    #[serde(default)]
    organic: Vec<SerperOrganicResult>,
}

#[derive(Debug, Deserialize)]
struct SerperOrganicResult {
    title: Option<String>,
    link: String,
    snippet: Option<String>,
    position: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Implementation
// ─────────────────────────────────────────────────────────────────────────────

impl SerperSearchProvider {
    pub fn new(config: &DiscoveryConfig) -> Result<Self, OsintError> {
        if !config.serper.enabled {
            return Err(OsintError::Discovery("serper provider is disabled".into()));
        }
        if config.serper.api_key.is_empty() {
            return Err(OsintError::Config(
                "serper api_key is empty; set RAVEN__DISCOVERY__SERPER__API_KEY".into(),
            ));
        }

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(OsintError::Http)?;

        Ok(Self {
            client,
            api_key: config.serper.api_key.clone(),
            base_url: config.serper.base_url.clone(),
        })
    }

    /// Build the search query string, adding a `site:` scope when requested.
    fn build_query(&self, request: &DiscoveryRequest) -> String {
        match &request.site {
            Some(site) => format!("{} site:{}", request.query.trim(), site.trim()),
            None => request.query.trim().to_string(),
        }
    }

    /// Build the request body for a single page.
    ///
    /// Serper's free tier silently truncates results above 10. We warn when
    /// the caller requests more and clamp to `SERPER_FREE_TIER_MAX` to avoid
    /// sending a value that will just be ignored. Paid-tier callers can raise
    /// `SERPER_FREE_TIER_MAX` or remove the clamp.
    fn build_body(&self, request: &DiscoveryRequest, page: Option<u32>) -> SerperRequestBody {
        let num = if request.limit > SERPER_FREE_TIER_MAX {
            tracing::warn!(
                requested = request.limit,
                capped_at = SERPER_FREE_TIER_MAX,
                "serper: free tier caps results at {} per request; \
                 raise SERPER_FREE_TIER_MAX or use pagination for larger limits",
                SERPER_FREE_TIER_MAX,
            );
            SERPER_FREE_TIER_MAX
        } else {
            request.limit
        };

        SerperRequestBody {
            q: self.build_query(request),
            num,
            gl: request.country.clone().map(|v| v.to_lowercase()),
            hl: request.lang.clone().map(|v| v.to_lowercase()),
            page,
        }
    }

    /// Convert a `SerperResponse` into a `DiscoveryResult`, normalizing each URL.
    fn into_result(
        &self,
        request: &DiscoveryRequest,
        response: SerperResponse,
    ) -> Result<DiscoveryResult, OsintError> {
        let mut urls = Vec::new();

        for organic in response.organic {
            let normalized = match normalize_url(&organic.link) {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(url = %organic.link, error = %e, "serper: skipping malformed URL");
                    continue;
                }
            };

            urls.push(DiscoveredUrl {
                domain: extract_domain(&normalized).unwrap_or_default(),
                url: normalized,
                title: organic.title,
                snippet: organic.snippet,
                provider: DiscoveryProviderKind::Serper,
                discovery_type: if request.site.is_some() {
                    DiscoveryType::DomainScopedSearch
                } else {
                    DiscoveryType::SearchResult
                },
                source_query: request.query.clone(),
                source_url: None,
                rank: organic.position,
                confidence: 0.85,
                discovered_at: Utc::now(),
            });
        }

        Ok(DiscoveryResult {
            job_id: request.job_id,
            request: request.clone(),
            total_discovered: urls.len(),
            urls,
            completed_at: Utc::now(),
        })
    }

    /// Core HTTP call — shared by both trait implementations.
    ///
    /// Sending the same request body from two trait methods was a maintenance
    /// hazard: retry logic, auth header rotation, or timeout changes would
    /// have to be duplicated. This single private method owns all HTTP
    /// concerns; the two trait impls just unwrap the result differently.
    async fn do_search(&self, request: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        let body = self.build_body(request, None);

        let response = self
            .client
            .post(&self.base_url)
            .header("X-API-KEY", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(OsintError::Http)?
            .error_for_status()
            .map_err(OsintError::Http)?
            .json::<SerperResponse>()
            .await
            .map_err(OsintError::Http)?;

        self.into_result(request, response)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Trait implementations
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl SearchProvider for SerperSearchProvider {
    fn name(&self) -> &str {
        "serper"
    }

    async fn search(&self, request: &DiscoveryRequest) -> Result<Vec<DiscoveredUrl>, OsintError> {
        self.do_search(request).await.map(|r| r.urls)
    }
}

#[async_trait]
impl DiscoveryPlugin for SerperSearchProvider {
    fn name(&self) -> &str {
        "serper"
    }

    async fn discover(&self, request: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        self.do_search(request).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::config::{DiscoveryConfig, DiscoveryProviderConfig};

    fn config() -> DiscoveryConfig {
        DiscoveryConfig {
            serper: DiscoveryProviderConfig {
                enabled: true,
                base_url: "https://google.serper.dev/search".into(),
                api_key: "test-key".into(),
                api_secret: String::new(),
            },
            ..DiscoveryConfig::default()
        }
    }

    #[test]
    fn builds_plain_query() {
        let provider = SerperSearchProvider::new(&config()).unwrap();
        let request = DiscoveryRequest::new("phishing indicators");
        assert_eq!(provider.build_query(&request), "phishing indicators");
    }

    #[test]
    fn builds_site_scoped_query() {
        let provider = SerperSearchProvider::new(&config()).unwrap();
        let mut request = DiscoveryRequest::new("phishing indicators");
        request.site = Some("example.com".into());
        assert_eq!(
            provider.build_query(&request),
            "phishing indicators site:example.com"
        );
    }

    #[test]
    fn clamps_limit_to_free_tier_max() {
        let provider = SerperSearchProvider::new(&config()).unwrap();
        let mut request = DiscoveryRequest::new("test");
        request.limit = 50;
        let body = provider.build_body(&request, None);
        assert_eq!(body.num, SERPER_FREE_TIER_MAX);
    }

    #[test]
    fn does_not_clamp_limit_within_free_tier() {
        let provider = SerperSearchProvider::new(&config()).unwrap();
        let mut request = DiscoveryRequest::new("test");
        request.limit = 5;
        let body = provider.build_body(&request, None);
        assert_eq!(body.num, 5);
    }

    #[test]
    fn parses_serper_response() {
        let provider = SerperSearchProvider::new(&config()).unwrap();
        let request = DiscoveryRequest::new("apple inc");
        let response: SerperResponse = serde_json::from_str(
            r#"{
                "organic": [
                    {
                        "title": "Apple",
                        "link": "https://www.apple.com/",
                        "snippet": "Official Apple site",
                        "position": 1
                    }
                ]
            }"#,
        )
        .unwrap();

        let result = provider.into_result(&request, response).unwrap();
        assert_eq!(result.total_discovered, 1);
        assert_eq!(result.urls[0].provider, DiscoveryProviderKind::Serper);
        assert_eq!(result.urls[0].domain, "www.apple.com");
        assert_eq!(result.urls[0].rank, Some(1));
        assert_eq!(result.urls[0].discovery_type, DiscoveryType::SearchResult);
    }

    #[test]
    fn sets_domain_scoped_discovery_type() {
        let provider = SerperSearchProvider::new(&config()).unwrap();
        let mut request = DiscoveryRequest::new("login");
        request.site = Some("example.com".into());
        let response: SerperResponse =
            serde_json::from_str(r#"{"organic": [{"link": "https://example.com/login"}]}"#)
                .unwrap();

        let result = provider.into_result(&request, response).unwrap();
        assert_eq!(
            result.urls[0].discovery_type,
            DiscoveryType::DomainScopedSearch
        );
    }

    #[test]
    fn skips_malformed_url_in_response() {
        let provider = SerperSearchProvider::new(&config()).unwrap();
        let request = DiscoveryRequest::new("test");
        let response: SerperResponse = serde_json::from_str(
            r#"{"organic": [{"link": "not a url at all"}, {"link": "https://good.example.com/"}]}"#,
        )
        .unwrap();

        let result = provider.into_result(&request, response).unwrap();
        assert_eq!(result.total_discovered, 1);
        assert_eq!(result.urls[0].domain, "good.example.com");
    }

    #[test]
    fn new_fails_if_key_is_empty() {
        let mut cfg = config();
        cfg.serper.api_key = String::new();
        assert!(SerperSearchProvider::new(&cfg).is_err());
    }

    #[test]
    fn new_fails_if_provider_disabled() {
        let mut cfg = config();
        cfg.serper.enabled = false;
        assert!(SerperSearchProvider::new(&cfg).is_err());
    }
}
