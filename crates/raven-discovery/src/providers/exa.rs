use async_trait::async_trait;
use chrono::Utc;
use raven_core::{
    config::DiscoveryConfig, DiscoveredUrl, DiscoveryPlugin, DiscoveryProviderKind,
    DiscoveryRequest, DiscoveryResult, DiscoveryType, OsintError, SearchProvider,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::normalize::{extract_domain, normalize_url};

/// Exa-backed agentic web search discovery.
///
/// Docs: <https://docs.exa.ai/reference/search>
/// Auth: `x-api-key` header — set via `RAVEN__DISCOVERY__EXA__API_KEY` env var,
/// never commit real keys to source.
///
/// Exa provides richer retrieval metadata than Serper (summaries, highlights,
/// full-text). Position it as the secondary provider for workflows that need
/// more signal per result; use Serper as the default for high-volume queries.
pub struct ExaSearchProvider {
    client: Client,
    api_key: String,
    base_url: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Exa wire types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ExaRequestBody {
    query: String,
    /// "auto" lets Exa choose between keyword and neural search.
    /// Other valid values: "keyword", "neural".
    #[serde(rename = "type")]
    search_type: String,
    #[serde(rename = "numResults")]
    num_results: usize,
    /// ISO 3166-1 alpha-2 country code hint (e.g. "US", "DE").
    #[serde(skip_serializing_if = "Option::is_none", rename = "locationHint")]
    location_hint: Option<String>,
    /// Restrict results to specific domains when `site` is set on the request.
    #[serde(skip_serializing_if = "Option::is_none", rename = "includeDomains")]
    include_domains: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ExaResponse {
    #[serde(default)]
    results: Vec<ExaResult>,
}

#[derive(Debug, Deserialize)]
struct ExaResult {
    title: Option<String>,
    url: String,
    /// Exa-generated summary — higher quality than raw highlights.
    summary: Option<String>,
    /// Extracted highlight snippets from the page.
    #[serde(default)]
    highlights: Vec<String>,
    /// Full page text (truncated by Exa to ~1 000 tokens).
    text: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Implementation
// ─────────────────────────────────────────────────────────────────────────────

impl ExaSearchProvider {
    pub fn new(config: &DiscoveryConfig) -> Result<Self, OsintError> {
        if !config.exa.enabled {
            return Err(OsintError::Discovery("exa provider is disabled".into()));
        }
        if config.exa.api_key.is_empty() {
            return Err(OsintError::Config(
                "exa api_key is empty; set RAVEN__DISCOVERY__EXA__API_KEY".into(),
            ));
        }

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(OsintError::Http)?;

        Ok(Self {
            client,
            api_key: config.exa.api_key.clone(),
            base_url: config.exa.base_url.clone(),
        })
    }

    /// Build the Exa request body from a `DiscoveryRequest`.
    fn build_body(&self, request: &DiscoveryRequest) -> ExaRequestBody {
        ExaRequestBody {
            query: request.query.trim().to_string(),
            search_type: "auto".into(),
            num_results: request.limit,
            // Exa accepts uppercase ISO country codes as location hints.
            location_hint: request.country.clone().map(|v| v.to_uppercase()),
            include_domains: request.site.clone().map(|site| vec![site]),
        }
    }

    /// Convert an `ExaResponse` into a `DiscoveryResult`, normalizing URLs and
    /// choosing the best available snippet (summary → first highlight → truncated text).
    fn into_result(
        &self,
        request: &DiscoveryRequest,
        response: ExaResponse,
    ) -> Result<DiscoveryResult, OsintError> {
        let mut urls = Vec::new();

        for (index, item) in response.results.into_iter().enumerate() {
            let normalized = match normalize_url(&item.url) {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(url = %item.url, error = %e, "exa: skipping malformed URL");
                    continue;
                }
            };

            // Prefer the Exa-generated summary; fall back to the first highlight;
            // fall back to a 240-char truncation of the full text.
            let snippet = item
                .summary
                .or_else(|| item.highlights.into_iter().next())
                .or_else(|| item.text.map(|t| t.chars().take(240).collect()));

            urls.push(DiscoveredUrl {
                domain: extract_domain(&normalized).unwrap_or_default(),
                url: normalized,
                title: item.title,
                snippet,
                provider: DiscoveryProviderKind::Exa,
                discovery_type: if request.site.is_some() {
                    DiscoveryType::DomainScopedSearch
                } else {
                    DiscoveryType::SearchResult
                },
                source_query: request.query.clone(),
                source_url: None,
                rank: Some((index + 1) as u32),
                confidence: 0.80,
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
    /// Centralising the HTTP logic here means retry/timeout/auth changes are
    /// made in one place; both `SearchProvider::search` and
    /// `DiscoveryPlugin::discover` simply call this and project the result.
    async fn do_search(&self, request: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        let body = self.build_body(request);

        let response = self
            .client
            .post(&self.base_url)
            .header("x-api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(OsintError::Http)?
            .error_for_status()
            .map_err(OsintError::Http)?
            .json::<ExaResponse>()
            .await
            .map_err(OsintError::Http)?;

        self.into_result(request, response)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Trait implementations
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl SearchProvider for ExaSearchProvider {
    fn name(&self) -> &str {
        "exa"
    }

    async fn search(&self, request: &DiscoveryRequest) -> Result<Vec<DiscoveredUrl>, OsintError> {
        self.do_search(request).await.map(|r| r.urls)
    }
}

#[async_trait]
impl DiscoveryPlugin for ExaSearchProvider {
    fn name(&self) -> &str {
        "exa"
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
            exa: DiscoveryProviderConfig {
                enabled: true,
                base_url: "https://api.exa.ai/search".into(),
                api_key: "test-key".into(),
            },
            ..DiscoveryConfig::default()
        }
    }

    #[test]
    fn builds_plain_body() {
        let provider = ExaSearchProvider::new(&config()).unwrap();
        let mut request = DiscoveryRequest::new("phishing kits");
        request.limit = 15;

        let body = provider.build_body(&request);
        assert_eq!(body.num_results, 15);
        assert_eq!(body.include_domains, None);
        assert_eq!(body.search_type, "auto");
    }

    #[test]
    fn builds_domain_scoped_body() {
        let provider = ExaSearchProvider::new(&config()).unwrap();
        let mut request = DiscoveryRequest::new("phishing kits");
        request.site = Some("example.com".into());
        request.limit = 15;

        let body = provider.build_body(&request);
        assert_eq!(body.num_results, 15);
        assert_eq!(
            body.include_domains.as_ref().unwrap(),
            &vec!["example.com".to_string()]
        );
    }

    #[test]
    fn country_uppercased_for_exa() {
        let provider = ExaSearchProvider::new(&config()).unwrap();
        let mut request = DiscoveryRequest::new("test");
        request.country = Some("us".into());

        let body = provider.build_body(&request);
        assert_eq!(body.location_hint.as_deref(), Some("US"));
    }

    #[test]
    fn parses_exa_response_with_summary() {
        let provider = ExaSearchProvider::new(&config()).unwrap();
        let request = DiscoveryRequest::new("apple inc");
        let response: ExaResponse = serde_json::from_str(
            r#"{
                "results": [
                    {
                        "title": "Apple",
                        "url": "https://www.apple.com/",
                        "summary": "Official Apple site",
                        "highlights": ["Apple designs consumer electronics"]
                    }
                ]
            }"#,
        )
        .unwrap();

        let result = provider.into_result(&request, response).unwrap();
        assert_eq!(result.total_discovered, 1);
        assert_eq!(result.urls[0].provider, DiscoveryProviderKind::Exa);
        assert_eq!(result.urls[0].domain, "www.apple.com");
        // Summary should be preferred over highlight.
        assert_eq!(result.urls[0].snippet.as_deref(), Some("Official Apple site"));
        assert_eq!(result.urls[0].rank, Some(1));
    }

    #[test]
    fn falls_back_to_highlight_when_no_summary() {
        let provider = ExaSearchProvider::new(&config()).unwrap();
        let request = DiscoveryRequest::new("test");
        let response: ExaResponse = serde_json::from_str(
            r#"{
                "results": [{
                    "url": "https://example.com/",
                    "highlights": ["First highlight"]
                }]
            }"#,
        )
        .unwrap();

        let result = provider.into_result(&request, response).unwrap();
        assert_eq!(result.urls[0].snippet.as_deref(), Some("First highlight"));
    }

    #[test]
    fn skips_malformed_url_in_response() {
        let provider = ExaSearchProvider::new(&config()).unwrap();
        let request = DiscoveryRequest::new("test");
        let response: ExaResponse = serde_json::from_str(
            r#"{"results": [{"url": "not a url"}, {"url": "https://good.example.com/"}]}"#,
        )
        .unwrap();

        let result = provider.into_result(&request, response).unwrap();
        assert_eq!(result.total_discovered, 1);
        assert_eq!(result.urls[0].domain, "good.example.com");
    }

    #[test]
    fn new_fails_if_key_is_empty() {
        let mut cfg = config();
        cfg.exa.api_key = String::new();
        assert!(ExaSearchProvider::new(&cfg).is_err());
    }

    #[test]
    fn new_fails_if_provider_disabled() {
        let mut cfg = config();
        cfg.exa.enabled = false;
        assert!(ExaSearchProvider::new(&cfg).is_err());
    }
}