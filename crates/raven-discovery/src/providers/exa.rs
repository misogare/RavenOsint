use async_trait::async_trait;
use chrono::Utc;
use raven_core::{
    config::DiscoveryConfig, DiscoveredUrl, DiscoveryPlugin, DiscoveryProviderKind,
    DiscoveryRequest, DiscoveryResult, DiscoveryType, OsintError, SearchProvider,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::normalize::{extract_domain, normalize_url};

/// Exa-backed search discovery.
pub struct ExaSearchProvider {
    client: Client,
    api_key: String,
    base_url: String,
}

#[derive(Debug, Serialize)]
struct ExaRequestBody {
    query: String,
    #[serde(rename = "type")]
    search_type: String,
    #[serde(rename = "numResults")]
    num_results: usize,
    #[serde(skip_serializing_if = "Option::is_none", rename = "userLocation")]
    user_location: Option<String>,
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
    summary: Option<String>,
    text: Option<String>,
    #[serde(default)]
    highlights: Vec<String>,
}

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

    fn build_body(&self, request: &DiscoveryRequest) -> ExaRequestBody {
        ExaRequestBody {
            query: request.query.trim().to_string(),
            search_type: "auto".into(),
            num_results: request.limit,
            user_location: request.country.clone().map(|value| value.to_uppercase()),
            include_domains: request.site.clone().map(|site| vec![site]),
        }
    }

    fn into_result(&self, request: &DiscoveryRequest, response: ExaResponse) -> Result<DiscoveryResult, OsintError> {
        let mut urls = Vec::new();

        for (index, item) in response.results.into_iter().enumerate() {
            let normalized = normalize_url(&item.url)?;
            let snippet = item
                .summary
                .or_else(|| item.highlights.first().cloned())
                .or(item.text.map(|text| text.chars().take(240).collect()));

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
}

#[async_trait]
impl SearchProvider for ExaSearchProvider {
    fn name(&self) -> &str {
        "exa"
    }

    async fn search(&self, request: &DiscoveryRequest) -> Result<Vec<DiscoveredUrl>, OsintError> {
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

        self.into_result(request, response).map(|result| result.urls)
    }
}

#[async_trait]
impl DiscoveryPlugin for ExaSearchProvider {
    fn name(&self) -> &str {
        "exa"
    }

    async fn discover(&self, request: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
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
    fn builds_domain_scoped_body() {
        let provider = ExaSearchProvider::new(&config()).unwrap();
        let mut request = DiscoveryRequest::new("phishing kits");
        request.site = Some("example.com".into());
        request.limit = 15;

        let body = provider.build_body(&request);
        assert_eq!(body.num_results, 15);
        assert_eq!(body.include_domains.as_ref().unwrap(), &vec!["example.com".to_string()]);
    }

    #[test]
    fn parses_exa_response() {
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
    }
}
