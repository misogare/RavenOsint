use async_trait::async_trait;
use chrono::Utc;
use raven_core::{
    config::DiscoveryConfig, DiscoveredUrl, DiscoveryPlugin, DiscoveryProviderKind,
    DiscoveryRequest, DiscoveryResult, DiscoveryType, OsintError, SearchProvider,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::normalize::{extract_domain, normalize_url};

/// Serper-backed Google-style search discovery.
pub struct SerperSearchProvider {
    client: Client,
    api_key: String,
    base_url: String,
}

#[derive(Debug, Serialize)]
struct SerperRequestBody {
    q: String,
    num: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    gl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hl: Option<String>,
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

    fn build_query(&self, request: &DiscoveryRequest) -> String {
        match &request.site {
            Some(site) => format!("{} site:{}", request.query.trim(), site.trim()),
            None => request.query.trim().to_string(),
        }
    }

    fn build_body(&self, request: &DiscoveryRequest) -> SerperRequestBody {
        SerperRequestBody {
            q: self.build_query(request),
            num: request.limit,
            gl: request.country.clone().map(|value| value.to_lowercase()),
            hl: request.lang.clone().map(|value| value.to_lowercase()),
        }
    }

    fn into_result(&self, request: &DiscoveryRequest, response: SerperResponse) -> Result<DiscoveryResult, OsintError> {
        let mut urls = Vec::new();

        for organic in response.organic {
            let normalized = normalize_url(&organic.link)?;
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
}

#[async_trait]
impl SearchProvider for SerperSearchProvider {
    fn name(&self) -> &str {
        "serper"
    }

    async fn search(&self, request: &DiscoveryRequest) -> Result<Vec<DiscoveredUrl>, OsintError> {
        let body = self.build_body(request);
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

        self.into_result(request, response).map(|result| result.urls)
    }
}

#[async_trait]
impl DiscoveryPlugin for SerperSearchProvider {
    fn name(&self) -> &str {
        "serper"
    }

    async fn discover(&self, request: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        let body = self.build_body(request);
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
            },
            ..DiscoveryConfig::default()
        }
    }

    #[test]
    fn builds_site_scoped_query() {
        let provider = SerperSearchProvider::new(&config()).unwrap();
        let mut request = DiscoveryRequest::new("phishing indicators");
        request.site = Some("example.com".into());
        assert_eq!(provider.build_query(&request), "phishing indicators site:example.com");
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
    }
}
