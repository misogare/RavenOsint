use async_trait::async_trait;
use chrono::Utc;
use raven_core::{
    config::DiscoveryConfig, DiscoveredUrl, DiscoveryPlugin, DiscoveryProviderKind,
    DiscoveryRequest, DiscoveryResult, DiscoveryType, OsintError, SearchProvider,
};
use reqwest::Client;
use serde::Deserialize;

use crate::normalize::{extract_domain, normalize_url};

/// Censys Global Search v3 provider.
///
/// Uses: POST /v3/global/search (as documented at docs.censys.com/reference/v3-globaldata-search-aggregate)
/// Auth: Bearer Personal Access Token
/// Set via: RAVEN__DISCOVERY__CENSYS__API_KEY
/// Get your PAT at: https://search.censys.io/account/api
///
/// Note: No org ID required for personal accounts. Free tier = 250 queries/month.
pub struct CensysProvider {
    client: Client,
    api_key: String,
    api_secret: String,
    base_url: String,
    organization_id: Option<String>,
}

// ─── wire types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CensysV3Response {
    result: Option<CensysV3Result>,
}

#[derive(Debug, Deserialize)]
struct CensysV3Result {
    #[serde(default)]
    hits: Vec<CensysV3Hit>,
}

#[derive(Debug, Deserialize)]
struct CensysV3Hit {
    ip: Option<String>,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    services: Vec<CensysV3Service>,
    #[serde(default)]
    labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CensysV3Service {
    port: Option<u16>,
    service_name: Option<String>,
    tls: Option<CensysV3Tls>,
}

#[derive(Debug, Deserialize)]
struct CensysV3Tls {
    certificates: Option<CensysV3Certs>,
}

#[derive(Debug, Deserialize)]
struct CensysV3Certs {
    leaf_data: Option<CensysV3Leaf>,
}

#[derive(Debug, Deserialize)]
struct CensysV3Leaf {
    #[serde(default)]
    names: Vec<String>,
}

// ─── impl ─────────────────────────────────────────────────────────────────────

impl CensysProvider {
    pub fn new(config: &DiscoveryConfig) -> Result<Self, OsintError> {
        if config.censys.api_key.is_empty() {
            return Err(OsintError::Config(
                "censys api_key is empty; set RAVEN__DISCOVERY__CENSYS__API_KEY".into(),
            ));
        }
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(OsintError::Http)?;

        let base_url = config.censys.base_url.trim_end_matches('/').to_string();
        let organization_id = std::env::var("RAVEN__DISCOVERY__CENSYS__ORGANIZATION_ID")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        Ok(Self {
            client,
            api_key: config.censys.api_key.clone(),
            api_secret: config.censys.api_secret.clone(),
            base_url,
            organization_id,
        })
    }

    fn is_v3_platform(&self) -> bool {
        self.base_url.contains("api.platform.censys.io") || self.base_url.contains("/v3")
    }

    fn has_v2_secret(&self) -> bool {
        !self.api_secret.is_empty()
    }

    fn build_query(&self, request: &DiscoveryRequest) -> String {
        match &request.site {
            Some(site) => format!(
                "dns.reverse_dns.reverse_dns: \"{site}\" or \
                 services.tls.certificates.leaf_data.names: \"{site}\""
            ),
            None => request.query.trim().to_string(),
        }
    }

    fn hit_to_urls(
        &self,
        hit: &CensysV3Hit,
        request: &DiscoveryRequest,
        rank: u32,
    ) -> Vec<DiscoveredUrl> {
        let ip = hit.ip.as_deref().unwrap_or("unknown");
        let mut hostnames = hit.names.clone();

        if hostnames.is_empty() {
            for svc in &hit.services {
                if let Some(names) = svc
                    .tls
                    .as_ref()
                    .and_then(|t| t.certificates.as_ref())
                    .and_then(|c| c.leaf_data.as_ref())
                    .map(|l| &l.names)
                {
                    hostnames.extend(names.clone());
                }
            }
        }
        if hostnames.is_empty() {
            if let Some(ip_str) = &hit.ip {
                hostnames.push(ip_str.clone());
            }
        }

        let mut urls = Vec::new();
        for svc in &hit.services {
            let port = svc.port.unwrap_or(0);
            let scheme = match (svc.service_name.as_deref(), svc.tls.is_some(), port) {
                (_, true, _) => "https",
                (_, _, 443) => "https",
                (_, _, 80) => "http",
                (Some("HTTP"), ..) => "http",
                _ => continue,
            };

            for host in &hostnames {
                let raw = if (scheme == "http" && port != 80 && port != 0)
                    || (scheme == "https" && port != 443 && port != 0)
                {
                    format!("{scheme}://{host}:{port}/")
                } else {
                    format!("{scheme}://{host}/")
                };

                let normalized = match normalize_url(&raw) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                urls.push(DiscoveredUrl {
                    domain: extract_domain(&normalized).unwrap_or_default(),
                    url: normalized,
                    title: None,
                    snippet: Some(format!(
                        "Censys: {} — port {} | labels: {}",
                        ip,
                        port,
                        if hit.labels.is_empty() {
                            "none".into()
                        } else {
                            hit.labels.join(", ")
                        }
                    )),
                    provider: DiscoveryProviderKind::Censys,
                    discovery_type: DiscoveryType::CensysAsset,
                    source_query: request.query.clone(),
                    source_url: None,
                    rank: Some(rank),
                    confidence: 0.75,
                    discovered_at: Utc::now(),
                });
            }
        }
        urls
    }

    async fn do_search(&self, request: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        let query = self.build_query(request);
        let per_page = request.limit.min(100);

        let response = if self.is_v3_platform() {
            self.search_v3(&query, per_page).await?
        } else {
            self.search_v2(&query, per_page).await?
        };

        let status = response.status();
        let response_text = response.text().await.unwrap_or_default();
        tracing::debug!(%status, "censys: got response");

        match status.as_u16() {
            401 | 403 => {
                tracing::warn!(
                    %status,
                    body = %truncate_body(&response_text),
                    "censys: auth or permission failure — verify API Access role and PAT scope in Censys Platform"
                );
                return Ok(empty_result(request));
            }
            429 => {
                tracing::warn!(
                    body = %truncate_body(&response_text),
                    "censys: rate limit hit"
                );
                return Ok(empty_result(request));
            }
            402 => {
                tracing::warn!(
                    body = %truncate_body(&response_text),
                    "censys: query requires a paid tier"
                );
                return Ok(empty_result(request));
            }
            _ => {}
        }

        let parsed = serde_json::from_str::<CensysV3Response>(&response_text)
            .map_err(|e| OsintError::Discovery(format!("censys response parse failed: {e}")))?;

        let hits = parsed.result.map(|r| r.hits).unwrap_or_default();
        let mut urls: Vec<DiscoveredUrl> = Vec::new();
        for (i, hit) in hits.iter().enumerate() {
            for u in self.hit_to_urls(hit, request, (i + 1) as u32) {
                urls.push(u);
                if urls.len() >= request.limit {
                    break;
                }
            }
            if urls.len() >= request.limit {
                break;
            }
        }

        Ok(DiscoveryResult {
            job_id: request.job_id,
            request: request.clone(),
            total_discovered: urls.len(),
            urls,
            completed_at: Utc::now(),
        })
    }

    async fn search_v2(
        &self,
        query: &str,
        per_page: usize,
    ) -> Result<reqwest::Response, OsintError> {
        let endpoint = format!("{}/hosts/search", self.base_url);
        tracing::debug!(endpoint = %endpoint, query = %query, "censys: sending v2 request");

        let mut req = self
            .client
            .get(&endpoint)
            .query(&[("q", query), ("per_page", &per_page.to_string())]);

        if self.has_v2_secret() {
            // Legacy v2 credentials: App ID + Secret.
            req = req.basic_auth(&self.api_key, Some(&self.api_secret));
        } else {
            // PAT flow for accounts issuing bearer tokens.
            req = req
                .bearer_auth(&self.api_key)
                .header("x-auth-token", &self.api_key);
        }

        req.send().await.map_err(OsintError::Http)
    }

    async fn search_v3(
        &self,
        query: &str,
        per_page: usize,
    ) -> Result<reqwest::Response, OsintError> {
        let endpoint = format!("{}/global/search/query", self.base_url);
        tracing::debug!(endpoint = %endpoint, query = %query, "censys: sending v3 request");

        // v3 Platform API expects bearer auth.
        let body = serde_json::json!({
            "query": query,
            "page_size": per_page,
        });

        let mut req = self
            .client
            .post(&endpoint)
            .bearer_auth(&self.api_key)
            .header("x-auth-token", &self.api_key)
            .header("x-api-key", &self.api_key)
            .header("accept", "application/json")
            .json(&body);

        if let Some(org_id) = &self.organization_id {
            req = req
                .query(&[("organization_id", org_id)])
                .header("x-organization-id", org_id);
        }

        req.send().await.map_err(OsintError::Http)
    }
}

fn truncate_body(input: &str) -> String {
    const MAX: usize = 400;
    let body = input.trim();
    if body.len() <= MAX {
        return body.to_string();
    }
    format!("{}...", &body[..MAX])
}

fn empty_result(r: &DiscoveryRequest) -> DiscoveryResult {
    DiscoveryResult {
        job_id: r.job_id,
        request: r.clone(),
        urls: vec![],
        total_discovered: 0,
        completed_at: Utc::now(),
    }
}

#[async_trait]
impl SearchProvider for CensysProvider {
    fn name(&self) -> &str {
        "censys"
    }
    async fn search(&self, req: &DiscoveryRequest) -> Result<Vec<DiscoveredUrl>, OsintError> {
        self.do_search(req).await.map(|r| r.urls)
    }
}

#[async_trait]
impl DiscoveryPlugin for CensysProvider {
    fn name(&self) -> &str {
        "censys"
    }
    async fn discover(&self, req: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        self.do_search(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::config::{DiscoveryConfig, DiscoveryProviderConfig};

    fn config() -> DiscoveryConfig {
        DiscoveryConfig {
            censys: DiscoveryProviderConfig {
                enabled: true,
                base_url: "https://search.censys.io/api/v2".into(),
                api_key: "test-pat".into(),
                api_secret: String::new(),
            },
            ..DiscoveryConfig::default()
        }
    }

    #[test]
    fn detects_v3_platform_mode() {
        let mut c = config();
        c.censys.base_url = "https://api.platform.censys.io/v3".into();
        let p = CensysProvider::new(&c).unwrap();
        assert!(p.is_v3_platform());
    }

    #[test]
    fn detects_v2_secret_mode() {
        let mut c = config();
        c.censys.api_secret = "secret".into();
        let p = CensysProvider::new(&c).unwrap();
        assert!(p.has_v2_secret());
    }

    #[test]
    fn domain_query_contains_site() {
        let p = CensysProvider::new(&config()).unwrap();
        let mut req = DiscoveryRequest::new("x");
        req.site = Some("example.com".into());
        assert!(p.build_query(&req).contains("example.com"));
    }
    #[test]
    fn raw_query_passthrough() {
        let p = CensysProvider::new(&config()).unwrap();
        assert_eq!(
            p.build_query(&DiscoveryRequest::new("services.port: 443")),
            "services.port: 443"
        );
    }
    #[test]
    fn fails_without_key() {
        let mut c = config();
        c.censys.api_key = String::new();
        assert!(CensysProvider::new(&c).is_err());
    }
    #[test]
    fn http_hit_produces_url() {
        let p = CensysProvider::new(&config()).unwrap();
        let hit = CensysV3Hit {
            ip: Some("1.2.3.4".into()),
            names: vec!["ex.com".into()],
            services: vec![CensysV3Service {
                port: Some(80),
                service_name: Some("HTTP".into()),
                tls: None,
            }],
            labels: vec![],
        };
        let urls = p.hit_to_urls(&hit, &DiscoveryRequest::new("t"), 1);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "http://ex.com/");
    }
}
