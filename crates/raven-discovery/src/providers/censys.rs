use async_trait::async_trait;
use chrono::Utc;
use raven_core::{
    config::DiscoveryConfig, DiscoveredUrl, DiscoveryPlugin, DiscoveryProviderKind,
    DiscoveryRequest, DiscoveryResult, DiscoveryType, OsintError, SearchProvider,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::normalize::{extract_domain, normalize_url};

/// Censys host search — uses Bearer PAT (Personal Access Token).
/// Get yours at: https://search.censys.io/account/api
/// Set via: RAVEN__DISCOVERY__CENSYS__API_KEY
pub struct CensysProvider {
    client:   Client,
    token:    String,
    base_url: String,
}

#[derive(Debug, Serialize)]
struct CensysSearchRequest {
    q:        String,
    per_page: usize,
}

#[derive(Debug, Deserialize)]
struct CensysSearchResponse {
    result: Option<CensysResult>,
}

#[derive(Debug, Deserialize)]
struct CensysResult {
    #[serde(default)]
    hits: Vec<CensysHit>,
}

#[derive(Debug, Deserialize)]
struct CensysHit {
    ip: String,
    #[serde(default)]
    name: Vec<String>,
    #[serde(default)]
    services: Vec<CensysService>,
    #[serde(default)]
    labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CensysService {
    port:               Option<u16>,
    transport_protocol: Option<String>,
    service_name:       Option<String>,
    tls:                Option<CensysTls>,
}

#[derive(Debug, Deserialize)]
struct CensysTls {
    certificates: Option<CensysCerts>,
}

#[derive(Debug, Deserialize)]
struct CensysCerts {
    leaf_data: Option<CensysLeaf>,
}

#[derive(Debug, Deserialize)]
struct CensysLeaf {
    #[serde(default)]
    names: Vec<String>,
}

impl CensysProvider {
    pub fn new(config: &DiscoveryConfig) -> Result<Self, OsintError> {
        if !config.censys.enabled {
            return Err(OsintError::Discovery("censys provider is disabled".into()));
        }
        if config.censys.api_key.is_empty() {
            return Err(OsintError::Config(
                "censys api_key is empty; set RAVEN__DISCOVERY__CENSYS__API_KEY to your PAT from https://search.censys.io/account/api".into(),
            ));
        }
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(OsintError::Http)?;
        Ok(Self {
            client,
            token:    config.censys.api_key.clone(),
            base_url: config.censys.base_url.trim_end_matches('/').to_string(),
        })
    }

    fn build_query(&self, request: &DiscoveryRequest) -> String {
        match &request.site {
            Some(site) => format!(
                "dns.reverse_dns.reverse_dns: \"{site}\" or services.tls.certificates.leaf_data.names: \"{site}\""
            ),
            None => request.query.trim().to_string(),
        }
    }

    fn hit_to_urls(&self, hit: &CensysHit, request: &DiscoveryRequest, rank: u32) -> Vec<DiscoveredUrl> {
        let mut urls = Vec::new();
        let mut hostnames: Vec<String> = hit.name.clone();
        if hostnames.is_empty() {
            for svc in &hit.services {
                if let Some(names) = svc.tls.as_ref()
                    .and_then(|t| t.certificates.as_ref())
                    .and_then(|c| c.leaf_data.as_ref())
                    .map(|l| &l.names)
                {
                    hostnames.extend(names.clone());
                }
            }
        }
        if hostnames.is_empty() { hostnames.push(hit.ip.clone()); }

        for svc in &hit.services {
            let port = svc.port.unwrap_or(0);
            let scheme = match (svc.service_name.as_deref(), svc.tls.is_some(), port) {
                (_, true, _)       => "https",
                (_, _, 443)        => "https",
                (_, _, 80)         => "http",
                (Some("HTTP"), ..) => "http",
                _                  => continue,
            };
            for host in &hostnames {
                let raw = if (scheme == "http" && port != 80 && port != 0)
                    || (scheme == "https" && port != 443 && port != 0)
                { format!("{scheme}://{host}:{port}/") } else { format!("{scheme}://{host}/") };

                let normalized = match normalize_url(&raw) { Ok(u) => u, Err(_) => continue };
                let snippet = Some(format!(
                    "Censys: {} — port {}/{} | labels: {}",
                    hit.ip, port,
                    svc.transport_protocol.as_deref().unwrap_or("tcp"),
                    if hit.labels.is_empty() { "none".into() } else { hit.labels.join(", ") }
                ));
                urls.push(DiscoveredUrl {
                    domain: extract_domain(&normalized).unwrap_or_default(),
                    url: normalized, title: None, snippet,
                    provider:       DiscoveryProviderKind::Censys,
                    discovery_type: DiscoveryType::CensysAsset,
                    source_query:   request.query.clone(),
                    source_url:     None, rank: Some(rank), confidence: 0.75,
                    discovered_at:  Utc::now(),
                });
            }
        }
        urls
    }

    async fn do_search(&self, request: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        let query    = self.build_query(request);
        let endpoint = format!("{}/hosts/search", self.base_url);

        let response = self.client.get(&endpoint)
            .bearer_auth(&self.token)
            .query(&[("q", &query), ("per_page", &request.limit.min(100).to_string())])
            .send().await.map_err(OsintError::Http)?;

        let status = response.status();
        if matches!(status.as_u16(), 401 | 403 | 402 | 429) {
            tracing::warn!(%status, "censys: non-success — check PAT or tier; returning empty");
            return Ok(empty_result(request));
        }

        let parsed = response.error_for_status().map_err(OsintError::Http)?
            .json::<CensysSearchResponse>().await.map_err(OsintError::Http)?;

        let hits = parsed.result.map(|r| r.hits).unwrap_or_default();
        let mut urls: Vec<DiscoveredUrl> = Vec::new();
        for (i, hit) in hits.iter().enumerate() {
            for u in self.hit_to_urls(hit, request, (i + 1) as u32) {
                urls.push(u);
                if urls.len() >= request.limit { break; }
            }
            if urls.len() >= request.limit { break; }
        }

        Ok(DiscoveryResult {
            job_id: request.job_id, request: request.clone(),
            total_discovered: urls.len(), urls, completed_at: Utc::now(),
        })
    }
}

fn empty_result(r: &DiscoveryRequest) -> DiscoveryResult {
    DiscoveryResult { job_id: r.job_id, request: r.clone(), urls: vec![], total_discovered: 0, completed_at: Utc::now() }
}

#[async_trait]
impl SearchProvider for CensysProvider {
    fn name(&self) -> &str { "censys" }
    async fn search(&self, req: &DiscoveryRequest) -> Result<Vec<DiscoveredUrl>, OsintError> {
        self.do_search(req).await.map(|r| r.urls)
    }
}

#[async_trait]
impl DiscoveryPlugin for CensysProvider {
    fn name(&self) -> &str { "censys" }
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
                enabled: true, base_url: "https://api.censys.io/v2".into(),
                api_key: "test-pat".into(), api_secret: String::new(),
            },
            ..DiscoveryConfig::default()
        }
    }

    #[test] fn domain_query_contains_site() {
        let p = CensysProvider::new(&config()).unwrap();
        let mut req = DiscoveryRequest::new("x"); req.site = Some("example.com".into());
        assert!(p.build_query(&req).contains("example.com"));
    }
    #[test] fn raw_query_passthrough() {
        let p = CensysProvider::new(&config()).unwrap();
        assert_eq!(p.build_query(&DiscoveryRequest::new("services.port: 443")), "services.port: 443");
    }
    #[test] fn fails_without_key() {
        let mut c = config(); c.censys.api_key = String::new();
        assert!(CensysProvider::new(&c).is_err());
    }
    #[test] fn http_hit_produces_url() {
        let p = CensysProvider::new(&config()).unwrap();
        let hit = CensysHit { ip: "1.2.3.4".into(), name: vec!["ex.com".into()],
            services: vec![CensysService { port: Some(80), transport_protocol: Some("TCP".into()),
                service_name: Some("HTTP".into()), tls: None }], labels: vec![] };
        let urls = p.hit_to_urls(&hit, &DiscoveryRequest::new("t"), 1);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "http://ex.com/");
    }
    #[test] fn ssh_hit_skipped() {
        let p = CensysProvider::new(&config()).unwrap();
        let hit = CensysHit { ip: "1.2.3.4".into(), name: vec!["ex.com".into()],
            services: vec![CensysService { port: Some(22), transport_protocol: Some("TCP".into()),
                service_name: Some("SSH".into()), tls: None }], labels: vec![] };
        assert!(p.hit_to_urls(&hit, &DiscoveryRequest::new("t"), 1).is_empty());
    }
}