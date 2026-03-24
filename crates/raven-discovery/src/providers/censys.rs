use async_trait::async_trait;
use chrono::Utc;
use raven_core::{
    config::DiscoveryConfig, DiscoveredUrl, DiscoveryPlugin, DiscoveryProviderKind,
    DiscoveryRequest, DiscoveryResult, DiscoveryType, OsintError, SearchProvider,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::normalize::{extract_domain, normalize_url};

/// Censys host/certificate search discovery provider.
///
/// Auth: HTTP Basic — App ID as username, Secret as password.
/// Set via:
///   RAVEN__DISCOVERY__CENSYS__API_KEY    = your App ID
///   RAVEN__DISCOVERY__CENSYS__API_SECRET = your Secret
///
/// Free tier: 250 queries/month on the v2 Search API.
/// Docs: <https://search.censys.io/api>
///
/// Capability notes:
/// - Host search (`/v2/hosts/search`) — finds internet-facing hosts matching
///   a query expression. Extracts IP + reverse DNS names, converted to URLs.
/// - This provider does NOT use premium intelligence endpoints. If the account
///   tier does not support a query, it logs a warning and returns an empty
///   result rather than erroring the entire pipeline.
pub struct CensysProvider {
    client:     Client,
    app_id:     String,
    secret:     String,
    base_url:   String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Censys wire types — /v2/hosts/search
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct CensysSearchRequest {
    q:                  String,
    per_page:           usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    virtual_hosts:      Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields:             Option<Vec<String>>,
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
    port:              Option<u16>,
    transport_protocol: Option<String>,
    service_name:      Option<String>,
    #[serde(default)]
    tls: Option<CensysTls>,
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
    subject_dn: Option<String>,
    names:      Option<Vec<String>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Implementation
// ─────────────────────────────────────────────────────────────────────────────

impl CensysProvider {
    pub fn new(config: &DiscoveryConfig) -> Result<Self, OsintError> {
        if !config.censys.enabled {
            return Err(OsintError::Discovery("censys provider is disabled".into()));
        }
        if config.censys.api_key.is_empty() {
            return Err(OsintError::Config(
                "censys api_key (App ID) is empty; set RAVEN__DISCOVERY__CENSYS__API_KEY".into(),
            ));
        }
        if config.censys.api_secret.is_empty() {
            return Err(OsintError::Config(
                "censys api_secret is empty; set RAVEN__DISCOVERY__CENSYS__API_SECRET".into(),
            ));
        }

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(OsintError::Http)?;

        Ok(Self {
            client,
            app_id:   config.censys.api_key.clone(),
            secret:   config.censys.api_secret.clone(),
            base_url: config.censys.base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Build a Censys query expression from the discovery request.
    ///
    /// If `site` is set, searches for hosts matching that domain in their
    /// DNS names or TLS certificates. Otherwise uses the raw query.
    fn build_query(&self, request: &DiscoveryRequest) -> String {
        match &request.site {
            Some(site) => {
                // Match hosts that have this domain in DNS name or TLS cert CN/SAN.
                format!(
                    "dns.reverse_dns.reverse_dns: \"{site}\" or \
                     services.tls.certificates.leaf_data.names: \"{site}\""
                )
            }
            None => request.query.trim().to_string(),
        }
    }

    /// Convert a Censys hit into zero or more `DiscoveredUrl` records.
    ///
    /// A single host can expose multiple services (HTTP on 80, HTTPS on 443,
    /// etc.) so we emit one URL per web-capable service.
    fn hit_to_urls(
        &self,
        hit: &CensysHit,
        request: &DiscoveryRequest,
        rank: u32,
    ) -> Vec<DiscoveredUrl> {
        let mut urls = Vec::new();

        // Collect hostnames: prefer reverse DNS names, fall back to raw IP.
        let mut hostnames: Vec<String> = hit.name.clone();
        if hostnames.is_empty() {
            // Try TLS cert names.
            for svc in &hit.services {
                if let Some(names) = svc
                    .tls
                    .as_ref()
                    .and_then(|t| t.certificates.as_ref())
                    .and_then(|c| c.leaf_data.as_ref())
                    .and_then(|l| l.names.as_ref())
                {
                    hostnames.extend(names.clone());
                }
            }
        }
        if hostnames.is_empty() {
            hostnames.push(hit.ip.clone());
        }

        for svc in &hit.services {
            let port = svc.port.unwrap_or(0);
            let scheme = match (
                svc.service_name.as_deref(),
                svc.tls.is_some(),
                port,
            ) {
                (_, true, _)       => "https",
                (_, _, 443)        => "https",
                (_, _, 80)         => "http",
                (Some("HTTP"), ..) => "http",
                _ => continue, // not a web service, skip
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

                let snippet = Some(format!(
                    "Censys host {} — port {}/{} labels: {}",
                    hit.ip,
                    port,
                    svc.transport_protocol.as_deref().unwrap_or("tcp"),
                    hit.labels.join(", ")
                ));

                urls.push(DiscoveredUrl {
                    domain: extract_domain(&normalized).unwrap_or_default(),
                    url:    normalized,
                    title:  None,
                    snippet,
                    provider:       DiscoveryProviderKind::Censys,
                    discovery_type: if request.site.is_some() {
                        DiscoveryType::CensysAsset
                    } else {
                        DiscoveryType::CensysAsset
                    },
                    source_query: request.query.clone(),
                    source_url:   None,
                    rank:         Some(rank),
                    confidence:   0.75,
                    discovered_at: Utc::now(),
                });
            }
        }

        urls
    }

    /// Execute the Censys host search. Returns degraded empty result on
    /// 403/402 (tier-restricted) rather than propagating an error.
    async fn do_search(&self, request: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        let body = CensysSearchRequest {
            q:             self.build_query(request),
            per_page:      request.limit.min(100),
            virtual_hosts: Some("INCLUDE".into()),
            fields:        Some(vec![
                "ip".into(),
                "name".into(),
                "services.port".into(),
                "services.transport_protocol".into(),
                "services.service_name".into(),
                "services.tls.certificates.leaf_data.names".into(),
                "labels".into(),
            ]),
        };

        let url = format!("{}/hosts/search", self.base_url);

        let response = self
            .client
            .get(&url)
            .basic_auth(&self.app_id, Some(&self.secret))
            .query(&[("q", &body.q), ("per_page", &body.per_page.to_string())])
            .send()
            .await
            .map_err(OsintError::Http)?;

        let status = response.status();

        // Graceful degradation for tier-restricted or quota-exceeded responses.
        if status == 403 || status == 402 || status == 429 {
            tracing::warn!(
                status = %status,
                "censys: account tier does not support this query or quota exceeded; \
                 returning empty result"
            );
            return Ok(DiscoveryResult {
                job_id:           request.job_id,
                request:          request.clone(),
                urls:             vec![],
                total_discovered: 0,
                completed_at:     Utc::now(),
            });
        }

        let parsed = response
            .error_for_status()
            .map_err(OsintError::Http)?
            .json::<CensysSearchResponse>()
            .await
            .map_err(OsintError::Http)?;

        let hits = parsed.result.map(|r| r.hits).unwrap_or_default();
        let mut urls: Vec<DiscoveredUrl> = Vec::new();

        for (i, hit) in hits.iter().enumerate() {
            let new_urls = self.hit_to_urls(hit, request, (i + 1) as u32);
            urls.extend(new_urls);
            if urls.len() >= request.limit {
                break;
            }
        }

        urls.truncate(request.limit);

        Ok(DiscoveryResult {
            job_id: request.job_id,
            request: request.clone(),
            total_discovered: urls.len(),
            urls,
            completed_at: Utc::now(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Trait implementations
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl SearchProvider for CensysProvider {
    fn name(&self) -> &str { "censys" }

    async fn search(&self, request: &DiscoveryRequest) -> Result<Vec<DiscoveredUrl>, OsintError> {
        self.do_search(request).await.map(|r| r.urls)
    }
}

#[async_trait]
impl DiscoveryPlugin for CensysProvider {
    fn name(&self) -> &str { "censys" }

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
            censys: DiscoveryProviderConfig {
                enabled:    true,
                base_url:   "https://api.censys.io/v2".into(),
                api_key:    "test-app-id".into(),
                api_secret: "test-secret".into(),
            },
            ..DiscoveryConfig::default()
        }
    }

    #[test]
    fn builds_domain_scoped_query() {
        let p = CensysProvider::new(&config()).unwrap();
        let mut req = DiscoveryRequest::new("ignored");
        req.site = Some("example.com".into());
        let q = p.build_query(&req);
        assert!(q.contains("example.com"));
    }

    #[test]
    fn builds_raw_query_without_site() {
        let p = CensysProvider::new(&config()).unwrap();
        let req = DiscoveryRequest::new("services.port: 8443");
        assert_eq!(p.build_query(&req), "services.port: 8443");
    }

    #[test]
    fn new_fails_without_secret() {
        let mut cfg = config();
        cfg.censys.api_secret = String::new();
        assert!(CensysProvider::new(&cfg).is_err());
    }

    #[test]
    fn hit_with_http_service_produces_url() {
        let p = CensysProvider::new(&config()).unwrap();
        let req = DiscoveryRequest::new("test");
        let hit = CensysHit {
            ip: "1.2.3.4".into(),
            name: vec!["example.com".into()],
            services: vec![CensysService {
                port: Some(80),
                transport_protocol: Some("TCP".into()),
                service_name: Some("HTTP".into()),
                tls: None,
            }],
            labels: vec![],
        };
        let urls = p.hit_to_urls(&hit, &req, 1);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "http://example.com/");
        assert_eq!(urls[0].provider, DiscoveryProviderKind::Censys);
    }

    #[test]
    fn hit_with_non_web_service_is_skipped() {
        let p = CensysProvider::new(&config()).unwrap();
        let req = DiscoveryRequest::new("test");
        let hit = CensysHit {
            ip: "1.2.3.4".into(),
            name: vec!["example.com".into()],
            services: vec![CensysService {
                port: Some(22),
                transport_protocol: Some("TCP".into()),
                service_name: Some("SSH".into()),
                tls: None,
            }],
            labels: vec![],
        };
        let urls = p.hit_to_urls(&hit, &req, 1);
        assert!(urls.is_empty());
    }
}
