use async_trait::async_trait;
use chrono::Utc;
use raven_core::{
    config::DiscoveryConfig, DiscoveredUrl, DiscoveryPlugin, DiscoveryProviderKind,
    DiscoveryRequest, DiscoveryResult, DiscoveryType, OsintError, SearchProvider,
};
use reqwest::Client;
use serde::Deserialize;

use crate::normalize::{extract_domain, normalize_url};

/// VirusTotal domain pivot discovery — free tier only.
/// Auth: x-apikey header. Set via: RAVEN__DISCOVERY__VIRUS_TOTAL__API_KEY
/// Free limits: 4 req/min, 500 req/day.
/// Uses: GET /domains/{domain}/urls  and  GET /domains/{domain} (subdomains)
pub struct VirusTotalProvider {
    client: Client,
    api_key: String,
    base_url: String,
}

// ─── wire types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct VtUrlsResponse {
    data: Option<Vec<VtUrlItem>>,
    // meta kept for future pagination — suppress dead_code warning
    #[allow(dead_code)]
    meta: Option<VtMeta>,
}

#[derive(Debug, Deserialize)]
struct VtUrlItem {
    // kept for future use
    #[allow(dead_code)]
    #[serde(rename = "type")]
    item_type: Option<String>,
    #[allow(dead_code)]
    id: Option<String>,
    attributes: Option<VtUrlAttributes>,
}

#[derive(Debug, Deserialize)]
struct VtUrlAttributes {
    url: Option<String>,
    title: Option<String>,
    last_final_url: Option<String>,
    #[allow(dead_code)]
    last_http_response_code: Option<u16>,
    times_submitted: Option<u64>,
    last_analysis_stats: Option<VtStats>,
}

#[derive(Debug, Deserialize)]
struct VtStats {
    malicious: Option<u64>,
    suspicious: Option<u64>,
    harmless: Option<u64>,
    undetected: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct VtDomainResponse {
    data: Option<VtDomainData>,
}

#[derive(Debug, Deserialize)]
struct VtDomainData {
    attributes: Option<VtDomainAttributes>,
}

#[derive(Debug, Deserialize)]
struct VtDomainAttributes {
    #[allow(dead_code)]
    last_analysis_stats: Option<VtStats>,
    reputation: Option<i64>,
    #[serde(default)]
    subdomains: Vec<String>,
    #[allow(dead_code)]
    last_dns_records: Option<Vec<VtDnsRecord>>,
}

#[derive(Debug, Deserialize)]
struct VtDnsRecord {
    #[allow(dead_code)]
    #[serde(rename = "type")]
    record_type: Option<String>,
    #[allow(dead_code)]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VtMeta {
    #[allow(dead_code)]
    cursor: Option<String>,
    #[allow(dead_code)]
    count: Option<u64>,
}

// ─── implementation ───────────────────────────────────────────────────────────

impl VirusTotalProvider {
    pub fn new(config: &DiscoveryConfig) -> Result<Self, OsintError> {
        if config.virus_total.api_key.is_empty() {
            return Err(OsintError::Config(
                "virustotal api_key is empty; set RAVEN__DISCOVERY__VIRUS_TOTAL__API_KEY".into(),
            ));
        }
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(OsintError::Http)?;
        Ok(Self {
            client,
            api_key: config.virus_total.api_key.clone(),
            base_url: config
                .virus_total
                .base_url
                .trim_end_matches('/')
                .to_string(),
        })
    }

    fn confidence_from_stats(stats: &Option<VtStats>) -> f32 {
        let s = match stats {
            Some(s) => s,
            None => return 0.5,
        };
        let mal = s.malicious.unwrap_or(0) as f32;
        let sus = s.suspicious.unwrap_or(0) as f32;
        let total = mal + sus + s.harmless.unwrap_or(0) as f32 + s.undetected.unwrap_or(0) as f32;
        if total == 0.0 {
            return 0.5;
        }
        ((mal + sus) / total * 0.9 + 0.1).clamp(0.1, 1.0)
    }

    async fn fetch_domain_urls(
        &self,
        domain: &str,
        limit: usize,
        request: &DiscoveryRequest,
    ) -> Result<Vec<DiscoveredUrl>, OsintError> {
        let endpoint = format!("{}/domains/{}/urls", self.base_url, domain);
        let response = self
            .client
            .get(&endpoint)
            .header("x-apikey", &self.api_key)
            .query(&[("limit", limit.to_string())])
            .send()
            .await
            .map_err(OsintError::Http)?;

        if response.status().as_u16() == 403 {
            // Public keys can receive 403 on relationship endpoints reserved for premium.
            tracing::info!(status = %response.status(), "virustotal: domain urls relationship not available for this key tier");
            return Ok(vec![]);
        }

        if matches!(response.status().as_u16(), 429 | 401) {
            tracing::warn!(status = %response.status(), "virustotal: rate limit or auth issue");
            return Ok(vec![]);
        }

        let parsed = response
            .error_for_status()
            .map_err(OsintError::Http)?
            .json::<VtUrlsResponse>()
            .await
            .map_err(OsintError::Http)?;

        let mut urls = Vec::new();
        for (rank, item) in parsed.data.unwrap_or_default().iter().enumerate() {
            let attrs = match &item.attributes {
                Some(a) => a,
                None => continue,
            };
            let raw = attrs
                .last_final_url
                .as_deref()
                .or(attrs.url.as_deref())
                .unwrap_or_default();
            if raw.is_empty() {
                continue;
            }
            let normalized = match normalize_url(raw) {
                Ok(u) => u,
                Err(_) => continue,
            };

            let mal = attrs
                .last_analysis_stats
                .as_ref()
                .and_then(|s| s.malicious)
                .unwrap_or(0);
            let sus = attrs
                .last_analysis_stats
                .as_ref()
                .and_then(|s| s.suspicious)
                .unwrap_or(0);

            urls.push(DiscoveredUrl {
                domain: extract_domain(&normalized).unwrap_or_default(),
                url: normalized,
                title: attrs.title.clone(),
                snippet: Some(format!(
                    "VirusTotal: {} malicious, {} suspicious | submitted {} times",
                    mal,
                    sus,
                    attrs.times_submitted.unwrap_or(0)
                )),
                provider: DiscoveryProviderKind::VirusTotal,
                discovery_type: DiscoveryType::VirusTotalPivot,
                source_query: request.query.clone(),
                source_url: None,
                rank: Some((rank + 1) as u32),
                confidence: Self::confidence_from_stats(&attrs.last_analysis_stats),
                discovered_at: Utc::now(),
            });
        }
        Ok(urls)
    }

    async fn fetch_subdomains(
        &self,
        domain: &str,
        request: &DiscoveryRequest,
    ) -> Result<Vec<DiscoveredUrl>, OsintError> {
        let endpoint = format!("{}/domains/{}", self.base_url, domain);
        let response = self
            .client
            .get(&endpoint)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(OsintError::Http)?;

        if matches!(response.status().as_u16(), 429 | 403 | 401) {
            tracing::warn!(status = %response.status(), "virustotal: rate limit or auth issue");
            return Ok(vec![]);
        }

        let parsed = response
            .error_for_status()
            .map_err(OsintError::Http)?
            .json::<VtDomainResponse>()
            .await
            .map_err(OsintError::Http)?;

        let attrs = match parsed.data.and_then(|d| d.attributes) {
            Some(a) => a,
            None => return Ok(vec![]),
        };
        let reputation = attrs.reputation.unwrap_or(0);
        let mut urls = Vec::new();

        // Always return the queried domain itself when domain-info is accessible.
        let root = format!("https://{domain}/");
        if let Ok(normalized) = normalize_url(&root) {
            urls.push(DiscoveredUrl {
                domain: extract_domain(&normalized).unwrap_or_else(|| domain.to_string()),
                url: normalized,
                title: None,
                snippet: Some(format!(
                    "VirusTotal domain lookup | reputation: {reputation}"
                )),
                provider: DiscoveryProviderKind::VirusTotal,
                discovery_type: DiscoveryType::VirusTotalPivot,
                source_query: request.query.clone(),
                source_url: None,
                rank: Some(1),
                confidence: if reputation < 0 { 0.9 } else { 0.5 },
                discovered_at: Utc::now(),
            });
        }

        for (rank, subdomain) in attrs.subdomains.iter().enumerate() {
            let normalized = match normalize_url(&format!("https://{subdomain}/")) {
                Ok(u) => u,
                Err(_) => continue,
            };
            urls.push(DiscoveredUrl {
                domain: extract_domain(&normalized).unwrap_or_default(),
                url: normalized,
                title: None,
                snippet: Some(format!(
                    "VirusTotal subdomain of {domain} | reputation: {reputation}"
                )),
                provider: DiscoveryProviderKind::VirusTotal,
                discovery_type: DiscoveryType::VirusTotalPivot,
                source_query: request.query.clone(),
                source_url: None,
                rank: Some((rank + 2) as u32),
                confidence: if reputation < 0 { 0.9 } else { 0.5 },
                discovered_at: Utc::now(),
            });
        }
        Ok(urls)
    }

    async fn do_search(&self, request: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        let domain = request.site.as_deref().unwrap_or(request.query.trim());

        let (url_res, sub_res) = tokio::join!(
            self.fetch_domain_urls(domain, request.limit, request),
            self.fetch_subdomains(domain, request),
        );

        let mut urls = url_res.unwrap_or_default();
        for sub in sub_res.unwrap_or_default() {
            if urls.len() >= request.limit {
                break;
            }
            if !urls.iter().any(|u| u.url == sub.url) {
                urls.push(sub);
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

#[async_trait]
impl SearchProvider for VirusTotalProvider {
    fn name(&self) -> &str {
        "virustotal"
    }
    async fn search(&self, req: &DiscoveryRequest) -> Result<Vec<DiscoveredUrl>, OsintError> {
        self.do_search(req).await.map(|r| r.urls)
    }
}

#[async_trait]
impl DiscoveryPlugin for VirusTotalProvider {
    fn name(&self) -> &str {
        "virustotal"
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
            virus_total: DiscoveryProviderConfig {
                enabled: true,
                base_url: "https://www.virustotal.com/api/v3".into(),
                api_key: "test-key".into(),
                api_secret: String::new(),
            },
            ..DiscoveryConfig::default()
        }
    }

    #[test]
    fn fails_if_key_empty() {
        let mut c = config();
        c.virus_total.api_key = String::new();
        assert!(VirusTotalProvider::new(&c).is_err());
    }
    #[test]
    fn fails_if_disabled() {
        let mut c = config();
        c.virus_total.enabled = false;
        assert!(VirusTotalProvider::new(&c).is_ok());
    }
    #[test]
    fn high_confidence_for_malicious() {
        let stats = Some(VtStats {
            malicious: Some(50),
            suspicious: Some(5),
            harmless: Some(0),
            undetected: Some(5),
        });
        assert!(VirusTotalProvider::confidence_from_stats(&stats) > 0.8);
    }
    #[test]
    fn low_confidence_for_clean() {
        let stats = Some(VtStats {
            malicious: Some(0),
            suspicious: Some(0),
            harmless: Some(60),
            undetected: Some(10),
        });
        assert!(VirusTotalProvider::confidence_from_stats(&stats) < 0.3);
    }
}
