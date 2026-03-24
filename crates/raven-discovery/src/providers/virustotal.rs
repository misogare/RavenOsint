use async_trait::async_trait;
use chrono::Utc;
use raven_core::{
    config::DiscoveryConfig, DiscoveredUrl, DiscoveryPlugin, DiscoveryProviderKind,
    DiscoveryRequest, DiscoveryResult, DiscoveryType, OsintError, SearchProvider,
};
use reqwest::Client;
use serde::Deserialize;

use crate::normalize::{extract_domain, normalize_url};

/// VirusTotal domain/URL enrichment and pivot discovery provider.
///
/// Auth: `x-apikey` header.
/// Set via: RAVEN__DISCOVERY__VIRUS_TOTAL__API_KEY
///
/// Free tier limits: 4 requests/minute, 500 requests/day.
///
/// Capability tiers — this provider uses ONLY free-tier endpoints:
///   ✅ GET /domains/{domain}         — domain reputation + subdomains
///   ✅ GET /domains/{domain}/urls     — known URLs for a domain
///   ✅ GET /urls/{id}                 — URL analysis report
///   ❌ GET /intelligence/search       — premium only, not used
///   ❌ Livehunt / Retrohunt           — premium only, not used
///
/// When `request.site` is set, queries that domain's known URLs.
/// When only `request.query` is given, treats it as a domain name pivot.
pub struct VirusTotalProvider {
    client:   Client,
    api_key:  String,
    base_url: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// VirusTotal wire types
// ─────────────────────────────────────────────────────────────────────────────

/// Response envelope for domain URLs endpoint.
#[derive(Debug, Deserialize)]
struct VtUrlsResponse {
    data: Option<Vec<VtUrlItem>>,
    meta: Option<VtMeta>,
}

#[derive(Debug, Deserialize)]
struct VtUrlItem {
    #[serde(rename = "type")]
    item_type: Option<String>,
    id:        Option<String>,
    attributes: Option<VtUrlAttributes>,
}

#[derive(Debug, Deserialize)]
struct VtUrlAttributes {
    url:             Option<String>,
    title:           Option<String>,
    last_final_url:  Option<String>,
    last_http_response_code: Option<u16>,
    times_submitted: Option<u64>,
    last_analysis_stats: Option<VtStats>,
}

#[derive(Debug, Deserialize)]
struct VtStats {
    malicious:  Option<u64>,
    suspicious: Option<u64>,
    harmless:   Option<u64>,
    undetected: Option<u64>,
}

/// Response envelope for domain report endpoint.
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
    last_analysis_stats:    Option<VtStats>,
    reputation:             Option<i64>,
    #[serde(default)]
    subdomains:             Vec<String>,
    last_dns_records:       Option<Vec<VtDnsRecord>>,
}

#[derive(Debug, Deserialize)]
struct VtDnsRecord {
    #[serde(rename = "type")]
    record_type: Option<String>,
    value:       Option<String>,
}

#[derive(Debug, Deserialize)]
struct VtMeta {
    cursor: Option<String>,
    count:  Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Implementation
// ─────────────────────────────────────────────────────────────────────────────

impl VirusTotalProvider {
    pub fn new(config: &DiscoveryConfig) -> Result<Self, OsintError> {
        if !config.virus_total.enabled {
            return Err(OsintError::Discovery("virustotal provider is disabled".into()));
        }
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
            api_key:  config.virus_total.api_key.clone(),
            base_url: config.virus_total.base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Derive confidence score from VirusTotal analysis stats.
    /// More malicious/suspicious detections → lower confidence it's safe.
    fn confidence_from_stats(stats: &Option<VtStats>) -> f32 {
        let s = match stats {
            Some(s) => s,
            None => return 0.5,
        };
        let malicious  = s.malicious.unwrap_or(0) as f32;
        let suspicious = s.suspicious.unwrap_or(0) as f32;
        let total = malicious
            + suspicious
            + s.harmless.unwrap_or(0) as f32
            + s.undetected.unwrap_or(0) as f32;

        if total == 0.0 {
            return 0.5;
        }

        let bad_ratio = (malicious + suspicious) / total;
        // Invert: high bad_ratio → low confidence the URL is clean.
        // We store raw confidence in DiscoveredUrl (not a verdict), so
        // this represents "confidence this is worth investigating".
        // High detection rate = high OSINT value.
        (bad_ratio * 0.9 + 0.1).clamp(0.1, 1.0)
    }

    /// Fetch known URLs for a domain from VirusTotal.
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

        // Graceful degradation on rate limit or auth issues.
        let status = response.status();
        if status == 429 {
            tracing::warn!("virustotal: rate limit hit — returning empty result");
            return Ok(vec![]);
        }
        if status == 403 {
            tracing::warn!("virustotal: forbidden — check API key or tier restrictions");
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

            // Prefer last_final_url (post-redirect), fall back to url.
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

            let malicious  = attrs.last_analysis_stats.as_ref().and_then(|s| s.malicious).unwrap_or(0);
            let suspicious = attrs.last_analysis_stats.as_ref().and_then(|s| s.suspicious).unwrap_or(0);

            let snippet = Some(format!(
                "VirusTotal: {} malicious, {} suspicious detections | submitted {} times",
                malicious,
                suspicious,
                attrs.times_submitted.unwrap_or(0)
            ));

            urls.push(DiscoveredUrl {
                domain:         extract_domain(&normalized).unwrap_or_default(),
                url:            normalized,
                title:          attrs.title.clone(),
                snippet,
                provider:       DiscoveryProviderKind::VirusTotal,
                discovery_type: DiscoveryType::VirusTotalPivot,
                source_query:   request.query.clone(),
                source_url:     None,
                rank:           Some((rank + 1) as u32),
                confidence:     Self::confidence_from_stats(&attrs.last_analysis_stats),
                discovered_at:  Utc::now(),
            });
        }

        Ok(urls)
    }

    /// Fetch subdomains from a domain report.
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

        let status = response.status();
        if status == 429 {
            tracing::warn!("virustotal: rate limit hit fetching domain report");
            return Ok(vec![]);
        }
        if status == 403 {
            tracing::warn!("virustotal: forbidden fetching domain report");
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

        for (rank, subdomain) in attrs.subdomains.iter().enumerate() {
            let raw = format!("https://{subdomain}/");
            let normalized = match normalize_url(&raw) {
                Ok(u) => u,
                Err(_) => continue,
            };

            let snippet = Some(format!(
                "VirusTotal subdomain of {domain} | domain reputation: {reputation}"
            ));

            urls.push(DiscoveredUrl {
                domain:         extract_domain(&normalized).unwrap_or_default(),
                url:            normalized,
                title:          None,
                snippet,
                provider:       DiscoveryProviderKind::VirusTotal,
                discovery_type: DiscoveryType::VirusTotalPivot,
                source_query:   request.query.clone(),
                source_url:     None,
                rank:           Some((rank + 1) as u32),
                // Low reputation = more interesting for OSINT.
                confidence:     if reputation < 0 { 0.9 } else { 0.5 },
                discovered_at:  Utc::now(),
            });
        }

        Ok(urls)
    }

    async fn do_search(&self, request: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        let target_domain = request
            .site
            .as_deref()
            .unwrap_or(request.query.trim());

        // Fetch both known URLs and subdomains, then merge.
        let (url_results, subdomain_results) = tokio::join!(
            self.fetch_domain_urls(target_domain, request.limit, request),
            self.fetch_subdomains(target_domain, request),
        );

        let mut urls = url_results.unwrap_or_default();
        let subdomains = subdomain_results.unwrap_or_default();

        // Merge subdomains in if we have room.
        for sub in subdomains {
            if urls.len() >= request.limit {
                break;
            }
            if !urls.iter().any(|u| u.url == sub.url) {
                urls.push(sub);
            }
        }

        urls.truncate(request.limit);

        Ok(DiscoveryResult {
            job_id:           request.job_id,
            request:          request.clone(),
            total_discovered: urls.len(),
            urls,
            completed_at:     Utc::now(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Trait implementations
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl SearchProvider for VirusTotalProvider {
    fn name(&self) -> &str { "virustotal" }

    async fn search(&self, request: &DiscoveryRequest) -> Result<Vec<DiscoveredUrl>, OsintError> {
        self.do_search(request).await.map(|r| r.urls)
    }
}

#[async_trait]
impl DiscoveryPlugin for VirusTotalProvider {
    fn name(&self) -> &str { "virustotal" }

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
            virus_total: DiscoveryProviderConfig {
                enabled:    true,
                base_url:   "https://www.virustotal.com/api/v3".into(),
                api_key:    "test-key".into(),
                api_secret: String::new(),
            },
            ..DiscoveryConfig::default()
        }
    }

    #[test]
    fn new_fails_if_key_empty() {
        let mut cfg = config();
        cfg.virus_total.api_key = String::new();
        assert!(VirusTotalProvider::new(&cfg).is_err());
    }

    #[test]
    fn new_fails_if_disabled() {
        let mut cfg = config();
        cfg.virus_total.enabled = false;
        assert!(VirusTotalProvider::new(&cfg).is_err());
    }

    #[test]
    fn confidence_high_for_malicious_url() {
        let stats = Some(VtStats {
            malicious:  Some(50),
            suspicious: Some(5),
            harmless:   Some(0),
            undetected: Some(5),
        });
        let confidence = VirusTotalProvider::confidence_from_stats(&stats);
        assert!(confidence > 0.8, "expected high confidence, got {confidence}");
    }

    #[test]
    fn confidence_low_for_clean_url() {
        let stats = Some(VtStats {
            malicious:  Some(0),
            suspicious: Some(0),
            harmless:   Some(60),
            undetected: Some(10),
        });
        let confidence = VirusTotalProvider::confidence_from_stats(&stats);
        assert!(confidence < 0.3, "expected low confidence, got {confidence}");
    }
}
