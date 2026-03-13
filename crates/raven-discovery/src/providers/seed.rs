use async_trait::async_trait;
use chrono::Utc;
use raven_core::{
    DiscoveredUrl, DiscoveryPlugin, DiscoveryRequest, DiscoveryResult, DiscoveryType,
    DiscoveryProviderKind, OsintError,
};
use std::{collections::HashSet, path::Path};
use tokio::fs;

use crate::normalize::{extract_domain, normalize_url};

/// Seed-list discovery provider.
///
/// The provider accepts either:
/// - a path to a file containing one URL/domain per line, or
/// - a single inline URL/domain in `request.query`
pub struct SeedListProvider;

#[async_trait]
impl DiscoveryPlugin for SeedListProvider {
    fn name(&self) -> &str {
        "seed_list"
    }

    async fn discover(&self, request: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        let raw_inputs = load_seed_inputs(&request.query).await?;
        let mut seen = HashSet::new();
        let mut urls = Vec::new();

        for raw in raw_inputs {
            let normalized = normalize_seed(&raw)?;
            if !seen.insert(normalized.clone()) {
                continue;
            }

            urls.push(DiscoveredUrl {
                domain: extract_domain(&normalized).unwrap_or_default(),
                url: normalized,
                title: None,
                snippet: Some("seed input".into()),
                provider: DiscoveryProviderKind::SeedFile,
                discovery_type: DiscoveryType::SeedFile,
                source_query: request.query.clone(),
                source_url: None,
                rank: Some(urls.len() as u32 + 1),
                confidence: 1.0,
                discovered_at: Utc::now(),
            });

            if urls.len() >= request.limit {
                break;
            }
        }

        if urls.is_empty() {
            return Err(OsintError::Discovery(
                "seed discovery produced no valid URLs".into(),
            ));
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

async fn load_seed_inputs(query: &str) -> Result<Vec<String>, OsintError> {
    if looks_like_file_path(query) {
        let body = fs::read_to_string(query).await?;
        Ok(body
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(ToOwned::to_owned)
            .collect())
    } else {
        Ok(vec![query.trim().to_string()])
    }
}

fn looks_like_file_path(input: &str) -> bool {
    let path = Path::new(input.trim());
    path.exists() && path.is_file()
}

fn normalize_seed(raw: &str) -> Result<String, OsintError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(OsintError::Discovery("empty seed input".into()));
    }

    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return normalize_url(trimmed);
    }

    normalize_url(&format!("https://{trimmed}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::{DiscoveryProviderKind, DiscoveryRequest};

    #[test]
    fn normalizes_domain_seed() {
        let normalized = normalize_seed("example.com").unwrap();
        assert_eq!(normalized, "https://example.com/");
    }

    #[test]
    fn detects_inline_seed_not_path() {
        assert!(!looks_like_file_path("https://example.com"));
    }

    #[tokio::test]
    async fn deduplicates_inline_seed() {
        let provider = SeedListProvider;
        let mut request = DiscoveryRequest::new("example.com");
        request.provider = DiscoveryProviderKind::SeedFile;
        request.limit = 10;

        let result = provider.discover(&request).await.unwrap();
        assert_eq!(result.urls.len(), 1);
        assert_eq!(result.urls[0].url, "https://example.com/");
    }
}
