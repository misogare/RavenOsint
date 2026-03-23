use async_trait::async_trait;
use chrono::Utc;
use raven_core::{
    DiscoveredUrl, DiscoveryPlugin, DiscoveryRequest, DiscoveryResult, DiscoveryType,
    DiscoveryProviderKind, OsintError,
};
use std::collections::HashSet;
use tokio::fs;

use crate::normalize::{extract_domain, normalize_url};

/// Seed-list discovery provider.
///
/// The provider accepts either:
/// - a path to a file containing one URL/domain per line, or
/// - a single inline URL/domain in `request.query`
///
/// File detection works by attempting to read the path with `tokio::fs::read_to_string`.
/// If the read succeeds the query is treated as a file path; if it fails (file not found,
/// permission denied, or the string is not a valid path at all) the query is treated as
/// a single inline seed.  This avoids calling `Path::exists()` which would block the
/// async executor.
pub struct SeedListProvider;

#[async_trait]
impl DiscoveryPlugin for SeedListProvider {
    fn name(&self) -> &str {
        "seed_list"
    }

    async fn discover(&self, request: &DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        let raw_inputs = load_seed_inputs(&request.query).await;
        let mut seen = HashSet::new();
        let mut urls = Vec::new();

        for raw in raw_inputs {
            // Skip lines that fail normalization (malformed input) rather than
            // aborting the whole batch.
            let normalized = match normalize_seed(&raw) {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(input = %raw, error = %e, "seed: skipping malformed input");
                    continue;
                }
            };

            if !seen.insert(normalized.clone()) {
                // Duplicate — skip silently.
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

/// Load seed inputs from a file path or return the query as a single inline seed.
///
/// Attempts an async file read. On any error (not found, not a file, etc.)
/// falls back to treating the query string itself as an inline seed.
/// This is intentionally infallible at the outer level — callers receive at
/// least one entry unless the query is empty.
async fn load_seed_inputs(query: &str) -> Vec<String> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    match fs::read_to_string(trimmed).await {
        Ok(body) => {
            let lines: Vec<String> = body
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(ToOwned::to_owned)
                .collect();

            if lines.is_empty() {
                tracing::warn!(path = %trimmed, "seed file exists but contains no valid entries");
            } else {
                tracing::debug!(path = %trimmed, count = lines.len(), "seed: loaded from file");
            }

            lines
        }
        Err(_) => {
            // Not a readable file — treat as an inline URL/domain.
            tracing::debug!(query = %trimmed, "seed: treating query as inline seed");
            vec![trimmed.to_string()]
        }
    }
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
    fn normalizes_full_url_seed() {
        let normalized = normalize_seed("https://example.com/path?q=1#frag").unwrap();
        // Fragment should be stripped, path preserved, query preserved.
        assert_eq!(normalized, "https://example.com/path?q=1");
    }

    #[test]
    fn returns_error_for_empty_seed() {
        assert!(normalize_seed("   ").is_err());
    }

    #[tokio::test]
    async fn unknown_path_falls_back_to_inline() {
        // A string that looks like a path but does not exist on disk.
        let inputs = load_seed_inputs("/no/such/file.txt").await;
        assert_eq!(inputs, vec!["/no/such/file.txt".to_string()]);
    }

    #[tokio::test]
    async fn inline_url_is_returned_as_single_entry() {
        let inputs = load_seed_inputs("https://example.com").await;
        assert_eq!(inputs, vec!["https://example.com".to_string()]);
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

    #[tokio::test]
    async fn empty_query_produces_error() {
        let provider = SeedListProvider;
        let request = DiscoveryRequest::new("");
        let result = provider.discover(&request).await;
        assert!(result.is_err());
    }
}