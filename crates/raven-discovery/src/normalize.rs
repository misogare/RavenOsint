//! URL normalization helpers shared across discovery providers.

use raven_core::OsintError;
use url::Url;

/// Normalize a URL for deduplication and downstream validation.
pub fn normalize_url(input: &str) -> Result<String, OsintError> {
    let mut url = Url::parse(input).map_err(OsintError::InvalidUrl)?;

    url.set_fragment(None);

    // Normalize default ports away.
    let is_default_port = matches!(
        (url.scheme(), url.port()),
        ("http", Some(80)) | ("https", Some(443))
    );
    if is_default_port {
        let _ = url.set_port(None);
    }

    // Remove a trailing slash on non-root paths.
    let path = url.path().trim_end_matches('/').to_string();
    if !path.is_empty() {
        url.set_path(&path);
    }

    Ok(url.to_string())
}

/// Best-effort domain extraction for normalized discovery records.
pub fn extract_domain(input: &str) -> Option<String> {
    Url::parse(input)
        .ok()
        .and_then(|u| u.host_str().map(|host| host.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_default_https_port() {
        let url = normalize_url("https://example.com:443/path/").unwrap();
        assert_eq!(url, "https://example.com/path");
    }

    #[test]
    fn extracts_domain() {
        assert_eq!(
            extract_domain("https://sub.example.com/path").as_deref(),
            Some("sub.example.com")
        );
    }
}
