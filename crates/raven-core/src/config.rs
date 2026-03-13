//! Configuration structs — deserialised from `config/default.toml`
//! and optionally overridden by environment variables (RAVEN__*).

use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};

use crate::OsintError;

// ─────────────────────────────────────────────────────────────────────────────
// Sub-sections
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// `sqlite://raven.db` or `postgres://user:pass@host/db`
    pub url: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self { url: "sqlite://raven.db".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScraperConfig {
    pub rate_rpm:       u32,
    pub timeout_secs:   u64,
    pub max_redirects:  u32,
    pub user_agents:    Vec<String>,
    pub proxies:        Vec<String>,
}

impl Default for ScraperConfig {
    fn default() -> Self {
        Self {
            rate_rpm:      10,
            timeout_secs:  30,
            max_redirects: 10,
            user_agents:   vec![
                "Mozilla/5.0 (compatible; RavenOSINT/0.1)".into(),
            ],
            proxies: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmConfig {
    pub provider:    String,
    pub base_url:    String,
    pub model:       String,
    /// Never commit real keys — set via RAVEN__LLM__API_KEY env var.
    pub api_key:     String,
    pub max_tokens:  u32,
    pub temperature: f32,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider:    "deepseek".into(),
            base_url:    "https://api.deepseek.com/v1".into(),
            model:       "deepseek-chat".into(),
            api_key:     String::new(),
            max_tokens:  1024,
            temperature: 0.2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self { host: "127.0.0.1".into(), port: 3000 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level:  String,
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self { level: "info".into(), format: "pretty".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DiscoveryProviderConfig {
    pub enabled: bool,
    pub base_url: String,
    /// Never commit real keys — prefer env overrides.
    pub api_key: String,
}

impl Default for DiscoveryProviderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            api_key: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DiscoveryConfig {
    pub enabled: bool,
    pub default_provider: String,
    pub default_limit: usize,
    pub max_limit: usize,
    pub timeout_secs: u64,
    pub rate_rpm: u32,
    pub include_subdomains: bool,
    pub validate_by_default: bool,
    pub serper: DiscoveryProviderConfig,
    pub exa: DiscoveryProviderConfig,
    pub censys: DiscoveryProviderConfig,
    pub virus_total: DiscoveryProviderConfig,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_provider: "serper".into(),
            default_limit: 25,
            max_limit: 100,
            timeout_secs: 20,
            rate_rpm: 30,
            include_subdomains: true,
            validate_by_default: false,
            serper: DiscoveryProviderConfig {
                enabled: true,
                base_url: "https://google.serper.dev/search".into(),
                api_key: String::new(),
            },
            exa: DiscoveryProviderConfig {
                enabled: true,
                base_url: "https://api.exa.ai/search".into(),
                api_key: String::new(),
            },
            censys: DiscoveryProviderConfig {
                enabled: false,
                base_url: "https://api.platform.censys.io/v3/global/".into(),
                api_key: String::new(),
            },
            virus_total: DiscoveryProviderConfig {
                enabled: false,
                base_url: "https://www.virustotal.com/api/v3".into(),
                api_key: String::new(),
            },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Root config
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RavenConfig {
    pub database: DatabaseConfig,
    pub scraper:  ScraperConfig,
    pub discovery: DiscoveryConfig,
    pub llm:      LlmConfig,
    pub api:      ApiConfig,
    pub logging:  LoggingConfig,
}

impl RavenConfig {
    /// Load config from file (if present) then overlay env-vars.
    ///
    /// Priority (high → low):
    ///   1. Environment variables (`RAVEN__<SECTION>__<KEY>`)
    ///   2. `config/default.toml`
    ///   3. Built-in defaults
    pub fn load(config_path: &str) -> Result<Self, OsintError> {
        let fig = Figment::new()
            .merge(Toml::file(config_path))
            .merge(Env::prefixed("RAVEN__").split("__"));

        fig.extract::<Self>().map_err(|e| OsintError::Config(e.to_string()))
    }
}
