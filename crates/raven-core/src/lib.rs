//! raven-core — shared contracts, types, errors, and configuration.
//!
//! Every other crate in the workspace depends on this crate.
//! Nothing here depends on any other workspace crate.

pub mod config;
pub mod error;
pub mod traits;
pub mod types;

pub use config::{DiscoveryConfig, DiscoveryProviderConfig, RavenConfig};
pub use error::OsintError;
pub use traits::{
    AgentPlugin, DiscoveryPlugin, DynAgent, DynDiscovery, DynLlm, DynScraper, DynSearchProvider,
    LlmProvider, ScraperPlugin, SearchProvider,
};
pub use types::{
    AgentReport, BusEvent, DiscoveredUrl, DiscoveryProviderKind, DiscoveryRequest, DiscoveryResult,
    DiscoveryType, LlmContext, LlmVerdict, OsintTarget, ScraperOutput, SiteStatus,
    ValidationResult,
};
