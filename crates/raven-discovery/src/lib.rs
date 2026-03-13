//! raven-discovery — automatic URL discovery before validation.
//!
//! This crate will host provider implementations such as:
//! - seed-list discovery
//! - Serper-backed web search
//! - Exa-backed web search
//! - optional CTI-enrichment providers (Censys, VirusTotal)

pub mod normalize;
pub mod providers;
pub mod runtime;

pub use providers::{ExaSearchProvider, SeedListProvider, SerperSearchProvider};
pub use runtime::DiscoveryRuntime;
