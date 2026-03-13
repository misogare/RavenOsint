//! raven-scraper — HTTP scraping engine.
//!
//! Provides the `RavenScraper` struct (implements `ScraperPlugin`) with:
//! - per-domain rate limiting (governor)
//! - round-robin user-agent and proxy rotation
//! - HTML text extraction (scraper crate)
//! - SSL validity inference (rustls enforces cert validity)

pub mod extract;
pub mod rate_limit;
pub mod scraper;

pub use scraper::RavenScraper;
