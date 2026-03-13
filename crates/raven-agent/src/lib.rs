//! raven-agent — agent orchestration and built-in validation agents.
//!
//! ## Structure
//! - `AgentOrchestrator` — runs all registered agents concurrently via `JoinSet`
//! - Built-in agents: `AvailabilityAgent`, `SslAgent`, `ContentAnalyzerAgent`

pub mod agents;
pub mod orchestrator;

pub use agents::{AvailabilityAgent, ContentAnalyzerAgent, SslAgent};
pub use orchestrator::AgentOrchestrator;
