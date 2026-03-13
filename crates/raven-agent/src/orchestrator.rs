//! `AgentOrchestrator` — runs all registered agents concurrently and
//! collects their reports.
//!
//! Agent dependency ordering (via `AgentPlugin::depends_on()`) is tracked
//! in a `petgraph::DiGraph` for topological awareness.  In P0 all agents
//! are independent, so they execute fully in parallel via `JoinSet`.

use raven_core::{AgentReport, DynAgent, OsintError, ScraperOutput};
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

/// Orchestrates one or more `AgentPlugin` implementations against a single
/// `ScraperOutput`.
pub struct AgentOrchestrator {
    agents: Vec<DynAgent>,
}

impl AgentOrchestrator {
    pub fn new() -> Self {
        Self { agents: Vec::new() }
    }

    /// Register an agent (builder-style chaining).
    pub fn register(mut self, agent: DynAgent) -> Self {
        debug!(agent = %agent.name(), "orchestrator: registered agent");
        self.agents.push(agent);
        self
    }

    /// Run all registered agents concurrently against `input`.
    ///
    /// All agents fire at the same time (no dependency ordering in P0).
    /// The first hard error aborts the run; panicking tasks are caught and
    /// converted into `OsintError::Orchestrator`.
    pub async fn run_all(&self, input: &ScraperOutput) -> Result<Vec<AgentReport>, OsintError> {
        if self.agents.is_empty() {
            warn!("orchestrator: no agents registered, returning empty reports");
            return Ok(vec![]);
        }

        // Arc-wrap the input once so each task can hold a cheap shared ref.
        let input = Arc::new(input.clone());

        let mut set: JoinSet<Result<AgentReport, OsintError>> = JoinSet::new();

        for agent in &self.agents {
            let agent: DynAgent = agent.clone();
            let inp = Arc::clone(&input);
            set.spawn(async move {
                debug!(agent = %agent.name(), "agent: starting");
                let report = agent.run(&inp).await?;
                debug!(
                    agent = %report.agent_name,
                    passed = %report.passed,
                    delta  = %report.confidence_delta,
                    "agent: finished"
                );
                Ok(report)
            });
        }

        let mut reports = Vec::with_capacity(self.agents.len());

        while let Some(join_result) = set.join_next().await {
            match join_result {
                Ok(Ok(report)) => reports.push(report),
                Ok(Err(agent_err)) => {
                    // One agent failing should not block the others' results,
                    // but we do propagate the error to the caller.
                    return Err(agent_err);
                }
                Err(join_err) => {
                    return Err(OsintError::Orchestrator(format!(
                        "agent task panicked: {join_err}"
                    )));
                }
            }
        }

        info!(
            count = reports.len(),
            "orchestrator: all agents completed"
        );

        Ok(reports)
    }

    /// Compute the aggregate confidence delta from a finished report set.
    /// Clamps result to [0.0, 1.0].
    pub fn aggregate_confidence(reports: &[AgentReport], base: f32) -> f32 {
        let delta: f32 = reports.iter().map(|r| r.confidence_delta).sum();
        (base + delta).clamp(0.0, 1.0)
    }
}

impl Default for AgentOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}
