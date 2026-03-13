use std::{collections::HashMap, sync::Arc};

use chrono::Utc;
use raven_agent::{AgentOrchestrator, AvailabilityAgent, ContentAnalyzerAgent, SslAgent};
use raven_bus::RavenBus;
use raven_core::{
    BusEvent, DiscoveredUrl, DiscoveryRequest, DiscoveryResult, LlmContext, LlmProvider,
    LlmVerdict, OsintError, OsintTarget, RavenConfig, ScraperPlugin, SiteStatus,
    ValidationResult,
};
use raven_discovery::DiscoveryRuntime;
use raven_llm::{build_agent_summary, DeepSeekProvider};
use raven_scraper::{extract::truncate, RavenScraper};
use raven_storage::ResultStore;
use serde::Serialize;
use tracing::warn;
use utoipa::ToSchema;

pub struct PipelineRuntime {
    bus: RavenBus,
    scraper: RavenScraper,
    agents: AgentOrchestrator,
    llm: Option<DeepSeekProvider>,
    store: Arc<dyn ResultStore>,
}

impl PipelineRuntime {
    pub fn new(config: &RavenConfig, store: Arc<dyn ResultStore>) -> Result<Self, OsintError> {
        let scraper = RavenScraper::new(&config.scraper)?;
        let agents = AgentOrchestrator::new()
            .register(Arc::new(AvailabilityAgent))
            .register(Arc::new(SslAgent))
            .register(Arc::new(ContentAnalyzerAgent));

        let llm = if config.llm.provider.eq_ignore_ascii_case("deepseek") && !config.llm.api_key.is_empty() {
            Some(DeepSeekProvider::new(&config.llm)?)
        } else {
            None
        };

        Ok(Self {
            bus: RavenBus::new(),
            scraper,
            agents,
            llm,
            store,
        })
    }

    pub async fn execute(&self, target: OsintTarget) -> Result<ValidationResult, OsintError> {
        let job_id = target.id;
        self.publish(BusEvent::TargetQueued(target.clone()));

        let outcome: Result<ValidationResult, OsintError> = async {
            let mut scrape = self.scraper.scrape(&target.url).await?;
            scrape.job_id = job_id;
            self.publish(BusEvent::ScrapeDone(scrape.clone()));

            let agent_reports = self.agents.run_all(&scrape).await?;
            self.publish(BusEvent::AgentDone {
                job_id,
                reports: agent_reports.clone(),
            });

            let fallback_verdict = fallback_verdict(&scrape, &agent_reports);
            let llm_verdict = if let Some(provider) = &self.llm {
                let ctx = LlmContext {
                    job_id,
                    url: target.url.clone(),
                    body_snippet: truncate(&scrape.body_text, 4_000),
                    agent_summary: build_agent_summary(&agent_reports),
                };

                match provider.verify(&ctx).await {
                    Ok(verdict) => verdict,
                    Err(error) => {
                        warn!(job_id = %job_id, error = %error, "llm verification failed, falling back to heuristic verdict");
                        fallback_verdict.clone()
                    }
                }
            } else {
                fallback_verdict.clone()
            };

            self.publish(BusEvent::LlmVerified {
                job_id,
                verdict: llm_verdict.clone(),
            });

            let status = if matches!(llm_verdict.status, SiteStatus::Unknown) {
                fallback_verdict.status.clone()
            } else {
                llm_verdict.status.clone()
            };

            let confidence = ((AgentOrchestrator::aggregate_confidence(&agent_reports, base_confidence(&scrape))
                + llm_verdict.confidence)
                / 2.0)
                .clamp(0.0, 1.0);

            let result = ValidationResult {
                job_id,
                target,
                scraper_output: Some(scrape),
                agent_reports,
                llm_verdict,
                status,
                confidence,
                completed_at: Utc::now(),
            };

            self.store.save(&result).await?;
            self.publish(BusEvent::PipelineComplete {
                job_id,
                result: result.clone(),
            });

            Ok(result)
        }
        .await;

        if let Err(error) = &outcome {
            self.publish(BusEvent::PipelineFailed {
                job_id,
                error: error.to_string(),
            });
        }

        outcome
    }

    fn publish(&self, event: BusEvent) {
        let _ = self.bus.publish(event);
    }
}

fn base_confidence(scrape: &raven_core::ScraperOutput) -> f32 {
    match scrape.status_code {
        200..=299 => 0.55,
        300..=399 => 0.45,
        400..=499 => 0.20,
        500..=599 => 0.05,
        _ => 0.10,
    }
}

fn fallback_verdict(scrape: &raven_core::ScraperOutput, reports: &[raven_core::AgentReport]) -> LlmVerdict {
    let failed = reports.iter().filter(|r| !r.passed).count();
    let content_failed = reports
        .iter()
        .find(|r| r.agent_name == "content_analyzer" && !r.passed);

    let status = if scrape.status_code >= 500 {
        SiteStatus::Down
    } else if let Some(report) = content_failed {
        if report.confidence_delta <= -0.35 {
            SiteStatus::Malicious
        } else {
            SiteStatus::Suspicious
        }
    } else if failed > 0 || scrape.status_code >= 400 {
        SiteStatus::Suspicious
    } else {
        SiteStatus::Active
    };

    let confidence = AgentOrchestrator::aggregate_confidence(reports, base_confidence(scrape));

    LlmVerdict {
        status,
        confidence,
        reasoning: "LLM verification unavailable; heuristic verdict derived from scraper and agent outputs.".into(),
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DiscoveryWorkflowResult {
    pub discovery: DiscoveryResult,
    pub validations: Vec<ValidationResult>,
}

pub struct WorkflowRuntime {
    validation: PipelineRuntime,
    discovery: DiscoveryRuntime,
    store: Arc<dyn ResultStore>,
}

impl WorkflowRuntime {
    pub fn new(config: &RavenConfig, store: Arc<dyn ResultStore>) -> Result<Self, OsintError> {
        let validation = PipelineRuntime::new(config, Arc::clone(&store))?;
        let discovery = DiscoveryRuntime::from_config(&config.discovery)?;

        Ok(Self {
            validation,
            discovery,
            store,
        })
    }

    pub async fn validate_target(&self, target: OsintTarget) -> Result<ValidationResult, OsintError> {
        self.validation.execute(target).await
    }

    pub async fn discover(&self, request: DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        let result = self.discovery.execute(request).await?;
        self.store.save_discovery(&result).await?;
        Ok(result)
    }

    pub async fn discover_and_validate(
        &self,
        request: DiscoveryRequest,
        tags: Vec<String>,
        metadata: HashMap<String, String>,
    ) -> Result<DiscoveryWorkflowResult, OsintError> {
        let discovery = self.discover(request).await?;
        let mut validations = Vec::new();

        if discovery.request.validate {
            for url in &discovery.urls {
                let target = discovered_to_target(url, discovery.job_id, &tags, &metadata);
                validations.push(self.validate_target(target).await?);
            }
        }

        Ok(DiscoveryWorkflowResult {
            discovery,
            validations,
        })
    }
}

fn discovered_to_target(
    discovered: &DiscoveredUrl,
    discovery_job_id: uuid::Uuid,
    tags: &[String],
    metadata: &HashMap<String, String>,
) -> OsintTarget {
    let mut merged_metadata = metadata.clone();
    merged_metadata.insert("discovery_job_id".into(), discovery_job_id.to_string());
    merged_metadata.insert("discovery_provider".into(), format!("{:?}", discovered.provider).to_lowercase());
    merged_metadata.insert("discovery_type".into(), format!("{:?}", discovered.discovery_type).to_lowercase());
    merged_metadata.insert("discovery_source_query".into(), discovered.source_query.clone());

    OsintTarget {
        id: uuid::Uuid::new_v4(),
        url: discovered.url.clone(),
        tags: tags.to_vec(),
        metadata: merged_metadata,
        submitted_at: Utc::now(),
    }
}