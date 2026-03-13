//! Discovery runtime shell.
//!
//! Holds a registry of discovery plugins keyed by provider kind. This keeps the
//! runtime stable while provider implementations are added incrementally.

use raven_bus::RavenBus;
use raven_core::{
    config::DiscoveryConfig, BusEvent, DiscoveryPlugin, DiscoveryProviderKind,
    DiscoveryRequest, DiscoveryResult, OsintError,
};
use std::{collections::HashMap, sync::Arc};

use crate::providers::{ExaSearchProvider, SeedListProvider, SerperSearchProvider};

pub struct DiscoveryRuntime {
    bus: RavenBus,
    plugins: HashMap<DiscoveryProviderKind, Arc<dyn DiscoveryPlugin>>,
}

impl DiscoveryRuntime {
    pub fn new() -> Self {
        Self {
            bus: RavenBus::new(),
            plugins: HashMap::new(),
        }
    }

    pub fn from_config(config: &DiscoveryConfig) -> Result<Self, OsintError> {
        let mut runtime = Self::new().with_plugin(DiscoveryProviderKind::SeedFile, Arc::new(SeedListProvider));

        if config.serper.enabled && !config.serper.api_key.is_empty() {
            runtime = runtime.with_plugin(
                DiscoveryProviderKind::Serper,
                Arc::new(SerperSearchProvider::new(config)?),
            );
        }

        if config.exa.enabled && !config.exa.api_key.is_empty() {
            runtime = runtime.with_plugin(
                DiscoveryProviderKind::Exa,
                Arc::new(ExaSearchProvider::new(config)?),
            );
        }

        Ok(runtime)
    }

    pub fn with_plugin(mut self, kind: DiscoveryProviderKind, plugin: Arc<dyn DiscoveryPlugin>) -> Self {
        self.plugins.insert(kind, plugin);
        self
    }

    pub fn register(&mut self, kind: DiscoveryProviderKind, plugin: Arc<dyn DiscoveryPlugin>) {
        self.plugins.insert(kind, plugin);
    }

    pub async fn execute(&self, request: DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        let _ = self.bus.publish(BusEvent::DiscoveryQueued(request.clone()));
        let plugin = self
            .plugins
            .get(&request.provider)
            .ok_or_else(|| OsintError::Discovery(format!("no discovery plugin registered for provider '{}'", provider_name(&request.provider))))?;
        let result: Result<DiscoveryResult, OsintError> = plugin.discover(&request).await;

        match &result {
            Ok(discovery) => {
                let _ = self.bus.publish(BusEvent::DiscoveryUrlsFound {
                    job_id: discovery.job_id,
                    urls: discovery.urls.clone(),
                });
                let _ = self.bus.publish(BusEvent::DiscoveryComplete(discovery.clone()));
            }
            Err(error) => {
                let _ = self.bus.publish(BusEvent::DiscoveryFailed {
                    job_id: request.job_id,
                    error: error.to_string(),
                });
            }
        }

        result
    }
}

impl Default for DiscoveryRuntime {
    fn default() -> Self {
        Self::new()
    }
}

fn provider_name(kind: &DiscoveryProviderKind) -> &'static str {
    match kind {
        DiscoveryProviderKind::Serper => "serper",
        DiscoveryProviderKind::Exa => "exa",
        DiscoveryProviderKind::SeedFile => "seed_file",
        DiscoveryProviderKind::Censys => "censys",
        DiscoveryProviderKind::VirusTotal => "virus_total",
        DiscoveryProviderKind::Other => "other",
    }
}
