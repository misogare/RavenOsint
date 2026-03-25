//! Discovery runtime — holds a registry of all provider plugins.

use raven_bus::RavenBus;
use raven_core::{
    config::DiscoveryConfig, BusEvent, DiscoveryPlugin, DiscoveryProviderKind,
    DiscoveryRequest, DiscoveryResult, OsintError,
};
use std::{collections::HashMap, sync::Arc};

use crate::providers::{
    CensysProvider, ExaSearchProvider, SeedListProvider,
    SerperSearchProvider, VirusTotalProvider,
};

pub struct DiscoveryRuntime {
    bus:     RavenBus,
    plugins: HashMap<DiscoveryProviderKind, Arc<dyn DiscoveryPlugin>>,
}

impl DiscoveryRuntime {
    pub fn new() -> Self {
        Self { bus: RavenBus::new(), plugins: HashMap::new() }
    }

    /// Build a runtime from config.
    ///
    /// A provider is registered if its API key is non-empty.
    /// The `enabled` flag in config is a secondary gate — having a key is enough.
    /// This means setting the env var is sufficient without also flipping enabled=true.
    pub fn from_config(config: &DiscoveryConfig) -> Result<Self, OsintError> {
        let mut runtime = Self::new()
            .with_plugin(DiscoveryProviderKind::SeedFile, Arc::new(SeedListProvider));

        if !config.serper.api_key.is_empty() {
            match SerperSearchProvider::new(config) {
                Ok(p)  => runtime = runtime.with_plugin(DiscoveryProviderKind::Serper, Arc::new(p)),
                Err(e) => tracing::warn!(error = %e, "serper provider failed to initialise"),
            }
        }

        if !config.exa.api_key.is_empty() {
            match ExaSearchProvider::new(config) {
                Ok(p)  => runtime = runtime.with_plugin(DiscoveryProviderKind::Exa, Arc::new(p)),
                Err(e) => tracing::warn!(error = %e, "exa provider failed to initialise"),
            }
        }

        // Censys uses a single Bearer PAT — only api_key is needed, api_secret unused
        if !config.censys.api_key.is_empty() {
            match CensysProvider::new(config) {
                Ok(p)  => runtime = runtime.with_plugin(DiscoveryProviderKind::Censys, Arc::new(p)),
                Err(e) => tracing::warn!(error = %e, "censys provider failed to initialise"),
            }
        }

        if !config.virus_total.api_key.is_empty() {
            match VirusTotalProvider::new(config) {
                Ok(p)  => runtime = runtime.with_plugin(DiscoveryProviderKind::VirusTotal, Arc::new(p)),
                Err(e) => tracing::warn!(error = %e, "virustotal provider failed to initialise"),
            }
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

    pub fn registered_providers(&self) -> Vec<String> {
        self.plugins.values().map(|p| p.name().to_string()).collect()
    }

    pub async fn execute(&self, request: DiscoveryRequest) -> Result<DiscoveryResult, OsintError> {
        let _ = self.bus.publish(BusEvent::DiscoveryQueued(request.clone()));

        let plugin = self.plugins.get(&request.provider).ok_or_else(|| {
            OsintError::Discovery(format!(
                "no plugin registered for provider '{}'; \
                 check your .env file has the right key set",
                provider_name(&request.provider)
            ))
        })?;

        let result = plugin.discover(&request).await;

        match &result {
            Ok(d) => {
                let _ = self.bus.publish(BusEvent::DiscoveryUrlsFound {
                    job_id: d.job_id, urls: d.urls.clone(),
                });
                let _ = self.bus.publish(BusEvent::DiscoveryComplete(d.clone()));
            }
            Err(e) => {
                let _ = self.bus.publish(BusEvent::DiscoveryFailed {
                    job_id: request.job_id, error: e.to_string(),
                });
            }
        }

        result
    }
}

impl Default for DiscoveryRuntime {
    fn default() -> Self { Self::new() }
}

fn provider_name(kind: &DiscoveryProviderKind) -> &'static str {
    match kind {
        DiscoveryProviderKind::Serper     => "serper",
        DiscoveryProviderKind::Exa        => "exa",
        DiscoveryProviderKind::SeedFile   => "seed_file",
        DiscoveryProviderKind::Censys     => "censys",
        DiscoveryProviderKind::VirusTotal => "virus_total",
        DiscoveryProviderKind::Other      => "other",
    }
}