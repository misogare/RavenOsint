//! `ResultStore` trait + `new_store()` factory.

use async_trait::async_trait;
use raven_core::{DiscoveryResult, OsintError, ValidationResult};
use uuid::Uuid;

/// Pagination parameters for list queries.
#[derive(Debug, Clone)]
pub struct ListParams {
    pub limit: i64,
    pub offset: i64,
}

impl Default for ListParams {
    fn default() -> Self {
        Self {
            limit: 50,
            offset: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// The storage contract every backend must implement.
#[async_trait]
pub trait ResultStore: Send + Sync + 'static {
    /// Persist a completed `ValidationResult` (upserts on conflict).
    async fn save(&self, result: &ValidationResult) -> Result<(), OsintError>;

    /// Retrieve one result by job id.
    async fn find_by_id(&self, job_id: Uuid) -> Result<ValidationResult, OsintError>;

    /// List results with simple pagination.
    async fn list(&self, params: ListParams) -> Result<Vec<ValidationResult>, OsintError>;

    /// Delete a result and its agent reports.
    async fn delete(&self, job_id: Uuid) -> Result<(), OsintError>;

    /// Total number of stored results.
    async fn count(&self) -> Result<i64, OsintError>;

    /// Persist a completed discovery result.
    async fn save_discovery(&self, result: &DiscoveryResult) -> Result<(), OsintError>;

    /// Retrieve one discovery result by job id.
    async fn find_discovery_by_id(&self, job_id: Uuid) -> Result<DiscoveryResult, OsintError>;

    /// List discovery results with simple pagination.
    async fn list_discoveries(
        &self,
        params: ListParams,
    ) -> Result<Vec<DiscoveryResult>, OsintError>;

    /// Total number of stored discovery results.
    async fn discovery_count(&self) -> Result<i64, OsintError>;
}

// ─────────────────────────────────────────────────────────────────────────────

/// Factory: inspect the URL prefix and return the appropriate boxed store.
pub async fn new_store(database_url: &str) -> Result<Box<dyn ResultStore>, OsintError> {
    #[cfg(feature = "duckdb")]
    if database_url.starts_with("duckdb") {
        let store = crate::duckdb_store::DuckDbStore::connect(database_url)?;
        return Ok(Box::new(store));
    }

    #[cfg(feature = "sqlite")]
    if database_url.starts_with("sqlite") {
        let store = crate::sqlite::SqliteStore::connect(database_url).await?;
        return Ok(Box::new(store));
    }

    #[cfg(feature = "postgres")]
    if database_url.starts_with("postgres") {
        let store = crate::postgres::PostgresStore::connect(database_url).await?;
        return Ok(Box::new(store));
    }

    Err(OsintError::Config(format!(
        "unsupported database URL scheme: '{database_url}'. \
         Enable the 'duckdb', 'sqlite', or 'postgres' feature and use a matching URL."
    )))
}
