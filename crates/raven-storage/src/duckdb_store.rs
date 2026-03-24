//! DuckDB storage backend — analytical in-process database.
//!
//! DuckDB is ideal for running queries across large scan result sets:
//! aggregations, time-series, cross-joins, and export to Parquet/CSV are
//! all fast and built-in.
//!
//! Unlike SQLite/Postgres, DuckDB's Rust driver is synchronous. Every call
//! is wrapped in `tokio::task::spawn_blocking` so the async executor is
//! never blocked.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use duckdb::{params, Connection};
use raven_core::{DiscoveryResult, OsintError, ValidationResult};
use tracing::info;
use uuid::Uuid;

use crate::{
    model::{
        discovery_to_rows, result_to_rows, rows_to_discovery, rows_to_result,
        AgentRow, DiscoveredUrlRow, DiscoveryJobRow, JobRow, ResultRow,
    },
    store::{ListParams, ResultStore},
};

// ─────────────────────────────────────────────────────────────────────────────
// Store
// ─────────────────────────────────────────────────────────────────────────────

/// DuckDB-backed result store.
///
/// The connection is protected by a `Mutex` because DuckDB connections are
/// not `Send` out of the box. `spawn_blocking` moves the guard to a thread
/// pool thread for every operation, keeping the async executor free.
pub struct DuckDbStore {
    conn: Arc<Mutex<Connection>>,
}

impl DuckDbStore {
    /// Open (or create) a DuckDB file and initialise the schema.
    ///
    /// `path` can be:
    ///   - `"duckdb://raven.duckdb"` (strip the scheme prefix)
    ///   - `":memory:"` for an in-memory database (tests)
    ///   - a bare file path like `"raven.duckdb"`
    pub fn connect(url: &str) -> Result<Self, OsintError> {
        // Strip the duckdb:// scheme if present.
        let path = url
            .strip_prefix("duckdb://")
            .unwrap_or(url);

        let conn = if path == ":memory:" {
            Connection::open_in_memory()
        } else {
            Connection::open(path)
        }
        .map_err(|e| OsintError::Database(format!("duckdb open: {e}")))?;

        Self::create_schema(&conn)?;

        info!(db = %path, "DuckDB connected and schema initialised");

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn create_schema(conn: &Connection) -> Result<(), OsintError> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id           VARCHAR PRIMARY KEY,
                url          VARCHAR NOT NULL,
                tags         VARCHAR NOT NULL DEFAULT '[]',
                metadata     VARCHAR NOT NULL DEFAULT '{}',
                submitted_at VARCHAR NOT NULL,
                completed_at VARCHAR,
                status       VARCHAR NOT NULL DEFAULT 'unknown'
            );

            CREATE TABLE IF NOT EXISTS validation_results (
                job_id         VARCHAR PRIMARY KEY,
                status         VARCHAR NOT NULL DEFAULT 'unknown',
                confidence     DOUBLE  NOT NULL DEFAULT 0.0,
                llm_status     VARCHAR NOT NULL DEFAULT 'unknown',
                llm_confidence DOUBLE  NOT NULL DEFAULT 0.0,
                llm_reasoning  VARCHAR NOT NULL DEFAULT '',
                scraper_output VARCHAR,
                completed_at   VARCHAR NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_reports (
                id               VARCHAR PRIMARY KEY,
                job_id           VARCHAR NOT NULL,
                agent_name       VARCHAR NOT NULL,
                passed           BOOLEAN NOT NULL DEFAULT false,
                confidence_delta DOUBLE  NOT NULL DEFAULT 0.0,
                details          VARCHAR NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS discovery_jobs (
                job_id           VARCHAR PRIMARY KEY,
                request_json     VARCHAR NOT NULL,
                total_discovered INTEGER NOT NULL DEFAULT 0,
                completed_at     VARCHAR NOT NULL
            );

            CREATE TABLE IF NOT EXISTS discovered_urls (
                id      VARCHAR PRIMARY KEY,
                job_id  VARCHAR NOT NULL,
                payload VARCHAR NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_agent_reports_job_id
                ON agent_reports(job_id);
            CREATE INDEX IF NOT EXISTS idx_scan_jobs_status
                ON scan_jobs(status);
            CREATE INDEX IF NOT EXISTS idx_discovered_urls_job_id
                ON discovered_urls(job_id);
            CREATE INDEX IF NOT EXISTS idx_discovery_jobs_completed_at
                ON discovery_jobs(completed_at);
            ",
        )
        .map_err(|e| OsintError::Database(format!("duckdb schema: {e}")))?;

        Ok(())
    }

    /// Clone the Arc so closures can take ownership of the connection handle.
    fn conn(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResultStore implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl ResultStore for DuckDbStore {
    async fn save(&self, result: &ValidationResult) -> Result<(), OsintError> {
        let (job, res, agents) = result_to_rows(result)?;
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|e| OsintError::Database(e.to_string()))?;

            // Upsert scan_jobs.
            guard.execute(
                "INSERT OR REPLACE INTO scan_jobs
                 (id, url, tags, metadata, submitted_at, completed_at, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    job.id, job.url, job.tags, job.metadata,
                    job.submitted_at, job.completed_at, job.status
                ],
            ).map_err(|e| OsintError::Database(e.to_string()))?;

            // Upsert validation_results.
            guard.execute(
                "INSERT OR REPLACE INTO validation_results
                 (job_id, status, confidence, llm_status, llm_confidence,
                  llm_reasoning, scraper_output, completed_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    res.job_id, res.status, res.confidence,
                    res.llm_status, res.llm_confidence, res.llm_reasoning,
                    res.scraper_output, res.completed_at
                ],
            ).map_err(|e| OsintError::Database(e.to_string()))?;

            // Delete + re-insert agent reports.
            guard.execute(
                "DELETE FROM agent_reports WHERE job_id = ?",
                params![res.job_id],
            ).map_err(|e| OsintError::Database(e.to_string()))?;

            for agent in &agents {
                guard.execute(
                    "INSERT INTO agent_reports
                     (id, job_id, agent_name, passed, confidence_delta, details)
                     VALUES (?, ?, ?, ?, ?, ?)",
                    params![
                        agent.id, agent.job_id, agent.agent_name,
                        agent.passed != 0, agent.confidence_delta, agent.details
                    ],
                ).map_err(|e| OsintError::Database(e.to_string()))?;
            }

            Ok::<_, OsintError>(())
        })
        .await
        .map_err(|e| OsintError::Database(format!("spawn_blocking: {e}")))?
    }

    async fn find_by_id(&self, job_id: Uuid) -> Result<ValidationResult, OsintError> {
        let id_str = job_id.to_string();
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|e| OsintError::Database(e.to_string()))?;

            let job: JobRow = {
                let mut stmt = guard.prepare(
                    "SELECT id, url, tags, metadata, submitted_at, completed_at, status
                     FROM scan_jobs WHERE id = ?",
                ).map_err(|e| OsintError::Database(e.to_string()))?;

                let mut rows = stmt.query(params![id_str])
                    .map_err(|e| OsintError::Database(e.to_string()))?;

                let row = rows.next()
                    .map_err(|e| OsintError::Database(e.to_string()))?
                    .ok_or_else(|| OsintError::NotFound(id_str.clone()))?;

                JobRow {
                    id:           row.get(0).map_err(|e| OsintError::Database(e.to_string()))?,
                    url:          row.get(1).map_err(|e| OsintError::Database(e.to_string()))?,
                    tags:         row.get(2).map_err(|e| OsintError::Database(e.to_string()))?,
                    metadata:     row.get(3).map_err(|e| OsintError::Database(e.to_string()))?,
                    submitted_at: row.get(4).map_err(|e| OsintError::Database(e.to_string()))?,
                    completed_at: row.get(5).map_err(|e| OsintError::Database(e.to_string()))?,
                    status:       row.get(6).map_err(|e| OsintError::Database(e.to_string()))?,
                }
            };

            let result: ResultRow = {
                let mut stmt = guard.prepare(
                    "SELECT job_id, status, confidence, llm_status, llm_confidence,
                            llm_reasoning, scraper_output, completed_at
                     FROM validation_results WHERE job_id = ?",
                ).map_err(|e| OsintError::Database(e.to_string()))?;

                let mut rows = stmt.query(params![id_str])
                    .map_err(|e| OsintError::Database(e.to_string()))?;

                let row = rows.next()
                    .map_err(|e| OsintError::Database(e.to_string()))?
                    .ok_or_else(|| OsintError::NotFound(id_str.clone()))?;

                ResultRow {
                    job_id:         row.get(0).map_err(|e| OsintError::Database(e.to_string()))?,
                    status:         row.get(1).map_err(|e| OsintError::Database(e.to_string()))?,
                    confidence:     row.get(2).map_err(|e| OsintError::Database(e.to_string()))?,
                    llm_status:     row.get(3).map_err(|e| OsintError::Database(e.to_string()))?,
                    llm_confidence: row.get(4).map_err(|e| OsintError::Database(e.to_string()))?,
                    llm_reasoning:  row.get(5).map_err(|e| OsintError::Database(e.to_string()))?,
                    scraper_output: row.get(6).map_err(|e| OsintError::Database(e.to_string()))?,
                    completed_at:   row.get(7).map_err(|e| OsintError::Database(e.to_string()))?,
                }
            };

            let agent_rows: Vec<AgentRow> = {
                let mut stmt = guard.prepare(
                    "SELECT id, job_id, agent_name, passed, confidence_delta, details
                     FROM agent_reports WHERE job_id = ?",
                ).map_err(|e| OsintError::Database(e.to_string()))?;

                let mut rows = stmt.query(params![id_str])
                    .map_err(|e| OsintError::Database(e.to_string()))?;

                let mut agents = Vec::new();
                while let Some(row) = rows.next().map_err(|e| OsintError::Database(e.to_string()))? {
                    let passed: bool = row.get(3).map_err(|e| OsintError::Database(e.to_string()))?;
                    agents.push(AgentRow {
                        id:               row.get(0).map_err(|e| OsintError::Database(e.to_string()))?,
                        job_id:           row.get(1).map_err(|e| OsintError::Database(e.to_string()))?,
                        agent_name:       row.get(2).map_err(|e| OsintError::Database(e.to_string()))?,
                        passed:           if passed { 1 } else { 0 },
                        confidence_delta: row.get(4).map_err(|e| OsintError::Database(e.to_string()))?,
                        details:          row.get(5).map_err(|e| OsintError::Database(e.to_string()))?,
                    });
                }
                agents
            };

            rows_to_result(job, result, agent_rows)
        })
        .await
        .map_err(|e| OsintError::Database(format!("spawn_blocking: {e}")))?
    }

    async fn list(&self, params: ListParams) -> Result<Vec<ValidationResult>, OsintError> {
        let conn = self.conn();
        let limit  = params.limit;
        let offset = params.offset;

        let ids: Vec<String> = tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|e| OsintError::Database(e.to_string()))?;
            let mut stmt = guard.prepare(
                "SELECT id FROM scan_jobs ORDER BY submitted_at DESC LIMIT ? OFFSET ?",
            ).map_err(|e| OsintError::Database(e.to_string()))?;

            let mut rows = stmt.query(params![limit, offset])
                .map_err(|e| OsintError::Database(e.to_string()))?;

            let mut ids = Vec::new();
            while let Some(row) = rows.next().map_err(|e| OsintError::Database(e.to_string()))? {
                ids.push(row.get::<_, String>(0).map_err(|e| OsintError::Database(e.to_string()))?);
            }
            Ok::<_, OsintError>(ids)
        })
        .await
        .map_err(|e| OsintError::Database(format!("spawn_blocking: {e}")))??;

        let mut results = Vec::with_capacity(ids.len());
        for id_str in ids {
            let id = Uuid::parse_str(&id_str)
                .map_err(|e| OsintError::Database(format!("uuid: {e}")))?;
            results.push(self.find_by_id(id).await?);
        }
        Ok(results)
    }

    async fn delete(&self, job_id: Uuid) -> Result<(), OsintError> {
        let id_str = job_id.to_string();
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|e| OsintError::Database(e.to_string()))?;
            guard.execute("DELETE FROM agent_reports      WHERE job_id = ?", params![id_str])
                .map_err(|e| OsintError::Database(e.to_string()))?;
            guard.execute("DELETE FROM validation_results WHERE job_id = ?", params![id_str])
                .map_err(|e| OsintError::Database(e.to_string()))?;
            guard.execute("DELETE FROM scan_jobs          WHERE id      = ?", params![id_str])
                .map_err(|e| OsintError::Database(e.to_string()))?;
            Ok::<_, OsintError>(())
        })
        .await
        .map_err(|e| OsintError::Database(format!("spawn_blocking: {e}")))?
    }

    async fn count(&self) -> Result<i64, OsintError> {
        let conn = self.conn();
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|e| OsintError::Database(e.to_string()))?;
            let mut stmt = guard.prepare("SELECT COUNT(*) FROM scan_jobs")
                .map_err(|e| OsintError::Database(e.to_string()))?;
            let mut rows = stmt.query([])
                .map_err(|e| OsintError::Database(e.to_string()))?;
            let row = rows.next()
                .map_err(|e| OsintError::Database(e.to_string()))?
                .ok_or_else(|| OsintError::Database("count returned no rows".into()))?;
            row.get::<_, i64>(0).map_err(|e| OsintError::Database(e.to_string()))
        })
        .await
        .map_err(|e| OsintError::Database(format!("spawn_blocking: {e}")))?
    }

    async fn save_discovery(&self, result: &DiscoveryResult) -> Result<(), OsintError> {
        let (job, urls) = discovery_to_rows(result)?;
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|e| OsintError::Database(e.to_string()))?;

            guard.execute(
                "INSERT OR REPLACE INTO discovery_jobs
                 (job_id, request_json, total_discovered, completed_at)
                 VALUES (?, ?, ?, ?)",
                params![job.job_id, job.request_json, job.total_discovered, job.completed_at],
            ).map_err(|e| OsintError::Database(e.to_string()))?;

            guard.execute(
                "DELETE FROM discovered_urls WHERE job_id = ?",
                params![job.job_id],
            ).map_err(|e| OsintError::Database(e.to_string()))?;

            for url in &urls {
                guard.execute(
                    "INSERT INTO discovered_urls (id, job_id, payload) VALUES (?, ?, ?)",
                    params![url.id, url.job_id, url.payload],
                ).map_err(|e| OsintError::Database(e.to_string()))?;
            }

            Ok::<_, OsintError>(())
        })
        .await
        .map_err(|e| OsintError::Database(format!("spawn_blocking: {e}")))?
    }

    async fn find_discovery_by_id(&self, job_id: Uuid) -> Result<DiscoveryResult, OsintError> {
        let id_str = job_id.to_string();
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|e| OsintError::Database(e.to_string()))?;

            let job: DiscoveryJobRow = {
                let mut stmt = guard.prepare(
                    "SELECT job_id, request_json, total_discovered, completed_at
                     FROM discovery_jobs WHERE job_id = ?",
                ).map_err(|e| OsintError::Database(e.to_string()))?;

                let mut rows = stmt.query(params![id_str])
                    .map_err(|e| OsintError::Database(e.to_string()))?;

                let row = rows.next()
                    .map_err(|e| OsintError::Database(e.to_string()))?
                    .ok_or_else(|| OsintError::NotFound(id_str.clone()))?;

                DiscoveryJobRow {
                    job_id:           row.get(0).map_err(|e| OsintError::Database(e.to_string()))?,
                    request_json:     row.get(1).map_err(|e| OsintError::Database(e.to_string()))?,
                    total_discovered: row.get(2).map_err(|e| OsintError::Database(e.to_string()))?,
                    completed_at:     row.get(3).map_err(|e| OsintError::Database(e.to_string()))?,
                }
            };

            let url_rows: Vec<DiscoveredUrlRow> = {
                let mut stmt = guard.prepare(
                    "SELECT id, job_id, payload FROM discovered_urls WHERE job_id = ?",
                ).map_err(|e| OsintError::Database(e.to_string()))?;

                let mut rows = stmt.query(params![id_str])
                    .map_err(|e| OsintError::Database(e.to_string()))?;

                let mut items = Vec::new();
                while let Some(row) = rows.next().map_err(|e| OsintError::Database(e.to_string()))? {
                    items.push(DiscoveredUrlRow {
                        id:      row.get(0).map_err(|e| OsintError::Database(e.to_string()))?,
                        job_id:  row.get(1).map_err(|e| OsintError::Database(e.to_string()))?,
                        payload: row.get(2).map_err(|e| OsintError::Database(e.to_string()))?,
                    });
                }
                items
            };

            rows_to_discovery(job, url_rows)
        })
        .await
        .map_err(|e| OsintError::Database(format!("spawn_blocking: {e}")))?
    }

    async fn list_discoveries(&self, params: ListParams) -> Result<Vec<DiscoveryResult>, OsintError> {
        let conn = self.conn();
        let limit  = params.limit;
        let offset = params.offset;

        let ids: Vec<String> = tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|e| OsintError::Database(e.to_string()))?;
            let mut stmt = guard.prepare(
                "SELECT job_id FROM discovery_jobs ORDER BY completed_at DESC LIMIT ? OFFSET ?",
            ).map_err(|e| OsintError::Database(e.to_string()))?;

            let mut rows = stmt.query(params![limit, offset])
                .map_err(|e| OsintError::Database(e.to_string()))?;

            let mut ids = Vec::new();
            while let Some(row) = rows.next().map_err(|e| OsintError::Database(e.to_string()))? {
                ids.push(row.get::<_, String>(0).map_err(|e| OsintError::Database(e.to_string()))?);
            }
            Ok::<_, OsintError>(ids)
        })
        .await
        .map_err(|e| OsintError::Database(format!("spawn_blocking: {e}")))??;

        let mut results = Vec::with_capacity(ids.len());
        for id_str in ids {
            let id = Uuid::parse_str(&id_str)
                .map_err(|e| OsintError::Database(format!("uuid: {e}")))?;
            results.push(self.find_discovery_by_id(id).await?);
        }
        Ok(results)
    }

    async fn discovery_count(&self) -> Result<i64, OsintError> {
        let conn = self.conn();
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|e| OsintError::Database(e.to_string()))?;
            let mut stmt = guard.prepare("SELECT COUNT(*) FROM discovery_jobs")
                .map_err(|e| OsintError::Database(e.to_string()))?;
            let mut rows = stmt.query([])
                .map_err(|e| OsintError::Database(e.to_string()))?;
            let row = rows.next()
                .map_err(|e| OsintError::Database(e.to_string()))?
                .ok_or_else(|| OsintError::Database("count returned no rows".into()))?;
            row.get::<_, i64>(0).map_err(|e| OsintError::Database(e.to_string()))
        })
        .await
        .map_err(|e| OsintError::Database(format!("spawn_blocking: {e}")))?
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_store_round_trips_count() {
        let store = DuckDbStore::connect(":memory:").unwrap();
        assert_eq!(store.count().await.unwrap(), 0);
        assert_eq!(store.discovery_count().await.unwrap(), 0);
    }
}
