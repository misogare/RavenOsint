//! SQLite backend for `ResultStore`.

use crate::{
    model::{
        discovery_to_rows, result_to_rows, rows_to_discovery, rows_to_result, AgentRow,
        DiscoveredUrlRow, DiscoveryJobRow, JobRow, ResultRow,
    },
    store::{ListParams, ResultStore},
};
use async_trait::async_trait;
use raven_core::{DiscoveryResult, OsintError, ValidationResult};
use sqlx::{migrate::MigrateDatabase, sqlite::SqlitePoolOptions, Row, SqlitePool};
use tracing::info;
use uuid::Uuid;

pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Connect (creating the DB file if needed) and run migrations.
    pub async fn connect(url: &str) -> Result<Self, OsintError> {
        // Create database file if it doesn't exist.
        if !sqlx::Sqlite::database_exists(url).await.unwrap_or(false) {
            sqlx::Sqlite::create_database(url)
                .await
                .map_err(|e| OsintError::Database(e.to_string()))?;
        }

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(url)
            .await
            .map_err(|e| OsintError::Database(e.to_string()))?;

        // Run embedded migrations.
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| OsintError::Database(format!("migration: {e}")))?;

        info!(db = %url, "SQLite connected and migrated");
        Ok(Self { pool })
    }
}

#[async_trait]
impl ResultStore for SqliteStore {
    async fn save(&self, result: &ValidationResult) -> Result<(), OsintError> {
        let (job, res, agents) = result_to_rows(result)?;

        // Upsert scan_jobs.
        sqlx::query(
            "INSERT INTO scan_jobs (id, url, tags, metadata, submitted_at, completed_at, status)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
               completed_at = excluded.completed_at,
               status       = excluded.status",
        )
        .bind(&job.id)
        .bind(&job.url)
        .bind(&job.tags)
        .bind(&job.metadata)
        .bind(&job.submitted_at)
        .bind(&job.completed_at)
        .bind(&job.status)
        .execute(&self.pool)
        .await
        .map_err(|e| OsintError::Database(e.to_string()))?;

        // Upsert validation_results.
        sqlx::query(
            "INSERT INTO validation_results
               (job_id, status, confidence, llm_status, llm_confidence, llm_reasoning, scraper_output, completed_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(job_id) DO UPDATE SET
               status         = excluded.status,
               confidence     = excluded.confidence,
               llm_status     = excluded.llm_status,
               llm_confidence = excluded.llm_confidence,
               llm_reasoning  = excluded.llm_reasoning,
               scraper_output = excluded.scraper_output,
               completed_at   = excluded.completed_at",
        )
        .bind(&res.job_id)
        .bind(&res.status)
        .bind(res.confidence)
        .bind(&res.llm_status)
        .bind(res.llm_confidence)
        .bind(&res.llm_reasoning)
        .bind(&res.scraper_output)
        .bind(&res.completed_at)
        .execute(&self.pool)
        .await
        .map_err(|e| OsintError::Database(e.to_string()))?;

        // Delete old agent_reports for this job then re-insert.
        sqlx::query("DELETE FROM agent_reports WHERE job_id = ?")
            .bind(&job.id)
            .execute(&self.pool)
            .await
            .map_err(|e| OsintError::Database(e.to_string()))?;

        for ar in &agents {
            sqlx::query(
                "INSERT INTO agent_reports (id, job_id, agent_name, passed, confidence_delta, details)
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(&ar.id)
            .bind(&ar.job_id)
            .bind(&ar.agent_name)
            .bind(ar.passed)
            .bind(ar.confidence_delta)
            .bind(&ar.details)
            .execute(&self.pool)
            .await
            .map_err(|e| OsintError::Database(e.to_string()))?;
        }

        Ok(())
    }

    async fn find_by_id(&self, job_id: Uuid) -> Result<ValidationResult, OsintError> {
        let id_str = job_id.to_string();

        let job_row = sqlx::query(
            "SELECT id, url, tags, metadata, submitted_at, completed_at, status
             FROM scan_jobs WHERE id = ?",
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| OsintError::Database(e.to_string()))?
        .ok_or_else(|| OsintError::NotFound(id_str.clone()))?;

        let result_row = sqlx::query(
            "SELECT job_id, status, confidence, llm_status, llm_confidence,
                    llm_reasoning, scraper_output, completed_at
             FROM validation_results WHERE job_id = ?",
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| OsintError::Database(e.to_string()))?
        .ok_or_else(|| OsintError::NotFound(id_str.clone()))?;

        let agent_rows: Vec<_> = sqlx::query(
            "SELECT id, job_id, agent_name, passed, confidence_delta, details
             FROM agent_reports WHERE job_id = ? ORDER BY rowid ASC",
        )
        .bind(&id_str)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| OsintError::Database(e.to_string()))?;

        let job = JobRow {
            id: job_row
                .try_get("id")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            url: job_row
                .try_get("url")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            tags: job_row
                .try_get("tags")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            metadata: job_row
                .try_get("metadata")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            submitted_at: job_row
                .try_get("submitted_at")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            completed_at: job_row
                .try_get("completed_at")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            status: job_row
                .try_get("status")
                .map_err(|e| OsintError::Database(e.to_string()))?,
        };

        let res = ResultRow {
            job_id: result_row
                .try_get("job_id")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            status: result_row
                .try_get("status")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            confidence: result_row
                .try_get("confidence")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            llm_status: result_row
                .try_get("llm_status")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            llm_confidence: result_row
                .try_get("llm_confidence")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            llm_reasoning: result_row
                .try_get("llm_reasoning")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            scraper_output: result_row
                .try_get("scraper_output")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            completed_at: result_row
                .try_get("completed_at")
                .map_err(|e| OsintError::Database(e.to_string()))?,
        };

        let agents: Vec<AgentRow> = agent_rows
            .iter()
            .map(|r| -> Result<AgentRow, OsintError> {
                Ok(AgentRow {
                    id: r
                        .try_get("id")
                        .map_err(|e| OsintError::Database(e.to_string()))?,
                    job_id: r
                        .try_get("job_id")
                        .map_err(|e| OsintError::Database(e.to_string()))?,
                    agent_name: r
                        .try_get("agent_name")
                        .map_err(|e| OsintError::Database(e.to_string()))?,
                    passed: r
                        .try_get("passed")
                        .map_err(|e| OsintError::Database(e.to_string()))?,
                    confidence_delta: r
                        .try_get("confidence_delta")
                        .map_err(|e| OsintError::Database(e.to_string()))?,
                    details: r
                        .try_get("details")
                        .map_err(|e| OsintError::Database(e.to_string()))?,
                })
            })
            .collect::<Result<_, _>>()?;

        rows_to_result(job, res, agents)
    }

    async fn list(&self, params: ListParams) -> Result<Vec<ValidationResult>, OsintError> {
        let rows =
            sqlx::query("SELECT id FROM scan_jobs ORDER BY submitted_at DESC LIMIT ? OFFSET ?")
                .bind(params.limit)
                .bind(params.offset)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| OsintError::Database(e.to_string()))?;

        let mut results = Vec::with_capacity(rows.len());
        for row in &rows {
            let id_str: String = row
                .try_get("id")
                .map_err(|e| OsintError::Database(e.to_string()))?;
            let id =
                Uuid::parse_str(&id_str).map_err(|e| OsintError::Database(format!("uuid: {e}")))?;
            results.push(self.find_by_id(id).await?);
        }
        Ok(results)
    }

    async fn delete(&self, job_id: Uuid) -> Result<(), OsintError> {
        let id = job_id.to_string();
        sqlx::query("DELETE FROM agent_reports WHERE job_id = ?")
            .bind(&id)
            .execute(&self.pool)
            .await
            .map_err(|e| OsintError::Database(e.to_string()))?;
        sqlx::query("DELETE FROM validation_results WHERE job_id = ?")
            .bind(&id)
            .execute(&self.pool)
            .await
            .map_err(|e| OsintError::Database(e.to_string()))?;
        sqlx::query("DELETE FROM scan_jobs WHERE id = ?")
            .bind(&id)
            .execute(&self.pool)
            .await
            .map_err(|e| OsintError::Database(e.to_string()))?;
        Ok(())
    }

    async fn count(&self) -> Result<i64, OsintError> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM scan_jobs")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| OsintError::Database(e.to_string()))?;
        let cnt: i64 = row
            .try_get("cnt")
            .map_err(|e| OsintError::Database(e.to_string()))?;
        Ok(cnt)
    }

    async fn save_discovery(&self, result: &DiscoveryResult) -> Result<(), OsintError> {
        let (job, urls) = discovery_to_rows(result)?;

        sqlx::query(
            "INSERT INTO discovery_jobs (job_id, request_json, total_discovered, completed_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(job_id) DO UPDATE SET
               request_json = excluded.request_json,
               total_discovered = excluded.total_discovered,
               completed_at = excluded.completed_at",
        )
        .bind(&job.job_id)
        .bind(&job.request_json)
        .bind(job.total_discovered)
        .bind(&job.completed_at)
        .execute(&self.pool)
        .await
        .map_err(|e| OsintError::Database(e.to_string()))?;

        sqlx::query("DELETE FROM discovered_urls WHERE job_id = ?")
            .bind(&job.job_id)
            .execute(&self.pool)
            .await
            .map_err(|e| OsintError::Database(e.to_string()))?;

        for url in &urls {
            sqlx::query(
                "INSERT INTO discovered_urls (id, job_id, payload)
                 VALUES (?, ?, ?)",
            )
            .bind(&url.id)
            .bind(&url.job_id)
            .bind(&url.payload)
            .execute(&self.pool)
            .await
            .map_err(|e| OsintError::Database(e.to_string()))?;
        }

        Ok(())
    }

    async fn find_discovery_by_id(&self, job_id: Uuid) -> Result<DiscoveryResult, OsintError> {
        let id_str = job_id.to_string();

        let job_row = sqlx::query(
            "SELECT job_id, request_json, total_discovered, completed_at
             FROM discovery_jobs WHERE job_id = ?",
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| OsintError::Database(e.to_string()))?
        .ok_or_else(|| OsintError::NotFound(id_str.clone()))?;

        let url_rows = sqlx::query(
            "SELECT id, job_id, payload
             FROM discovered_urls WHERE job_id = ? ORDER BY rowid ASC",
        )
        .bind(&id_str)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| OsintError::Database(e.to_string()))?;

        let job = DiscoveryJobRow {
            job_id: job_row
                .try_get("job_id")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            request_json: job_row
                .try_get("request_json")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            total_discovered: job_row
                .try_get("total_discovered")
                .map_err(|e| OsintError::Database(e.to_string()))?,
            completed_at: job_row
                .try_get("completed_at")
                .map_err(|e| OsintError::Database(e.to_string()))?,
        };

        let urls: Vec<DiscoveredUrlRow> = url_rows
            .iter()
            .map(|row| -> Result<DiscoveredUrlRow, OsintError> {
                Ok(DiscoveredUrlRow {
                    id: row
                        .try_get("id")
                        .map_err(|e| OsintError::Database(e.to_string()))?,
                    job_id: row
                        .try_get("job_id")
                        .map_err(|e| OsintError::Database(e.to_string()))?,
                    payload: row
                        .try_get("payload")
                        .map_err(|e| OsintError::Database(e.to_string()))?,
                })
            })
            .collect::<Result<_, _>>()?;

        rows_to_discovery(job, urls)
    }

    async fn list_discoveries(
        &self,
        params: ListParams,
    ) -> Result<Vec<DiscoveryResult>, OsintError> {
        let rows = sqlx::query(
            "SELECT job_id FROM discovery_jobs ORDER BY completed_at DESC LIMIT ? OFFSET ?",
        )
        .bind(params.limit)
        .bind(params.offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| OsintError::Database(e.to_string()))?;

        let mut results = Vec::with_capacity(rows.len());
        for row in &rows {
            let id_str: String = row
                .try_get("job_id")
                .map_err(|e| OsintError::Database(e.to_string()))?;
            let id =
                Uuid::parse_str(&id_str).map_err(|e| OsintError::Database(format!("uuid: {e}")))?;
            results.push(self.find_discovery_by_id(id).await?);
        }

        Ok(results)
    }

    async fn discovery_count(&self) -> Result<i64, OsintError> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM discovery_jobs")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| OsintError::Database(e.to_string()))?;
        let cnt: i64 = row
            .try_get("cnt")
            .map_err(|e| OsintError::Database(e.to_string()))?;
        Ok(cnt)
    }
}
