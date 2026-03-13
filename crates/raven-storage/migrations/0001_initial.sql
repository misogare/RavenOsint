-- Migration 0001: initial schema
-- Supports both SQLite and PostgreSQL

CREATE TABLE IF NOT EXISTS scan_jobs (
    id           TEXT        NOT NULL PRIMARY KEY,  -- UUID as text
    url          TEXT        NOT NULL,
    tags         TEXT        NOT NULL DEFAULT '[]', -- JSON array
    metadata     TEXT        NOT NULL DEFAULT '{}', -- JSON object
    submitted_at TEXT        NOT NULL,              -- ISO-8601
    completed_at TEXT,                              -- NULL while in-flight
    status       TEXT        NOT NULL DEFAULT 'unknown'
);

CREATE TABLE IF NOT EXISTS validation_results (
    job_id          TEXT    NOT NULL PRIMARY KEY REFERENCES scan_jobs(id),
    status          TEXT    NOT NULL DEFAULT 'unknown',
    confidence      REAL    NOT NULL DEFAULT 0.0,
    llm_status      TEXT    NOT NULL DEFAULT 'unknown',
    llm_confidence  REAL    NOT NULL DEFAULT 0.0,
    llm_reasoning   TEXT    NOT NULL DEFAULT '',
    scraper_output  TEXT,   -- JSON blob (nullable: scrape may have failed)
    completed_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_reports (
    id               TEXT    NOT NULL PRIMARY KEY,  -- UUID
    job_id           TEXT    NOT NULL REFERENCES scan_jobs(id),
    agent_name       TEXT    NOT NULL,
    passed           INTEGER NOT NULL DEFAULT 0,    -- 0/1 boolean
    confidence_delta REAL    NOT NULL DEFAULT 0.0,
    details          TEXT    NOT NULL DEFAULT '{}'  -- JSON object
);

CREATE INDEX IF NOT EXISTS idx_agent_reports_job_id ON agent_reports(job_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status     ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_url        ON scan_jobs(url);
