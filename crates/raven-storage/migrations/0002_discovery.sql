-- Migration 0002: discovery persistence

CREATE TABLE IF NOT EXISTS discovery_jobs (
    job_id            TEXT        NOT NULL PRIMARY KEY,
    request_json      TEXT        NOT NULL,
    total_discovered  INTEGER     NOT NULL DEFAULT 0,
    completed_at      TEXT        NOT NULL
);

CREATE TABLE IF NOT EXISTS discovered_urls (
    id         TEXT        NOT NULL PRIMARY KEY,
    job_id     TEXT        NOT NULL REFERENCES discovery_jobs(job_id),
    payload     TEXT       NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_discovered_urls_job_id ON discovered_urls(job_id);
CREATE INDEX IF NOT EXISTS idx_discovery_jobs_completed_at ON discovery_jobs(completed_at);