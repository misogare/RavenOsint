use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use raven_core::OsintTarget;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Deserialize, ToSchema)]
pub struct ScanRequest {
    pub url: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScanAccepted {
    pub job_id: Uuid,
    pub status: &'static str,
    pub target: OsintTarget,
    pub note: &'static str,
}

#[utoipa::path(
    post,
    path = "/scan",
    tag = "raven-api",
    request_body = ScanRequest,
    responses(
        (status = 202, description = "Target accepted for scanning", body = ScanAccepted)
    )
)]
pub async fn submit_scan(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> (StatusCode, Json<ScanAccepted>) {
    let job_id = Uuid::new_v4();
    let target = OsintTarget {
        id: job_id,
        url: req.url,
        tags: req.tags,
        metadata: req.metadata,
        submitted_at: Utc::now(),
    };

    let workflow = Arc::clone(&state.workflow);
    let target_for_task = target.clone();
    tokio::spawn(async move {
        info!(job_id = %target_for_task.id, url = %target_for_task.url, "api: scan task started");
        if let Err(error) = workflow.validate_target(target_for_task).await {
            error!(job_id = %job_id, error = %error, "api: scan task failed");
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(ScanAccepted {
            job_id,
            status: "queued",
            target,
            note: "Pipeline execution has started in the background.",
        }),
    )
}
