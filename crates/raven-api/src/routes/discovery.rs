use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use raven_core::{DiscoveryProviderKind, DiscoveryRequest, DiscoveryResult, OsintError};
use raven_storage::ListParams;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tracing::{error, info};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Deserialize, ToSchema)]
pub struct DiscoverRequest {
    pub query: String,
    #[serde(default)]
    pub site: Option<String>,
    #[serde(default)]
    pub provider: Option<DiscoveryProviderKind>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub lang: Option<String>,
    #[serde(default = "default_include_subdomains")]
    pub include_subdomains: bool,
    #[serde(default)]
    pub validate: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DiscoveryAccepted {
    pub job_id: Uuid,
    pub status: &'static str,
    pub provider: DiscoveryProviderKind,
    pub validate: bool,
    pub note: &'static str,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct DiscoveriesQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DiscoveriesPage {
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
    pub items: Vec<DiscoveryResult>,
}

fn default_limit() -> i64 {
    50
}

fn default_include_subdomains() -> bool {
    true
}

#[utoipa::path(
    post,
    path = "/discover",
    tag = "raven-api",
    request_body = DiscoverRequest,
    responses(
        (status = 202, description = "Discovery request accepted", body = DiscoveryAccepted)
    )
)]
pub async fn submit_discovery(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DiscoverRequest>,
) -> (StatusCode, Json<DiscoveryAccepted>) {
    let mut request = DiscoveryRequest::new(req.query);
    request.site = req.site;
    request.provider = req.provider.unwrap_or_default();
    request.limit = req.limit.unwrap_or(request.limit).clamp(1, 250);
    request.country = req.country;
    request.lang = req.lang;
    request.include_subdomains = req.include_subdomains;
    request.validate = req.validate;

    let workflow = Arc::clone(&state.workflow);
    let request_for_task = request.clone();
    let tags = req.tags;
    let metadata = req.metadata;

    tokio::spawn(async move {
        info!(job_id = %request_for_task.job_id, provider = ?request_for_task.provider, validate = request_for_task.validate, "api: discovery task started");
        let outcome = if request_for_task.validate {
            workflow
                .discover_and_validate(request_for_task.clone(), tags, metadata)
                .await
                .map(|_| ())
        } else {
            workflow
                .discover(request_for_task.clone())
                .await
                .map(|_| ())
        };

        if let Err(error) = outcome {
            error!(job_id = %request_for_task.job_id, error = %error, "api: discovery task failed");
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(DiscoveryAccepted {
            job_id: request.job_id,
            status: "queued",
            provider: request.provider,
            validate: request.validate,
            note: "Discovery execution has started in the background.",
        }),
    )
}

#[utoipa::path(
    get,
    path = "/discoveries",
    tag = "raven-api",
    params(DiscoveriesQuery),
    responses(
        (status = 200, description = "List stored discovery results", body = DiscoveriesPage),
        (status = 500, description = "Storage error")
    )
)]
pub async fn list_discoveries(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DiscoveriesQuery>,
) -> Result<Json<DiscoveriesPage>, (StatusCode, String)> {
    let params = ListParams {
        limit: query.limit.clamp(1, 250),
        offset: query.offset.max(0),
    };

    let total = state
        .store
        .discovery_count()
        .await
        .map_err(internal_error)?;
    let items = state
        .store
        .list_discoveries(params.clone())
        .await
        .map_err(internal_error)?;

    Ok(Json(DiscoveriesPage {
        total,
        limit: params.limit,
        offset: params.offset,
        items,
    }))
}

#[utoipa::path(
    get,
    path = "/discoveries/{job_id}",
    tag = "raven-api",
    params(("job_id" = String, Path, description = "Discovery result job UUID")),
    responses(
        (status = 200, description = "Single discovery result", body = DiscoveryResult),
        (status = 404, description = "Result not found"),
        (status = 500, description = "Storage error")
    )
)]
pub async fn get_discovery(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<DiscoveryResult>, (StatusCode, String)> {
    state
        .store
        .find_discovery_by_id(job_id)
        .await
        .map(Json)
        .map_err(map_result_error)
}

fn map_result_error(error: OsintError) -> (StatusCode, String) {
    match error {
        OsintError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        other => internal_error(other),
    }
}

fn internal_error(error: OsintError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}
