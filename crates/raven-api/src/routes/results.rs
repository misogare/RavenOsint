use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use raven_storage::ListParams;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Deserialize, IntoParams)]
pub struct ResultsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ResultsPage {
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
    pub items: Vec<raven_core::ValidationResult>,
}

fn default_limit() -> i64 {
    50
}

#[utoipa::path(
    get,
    path = "/results",
    tag = "raven-api",
    params(ResultsQuery),
    responses(
        (status = 200, description = "List stored validation results", body = ResultsPage),
        (status = 500, description = "Storage error")
    )
)]
pub async fn list_results(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ResultsQuery>,
) -> Result<Json<ResultsPage>, (StatusCode, String)> {
    let params = ListParams {
        limit: query.limit.clamp(1, 250),
        offset: query.offset.max(0),
    };

    let total = state
        .store
        .count()
        .await
        .map_err(internal_error)?;
    let items = state
        .store
        .list(params.clone())
        .await
        .map_err(internal_error)?;

    Ok(Json(ResultsPage {
        total,
        limit: params.limit,
        offset: params.offset,
        items,
    }))
}

#[utoipa::path(
    get,
    path = "/results/{job_id}",
    tag = "raven-api",
    params(("job_id" = String, Path, description = "Validation result job UUID")),
    responses(
        (status = 200, description = "Single validation result", body = raven_core::ValidationResult),
        (status = 404, description = "Result not found"),
        (status = 500, description = "Storage error")
    )
)]
pub async fn get_result(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<raven_core::ValidationResult>, (StatusCode, String)> {
    state
        .store
        .find_by_id(job_id)
        .await
        .map(Json)
        .map_err(map_result_error)
}

fn map_result_error(error: raven_core::OsintError) -> (StatusCode, String) {
    match error {
        raven_core::OsintError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        other => internal_error(other),
    }
}

fn internal_error(error: raven_core::OsintError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}
