//! raven-api — Axum REST API.

pub mod pipeline;
pub mod routes;
pub mod state;

use axum::{routing::get, Router};
use state::AppState;
use std::{net::SocketAddr, sync::Arc};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
	paths(
		crate::routes::health::health,
		crate::routes::scan::submit_scan,
		crate::routes::discovery::submit_discovery,
		crate::routes::discovery::get_discovery,
		crate::routes::discovery::list_discoveries,
		crate::routes::results::get_result,
		crate::routes::results::list_results
	),
	components(
		schemas(
			raven_core::DiscoveryProviderKind,
			raven_core::DiscoveryType,
			raven_core::DiscoveredUrl,
			raven_core::DiscoveryRequest,
			raven_core::DiscoveryResult,
			raven_core::SiteStatus,
			raven_core::OsintTarget,
			raven_core::ScraperOutput,
			raven_core::AgentReport,
			raven_core::LlmVerdict,
			raven_core::ValidationResult,
			crate::pipeline::DiscoveryWorkflowResult,
			crate::routes::discovery::DiscoverRequest,
			crate::routes::discovery::DiscoveryAccepted,
			crate::routes::discovery::DiscoveriesPage,
			crate::routes::scan::ScanRequest,
			crate::routes::scan::ScanAccepted,
			crate::routes::results::ResultsPage,
			crate::routes::health::HealthResponse,
		)
	),
	tags(
		(name = "raven-api", description = "RavenOSINT API")
	)
)]
pub struct ApiDoc;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(routes::health::health))
        .route(
            "/discover",
            axum::routing::post(routes::discovery::submit_discovery),
        )
        .route("/discoveries", get(routes::discovery::list_discoveries))
        .route(
            "/discoveries/:job_id",
            get(routes::discovery::get_discovery),
        )
        .route("/scan", axum::routing::post(routes::scan::submit_scan))
        .route("/results", get(routes::results::list_results))
        .route("/results/:job_id", get(routes::results::get_result))
        .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

pub async fn serve(state: Arc<AppState>, addr: SocketAddr) -> Result<(), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router(state)).await
}
