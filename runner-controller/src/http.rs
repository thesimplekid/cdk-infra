use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use tokio::sync::watch;
use tracing::info;

use crate::state::StateDb;

#[derive(Clone)]
pub struct AppState {
    pub state_db: Arc<StateDb>,
    pub start_time: Instant,
    pub pool_size: usize,
    pub poll_interval_seconds: u64,
    pub job_timeout_seconds: u64,
    pub runner_startup_timeout_seconds: u64,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub pool_size: usize,
    pub active_containers: usize,
    pub containers: Vec<ContainerInfo>,
    pub poll_interval_seconds: u64,
    pub job_timeout_seconds: u64,
    pub runner_startup_timeout_seconds: u64,
    pub uptime_seconds: u64,
}

#[derive(Serialize)]
pub struct ContainerInfo {
    pub name: String,
    pub slot: usize,
    pub running_seconds: u64,
    pub busy_seconds: Option<u64>,
}

/// GET /health - simple health check
async fn health() -> impl IntoResponse {
    StatusCode::OK
}

/// GET /status - JSON status of pool containers
async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let db_containers = match state.state_db.list_containers() {
        Ok(c) => c,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to list containers")
                .into_response()
        }
    };

    let containers: Vec<ContainerInfo> = db_containers
        .into_iter()
        .map(|(name, container_state)| ContainerInfo {
            name,
            slot: container_state.slot,
            running_seconds: container_state.running_seconds(),
            busy_seconds: container_state.busy_seconds(),
        })
        .collect();

    let response = StatusResponse {
        pool_size: state.pool_size,
        active_containers: containers.len(),
        containers,
        poll_interval_seconds: state.poll_interval_seconds,
        job_timeout_seconds: state.job_timeout_seconds,
        runner_startup_timeout_seconds: state.runner_startup_timeout_seconds,
        uptime_seconds: state.start_time.elapsed().as_secs(),
    };

    Json(response).into_response()
}

pub async fn run_server(
    addr: SocketAddr,
    state: AppState,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .with_state(state);

    info!(addr = %addr, "Starting HTTP server");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "Failed to bind HTTP server");
            return;
        }
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            loop {
                if shutdown_rx.changed().await.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            info!("HTTP server shutting down");
        })
        .await
        .ok();
}
