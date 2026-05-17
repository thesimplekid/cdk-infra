use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use tokio::sync::watch;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod container;
mod github;
mod http;
mod listener;
mod state;

use config::Config;
use container::ContainerManager;
use github::GitHubClient;
use http::AppState;
use listener::PoolController;
use state::StateDb;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("runner-controller (warm pool mode) starting");

    let start_time = Instant::now();

    // Load configuration
    let config = Config::from_env()?;
    tracing::info!(
        repo = %config.github_repo,
        pool_size = config.max_concurrent_jobs,
        poll_interval = ?config.poll_interval,
        runner_startup_timeout = ?config.runner_startup_timeout,
        labels = ?config.runner_labels,
        http_port = config.http_port,
        "Configuration loaded"
    );

    // Initialize state database
    let state_db = Arc::new(StateDb::open(&config.state_dir)?);
    tracing::info!(state_dir = ?config.state_dir, "State database opened");

    // Initialize GitHub client
    let github = GitHubClient::new(config.github_repo.clone(), config.github_token.clone())?;
    tracing::info!("GitHub client initialized");

    // Quick connectivity check
    match github.list_runners().await {
        Ok(runners) => {
            tracing::info!(count = runners.len(), "Connected to GitHub API");
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list runners (will retry in main loop)");
        }
    }

    // Initialize container manager
    let containers = Arc::new(ContainerManager::new(config.state_dir.clone()));
    tracing::info!("Container manager initialized");

    // Set up shutdown signal
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Start HTTP server
    let http_state = AppState {
        state_db: Arc::clone(&state_db),
        start_time,
        pool_size: config.max_concurrent_jobs,
        poll_interval_seconds: config.poll_interval.as_secs(),
        job_timeout_seconds: config.job_timeout.as_secs(),
        runner_startup_timeout_seconds: config.runner_startup_timeout.as_secs(),
    };
    let http_addr: SocketAddr = ([0, 0, 0, 0], config.http_port).into();
    let http_shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(http::run_server(http_addr, http_state, http_shutdown_rx));

    // Create pool controller
    let mut controller = PoolController::new(
        config.clone(),
        github,
        Arc::clone(&containers),
        Arc::clone(&state_db),
        shutdown_rx,
    );

    // Spawn signal handler
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to create SIGTERM handler");
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("Failed to create SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                tracing::info!("Received SIGINT");
            }
        }

        let _ = shutdown_tx_clone.send(true);
    });

    // Run the main loop
    let result = controller.run().await;

    // Graceful shutdown
    controller.shutdown().await?;

    tracing::info!("runner-controller stopped");

    result
}
