use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub github_repo: String,
    pub github_token: String,
    pub max_concurrent_jobs: usize,
    pub poll_interval: Duration,
    pub job_timeout: Duration,
    pub runner_startup_timeout: Duration,
    pub runner_labels: Vec<String>,
    pub state_dir: PathBuf,
    pub http_port: u16,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let github_repo = std::env::var("GITHUB_REPO")
            .context("GITHUB_REPO environment variable is required")?;

        let github_token_file = std::env::var("GITHUB_TOKEN_FILE")
            .context("GITHUB_TOKEN_FILE environment variable is required")?;

        let github_token = std::fs::read_to_string(&github_token_file)
            .with_context(|| format!("Failed to read GitHub token from {}", github_token_file))?
            .trim()
            .to_string();

        let max_concurrent_jobs = std::env::var("MAX_CONCURRENT")
            .unwrap_or_else(|_| "7".to_string())
            .parse()
            .context("MAX_CONCURRENT must be a valid number")?;

        let poll_interval_secs: u64 = std::env::var("POLL_INTERVAL")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .context("POLL_INTERVAL must be a valid number")?;

        let job_timeout_secs: u64 = std::env::var("JOB_TIMEOUT")
            .unwrap_or_else(|_| "7200".to_string())
            .parse()
            .context("JOB_TIMEOUT must be a valid number")?;

        let runner_startup_timeout_secs: u64 = std::env::var("RUNNER_STARTUP_TIMEOUT")
            .unwrap_or_else(|_| "600".to_string())
            .parse()
            .context("RUNNER_STARTUP_TIMEOUT must be a valid number")?;

        let runner_labels = std::env::var("RUNNER_LABELS")
            .unwrap_or_else(|_| "self-hosted,ci,nix,x64,Linux".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let state_dir = std::env::var("STATE_DIR")
            .unwrap_or_else(|_| "/var/lib/runner-controller".to_string())
            .into();

        let http_port = std::env::var("HTTP_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .context("HTTP_PORT must be a valid port number")?;

        Ok(Config {
            github_repo,
            github_token,
            max_concurrent_jobs,
            poll_interval: Duration::from_secs(poll_interval_secs),
            job_timeout: Duration::from_secs(job_timeout_secs),
            runner_startup_timeout: Duration::from_secs(runner_startup_timeout_secs),
            runner_labels,
            state_dir,
            http_port,
        })
    }
}
