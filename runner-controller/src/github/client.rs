use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use tracing::{debug, warn};

use super::types::*;

const GITHUB_API_BASE: &str = "https://api.github.com";
const MAX_RETRIES: u32 = 3;
const INITIAL_BACKOFF_MS: u64 = 1000;

pub struct GitHubClient {
    client: Client,
    repo: String,
    token: String,
}

impl GitHubClient {
    pub fn new(repo: String, token: String) -> Result<Self> {
        let client = Client::builder()
            .user_agent("runner-controller/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            repo,
            token,
        })
    }

    /// Make a GET request with retries and exponential backoff
    async fn get<T: serde::de::DeserializeOwned>(&self, endpoint: &str) -> Result<T> {
        let url = format!("{}{}", GITHUB_API_BASE, endpoint);
        let mut backoff_ms = INITIAL_BACKOFF_MS;

        for attempt in 1..=MAX_RETRIES {
            debug!(url = %url, attempt, "GitHub API request");

            let response = self
                .client
                .get(&url)
                .header("Authorization", format!("token {}", self.token))
                .header("Accept", "application/vnd.github.v3+json")
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();

                    // Check rate limit headers
                    if let Some(remaining) = resp.headers().get("x-ratelimit-remaining") {
                        if let Ok(remaining_str) = remaining.to_str() {
                            if let Ok(remaining_num) = remaining_str.parse::<u32>() {
                                if remaining_num < 100 {
                                    warn!(remaining = remaining_num, "GitHub API rate limit low");
                                }
                            }
                        }
                    }

                    match status {
                        StatusCode::OK => {
                            return resp
                                .json::<T>()
                                .await
                                .context("Failed to parse JSON response");
                        }
                        StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS => {
                            // Rate limited, wait and retry
                            warn!(
                                status = %status,
                                attempt,
                                backoff_ms,
                                "Rate limited, backing off"
                            );
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                            backoff_ms *= 2;
                            continue;
                        }
                        StatusCode::UNAUTHORIZED => {
                            anyhow::bail!("GitHub API unauthorized - check token");
                        }
                        StatusCode::NOT_FOUND => {
                            anyhow::bail!("GitHub API resource not found: {}", endpoint);
                        }
                        _ => {
                            let body = resp.text().await.unwrap_or_default();
                            warn!(
                                status = %status,
                                body = %body,
                                attempt,
                                "GitHub API error, retrying"
                            );
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                            backoff_ms *= 2;
                            continue;
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, attempt, "GitHub API request failed, retrying");
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms *= 2;
                    continue;
                }
            }
        }

        anyhow::bail!("GitHub API request failed after {} retries: {}", MAX_RETRIES, endpoint)
    }

    /// Make a POST request with retries
    async fn post<T: serde::de::DeserializeOwned>(&self, endpoint: &str) -> Result<T> {
        let url = format!("{}{}", GITHUB_API_BASE, endpoint);
        let mut backoff_ms = INITIAL_BACKOFF_MS;

        for attempt in 1..=MAX_RETRIES {
            debug!(url = %url, attempt, "GitHub API POST request");

            let response = self
                .client
                .post(&url)
                .header("Authorization", format!("token {}", self.token))
                .header("Accept", "application/vnd.github.v3+json")
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();

                    match status {
                        StatusCode::OK | StatusCode::CREATED => {
                            return resp
                                .json::<T>()
                                .await
                                .context("Failed to parse JSON response");
                        }
                        StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS => {
                            warn!(status = %status, attempt, "Rate limited, backing off");
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                            backoff_ms *= 2;
                            continue;
                        }
                        StatusCode::UNAUTHORIZED => {
                            anyhow::bail!("GitHub API unauthorized - check token");
                        }
                        _ => {
                            let body = resp.text().await.unwrap_or_default();
                            warn!(status = %status, body = %body, attempt, "GitHub API error");
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                            backoff_ms *= 2;
                            continue;
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, attempt, "GitHub API request failed");
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms *= 2;
                    continue;
                }
            }
        }

        anyhow::bail!("GitHub API POST failed after {} retries: {}", MAX_RETRIES, endpoint)
    }

    /// Make a DELETE request (no response body expected)
    async fn delete(&self, endpoint: &str) -> Result<()> {
        let url = format!("{}{}", GITHUB_API_BASE, endpoint);
        let mut backoff_ms = INITIAL_BACKOFF_MS;

        for attempt in 1..=MAX_RETRIES {
            debug!(url = %url, attempt, "GitHub API DELETE request");

            let response = self
                .client
                .delete(&url)
                .header("Authorization", format!("token {}", self.token))
                .header("Accept", "application/vnd.github.v3+json")
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let status = resp.status();

                    match status {
                        StatusCode::NO_CONTENT | StatusCode::OK => {
                            return Ok(());
                        }
                        StatusCode::NOT_FOUND => {
                            // Already deleted, that's fine
                            debug!("Resource already deleted: {}", endpoint);
                            return Ok(());
                        }
                        StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS => {
                            warn!(status = %status, attempt, "Rate limited, backing off");
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                            backoff_ms *= 2;
                            continue;
                        }
                        StatusCode::UNAUTHORIZED => {
                            anyhow::bail!("GitHub API unauthorized - check token");
                        }
                        _ => {
                            let body = resp.text().await.unwrap_or_default();
                            warn!(status = %status, body = %body, attempt, "GitHub API error");
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                            backoff_ms *= 2;
                            continue;
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, attempt, "GitHub API request failed");
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms *= 2;
                    continue;
                }
            }
        }

        anyhow::bail!("GitHub API DELETE failed after {} retries: {}", MAX_RETRIES, endpoint)
    }

    /// Get a registration token for new runners
    pub async fn get_registration_token(&self) -> Result<String> {
        let endpoint = format!("/repos/{}/actions/runners/registration-token", self.repo);
        let response: RegistrationTokenResponse = self.post(&endpoint).await?;
        Ok(response.token)
    }

    /// List all runners for the repository
    pub async fn list_runners(&self) -> Result<Vec<Runner>> {
        let mut runners = Vec::new();

        for page in 1.. {
            let endpoint = format!(
                "/repos/{}/actions/runners?per_page=100&page={}",
                self.repo, page
            );
            let response: RunnersResponse = self.get(&endpoint).await?;
            let count = response.runners.len();
            runners.extend(response.runners);

            if count < 100 {
                break;
            }
        }

        Ok(runners)
    }

    /// Delete a runner by ID
    pub async fn delete_runner(&self, runner_id: u64) -> Result<()> {
        let endpoint = format!("/repos/{}/actions/runners/{}", self.repo, runner_id);
        self.delete(&endpoint).await
    }

    /// Find a runner by name and return its ID
    pub async fn find_runner_by_name(&self, name: &str) -> Result<Option<u64>> {
        let runners = self.list_runners().await?;
        Ok(runners.into_iter().find(|r| r.name == name).map(|r| r.id))
    }

    /// Delete a runner by name (convenience method)
    pub async fn delete_runner_by_name(&self, name: &str) -> Result<()> {
        if let Some(runner_id) = self.find_runner_by_name(name).await? {
            self.delete_runner(runner_id).await?;
            debug!(name = %name, runner_id, "Deleted runner");
        } else {
            debug!(name = %name, "Runner not found, nothing to delete");
        }
        Ok(())
    }
}
