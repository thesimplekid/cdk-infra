use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::container::ContainerManager;
use crate::github::GitHubClient;
use crate::state::{ContainerState, StateDb};

pub struct PoolController {
    config: Config,
    github: GitHubClient,
    containers: Arc<ContainerManager>,
    state_db: Arc<StateDb>,
    shutdown_rx: watch::Receiver<bool>,
}

impl PoolController {
    pub fn new(
        config: Config,
        github: GitHubClient,
        containers: Arc<ContainerManager>,
        state_db: Arc<StateDb>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Self {
        Self {
            config,
            github,
            containers,
            state_db,
            shutdown_rx,
        }
    }

    /// Reconcile state on startup - clean up old containers and stale state
    pub async fn reconcile_on_startup(&self) -> Result<()> {
        info!("Reconciling pool on startup");

        // Get all containers (both old j* and new r* style)
        let all_containers = self.containers.list_all().await?;

        // Clean up any old-style j* containers (migration from job-based to pool-based)
        for name in all_containers.iter().filter(|n| n.starts_with('j')) {
            info!(name = %name, "Cleaning up old-style job container");
            self.cleanup_container_full(name).await?;
        }

        // Check pool containers (r* style)
        let pool_containers = self.containers.list().await?;
        for name in &pool_containers {
            match self.containers.is_runner_completed(name).await {
                Ok(true) => {
                    info!(name = %name, "Cleaning up completed container from previous run");
                    self.cleanup_container_full(name).await?;
                }
                Ok(false) => {
                    info!(name = %name, "Container still has active runner");
                }
                Err(e) => {
                    warn!(name = %name, error = %e, "Failed to check container, cleaning up");
                    self.cleanup_container_full(name).await?;
                }
            }
        }

        // Clean up stale state entries (containers in DB but not in nixos-container list)
        let db_containers = self.state_db.list_containers()?;
        let active_set: HashSet<&str> = pool_containers.iter().map(|s| s.as_str()).collect();

        for (name, _) in db_containers {
            if !active_set.contains(name.as_str()) {
                info!(name = %name, "Removing stale state entry");
                self.state_db.remove_container(&name)?;
            }
        }

        Ok(())
    }

    /// Full cleanup: deregister from GitHub, destroy container, remove state
    async fn cleanup_container_full(&self, name: &str) -> Result<()> {
        // Deregister from GitHub
        if let Err(e) = self.github.delete_runner_by_name(name).await {
            warn!(name = %name, error = %e, "Failed to deregister runner from GitHub");
        }

        // Destroy container
        self.containers.cleanup_container(name).await?;

        // Remove from state DB
        self.state_db.remove_container(name)?;

        Ok(())
    }

    /// Spawn a container for a pool slot
    async fn spawn_pool_container(&self, slot: usize) -> Result<String> {
        // Get registration token
        let token = self.github.get_registration_token().await?;

        // Spawn container
        let name = self.containers.spawn_pool_container(slot, &token).await?;

        // Record in state DB
        let state = ContainerState::new(slot);
        self.state_db.put_container(&name, &state)?;

        Ok(name)
    }

    /// Respawn a container in a pool slot (cleanup old, spawn new)
    async fn respawn_pool_container(&self, name: &str, slot: usize) -> Result<()> {
        self.cleanup_container_full(name).await?;
        self.spawn_pool_container(slot).await?;
        Ok(())
    }

    /// Maintain the warm pool - ensure all slots have running containers
    async fn maintain_pool(&self) -> Result<()> {
        let current_containers: HashSet<String> =
            self.containers.list().await?.into_iter().collect();

        for slot in 0..self.config.max_concurrent_jobs {
            let name = ContainerManager::slot_to_container_name(slot);

            if !current_containers.contains(&name) {
                // Slot is empty - spawn a new container
                info!(slot, "Spawning container for empty pool slot");
                match self.spawn_pool_container(slot).await {
                    Ok(spawned_name) => {
                        info!(slot, name = %spawned_name, "Pool container spawned successfully");
                    }
                    Err(e) => {
                        warn!(slot, error = %e, "Failed to spawn pool container");
                    }
                }
            } else {
                // Container exists - check if runner completed or timed out
                match self.containers.is_runner_completed(&name).await {
                    Ok(true) => {
                        info!(slot, name = %name, "Runner completed, respawning container");
                        if let Err(e) = self.respawn_pool_container(&name, slot).await {
                            warn!(slot, name = %name, error = %e, "Failed to respawn container");
                        }
                    }
                    Ok(false) => {
                        // Runner still active - check for timeout
                        if let Some(state) = self.state_db.get_container(&name)? {
                            let running_secs = state.running_seconds();
                            let timeout_secs = self.config.job_timeout.as_secs();

                            if running_secs > timeout_secs {
                                warn!(
                                    slot,
                                    name = %name,
                                    running_secs,
                                    timeout_secs,
                                    "Container exceeded timeout, respawning"
                                );
                                if let Err(e) = self.respawn_pool_container(&name, slot).await {
                                    warn!(slot, name = %name, error = %e, "Failed to respawn timed out container");
                                }
                            } else {
                                debug!(slot, name = %name, running_secs, "Container healthy");
                            }
                        } else {
                            // Container exists but no state - orphaned
                            // Check if runner completed before respawning
                            match self.containers.is_runner_completed(&name).await {
                                Ok(true) => {
                                    warn!(slot, name = %name, "Orphaned container completed, respawning");
                                    if let Err(e) = self.respawn_pool_container(&name, slot).await {
                                        warn!(slot, name = %name, error = %e, "Failed to respawn orphaned container");
                                    }
                                }
                                Ok(false) => {
                                    // Runner still active, add back to state
                                    warn!(slot, name = %name, "Orphaned container still active, recovering state");
                                    let state = ContainerState::new(slot);
                                    if let Err(e) = self.state_db.put_container(&name, &state) {
                                        warn!(slot, name = %name, error = %e, "Failed to recover state for orphaned container");
                                    }
                                }
                                Err(e) => {
                                    warn!(slot, name = %name, error = %e, "Failed to check orphaned container status, respawning");
                                    if let Err(e) = self.respawn_pool_container(&name, slot).await {
                                        warn!(slot, name = %name, error = %e, "Failed to respawn orphaned container");
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(slot, name = %name, error = %e, "Failed to check runner status, respawning");
                        if let Err(e) = self.respawn_pool_container(&name, slot).await {
                            warn!(slot, name = %name, error = %e, "Failed to respawn container after check failure");
                        }
                    }
                }
            }
        }

        // Clean up stale state entries (in DB but container no longer exists)
        let db_containers = self.state_db.list_containers()?;
        for (name, _) in db_containers {
            if !current_containers.contains(&name) {
                info!(name = %name, "Removing stale state entry (container no longer exists)");
                self.state_db.remove_container(&name)?;
            }
        }

        Ok(())
    }

    /// Main run loop
    pub async fn run(&mut self) -> Result<()> {
        info!(
            poll_interval = ?self.config.poll_interval,
            pool_size = self.config.max_concurrent_jobs,
            "Pool controller starting"
        );

        // Reconcile on startup
        self.reconcile_on_startup().await?;

        loop {
            // Check for shutdown signal
            if *self.shutdown_rx.borrow() {
                info!("Shutdown signal received");
                break;
            }

            // Maintain the warm pool
            if let Err(e) = self.maintain_pool().await {
                warn!(error = %e, "Error maintaining pool");
            }

            // Wait for next poll or shutdown
            tokio::select! {
                _ = tokio::time::sleep(self.config.poll_interval) => {}
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        info!("Shutdown signal received during sleep");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Graceful shutdown - kill all containers
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down, cleaning up all containers");

        // Get all containers (both old and new style for thorough cleanup)
        let containers = self.containers.list_all().await?;
        info!(count = containers.len(), "Containers to clean up");

        for name in containers {
            info!(name = %name, "Cleaning up container on shutdown");
            if let Err(e) = self.cleanup_container_full(&name).await {
                warn!(name = %name, error = %e, "Failed to cleanup container on shutdown");
            }
        }

        // Clear all state
        self.state_db.clear_all()?;

        info!("Shutdown complete");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_to_container_name() {
        // Set a test hostname
        std::env::set_var("HOSTNAME", "test-host");
        // Hash of "test-host" truncated to 8 chars
        let expected_prefix = "aa098d39-r";
        assert_eq!(ContainerManager::slot_to_container_name(0), format!("{}0", expected_prefix));
        assert_eq!(ContainerManager::slot_to_container_name(5), format!("{}5", expected_prefix));
        assert_eq!(ContainerManager::slot_to_container_name(42), format!("{}42", expected_prefix));
    }
}
