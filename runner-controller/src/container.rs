use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{debug, info, warn};



const NSPAWN_CONFIG_TEMPLATE: &str = r#"[Exec]
SystemCallFilter=add_key keyctl bpf
Capability=all

[Files]
Bind=/sys/fs/bpf
BindReadOnly=/sys/module
BindReadOnly=/lib/modules
BindReadOnly=/run/secrets
BindReadOnly=/run/agenix
"#;

pub struct ContainerManager {
    nixos_container_bin: PathBuf,
    container_template: PathBuf,
    state_dir: PathBuf,
}

impl ContainerManager {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            nixos_container_bin: PathBuf::from("/run/current-system/sw/bin/nixos-container"),
            container_template: PathBuf::from("/etc/nixos/ci-container-template.nix"),
            state_dir,
        }
    }

    /// Run nixos-container command and return output
    async fn run_container_cmd(&self, args: &[&str]) -> Result<String> {
        let output = Command::new(&self.nixos_container_bin)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute nixos-container")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "nixos-container {} failed: {}",
                args.join(" "),
                stderr
            );
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Run a command inside a container
    async fn run_in_container(&self, name: &str, cmd: &[&str]) -> Result<String> {
        let mut args = vec!["run", name, "--"];
        args.extend(cmd);

        let output = Command::new(&self.nixos_container_bin)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute command in container")?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Check if container can be reached
    async fn container_is_reachable(&self, name: &str) -> bool {
        let result = Command::new(&self.nixos_container_bin)
            .args(["run", name, "--", "true"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;

        matches!(result, Ok(status) if status.success())
    }

    /// List all pool containers ({prefix}-r{digits})
    pub async fn list(&self) -> Result<Vec<String>> {
        let output = self.run_container_cmd(&["list"]).await?;

        let containers: Vec<String> = output
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|name| {

                // match {prefix}-r{digits}
                if let Some((prefix, slot)) = name.split_once("-r") {
                    return prefix.len() == 5
                        && prefix.chars().all(|c| c.is_ascii_hexdigit())
                        && !slot.is_empty()
                        && slot.chars().all(|c| c.is_ascii_digit());
                }

                false
            })
            .collect();

        Ok(containers)
    }

    /// List all runner containers ({prefix}-r* style)
    pub async fn list_all(&self) -> Result<Vec<String>> {
        let output = self.run_container_cmd(&["list"]).await?;

        let containers: Vec<String> = output
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|name| {
                // match {prefix}-r{digits}
                if let Some((prefix, slot)) = name.split_once("-r") {
                    return prefix.len() == 5
                        && prefix.chars().all(|c| c.is_ascii_hexdigit())
                        && !slot.is_empty()
                        && slot.chars().all(|c| c.is_ascii_digit());
                }

                false
            })
            .collect();

        Ok(containers)
    }

    /// Get a free subnet octet in the 100-199 range
    pub async fn get_free_subnet(&self) -> Result<u8> {
        let containers = self.list_all().await?;
        let mut used_subnets = HashSet::new();

        for container in containers {
            if let Ok(ip) = self.run_container_cmd(&["show-ip", &container]).await {
                // Parse IP like "192.168.150.11" to get subnet octet (150)
                if let Some(octet) = ip.trim().split('.').nth(2) {
                    if let Ok(n) = octet.parse::<u8>() {
                        used_subnets.insert(n);
                    }
                }
            }
        }

        for octet in 100..=199 {
            if !used_subnets.contains(&octet) {
                return Ok(octet);
            }
        }

        // Fallback - shouldn't happen with max 7 concurrent
        Ok(100)
    }

    /// Convert pool slot index to container name (r + slot number)
    pub fn slot_to_container_name(slot: usize) -> String {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "runner".to_string());
        let hash = Self::hash_string(&hostname);
        let short_id = format!("{:x}", hash).chars().take(5).collect::<String>();

        // Container names like "hash-r0"
        format!("{}-r{}", short_id, slot)
    }
    fn hash_string(s: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    }

    /// Write nspawn configuration for Docker support
    fn write_nspawn_config(&self, name: &str) -> Result<()> {
        let nspawn_dir = Path::new("/etc/systemd/nspawn");
        std::fs::create_dir_all(nspawn_dir)?;

        let config_path = nspawn_dir.join(format!("{}.nspawn", name));
        std::fs::write(&config_path, NSPAWN_CONFIG_TEMPLATE)
            .with_context(|| format!("Failed to write nspawn config: {:?}", config_path))?;

        Ok(())
    }

    /// Create and start a container for a pool slot
    pub async fn spawn_pool_container(&self, slot: usize, token: &str) -> Result<String> {
        let name = Self::slot_to_container_name(slot);
        let subnet = self.get_free_subnet().await?;

        info!(
            name = %name,
            slot,
            subnet,
            "Spawning pool container"
        );

        // Clean up any existing container with same name
        if self.list_all().await?.contains(&name) {
            warn!(name = %name, "Cleaning up existing container first");
            self.cleanup_container(&name).await?;
        }

        // Clean up leftover artifacts
        self.cleanup_artifacts(&name).await;

        // Write nspawn config for Docker support
        self.write_nspawn_config(&name)?;

        // Write token to state dir temporarily
        let token_file = self.state_dir.join(format!("{}.token", name));
        std::fs::write(&token_file, token)
            .context("Failed to write token file")?;

        // Create container
        let local_addr = format!("192.168.{}.11", subnet);
        let host_addr = format!("192.168.{}.10", subnet);

        let create_result = self
            .run_container_cmd(&[
                "create",
                &name,
                "--config-file",
                self.container_template.to_str().unwrap(),
                "--local-address",
                &local_addr,
                "--host-address",
                &host_addr,
            ])
            .await;

        if let Err(e) = create_result {
            // Cleanup on failure
            self.cleanup_artifacts(&name).await;
            let _ = std::fs::remove_file(&token_file);
            return Err(e);
        }

        // Write token into container filesystem before starting
        let container_root = PathBuf::from(format!("/var/lib/nixos-containers/{}", name));
        let container_token_path = container_root.join("var/lib/github-runner-token");

        if let Some(parent) = container_token_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::copy(&token_file, &container_token_path)
            .context("Failed to copy token to container")?;

        // Start container
        if let Err(e) = self.run_container_cmd(&["start", &name]).await {
            warn!(name = %name, error = %e, "Failed to start container, cleaning up");
            self.cleanup_container(&name).await?;
            return Err(e);
        }

        // Clean up temp token file (already copied into container)
        let _ = std::fs::remove_file(&token_file);

        info!(name = %name, slot, "Pool container started");
        Ok(name)
    }

    /// Check if the github-runner service inside container has completed
    pub async fn is_runner_completed(&self, name: &str) -> Result<bool> {
        // First check if container is reachable
        if !self.container_is_reachable(name).await {
            debug!(name = %name, "Container not reachable, considering completed");
            return Ok(true);
        }

        // Check github-runner service status
        let status = self
            .run_in_container(name, &["systemctl", "is-active", "github-runner.service"])
            .await
            .unwrap_or_else(|_| "unknown".to_string());

        let status = status.trim();

        match status {
            "active" | "activating" | "reloading" => Ok(false),
            "failed" => {
                debug!(name = %name, "Runner service failed");
                Ok(true)
            }
            "inactive" => {
                // Check if service ever ran
                let result = self
                    .run_in_container(
                        name,
                        &["systemctl", "show", "github-runner.service", "--property=Result"],
                    )
                    .await
                    .unwrap_or_default();

                if result.contains("success") || result.contains("exit-code") {
                    debug!(name = %name, "Runner service completed");
                    Ok(true)
                } else {
                    // Service hasn't run yet
                    Ok(false)
                }
            }
            _ => {
                debug!(name = %name, status, "Unknown service status");
                Ok(false)
            }
        }
    }

    /// Stop a container
    pub async fn stop(&self, name: &str) -> Result<()> {
        debug!(name = %name, "Stopping container");

        // Stop systemd service first
        let _ = Command::new("systemctl")
            .args(["stop", &format!("container@{}.service", name)])
            .status()
            .await;

        // Then nixos-container stop
        let _ = self.run_container_cmd(&["stop", name]).await;

        Ok(())
    }

    /// Destroy a container
    pub async fn destroy(&self, name: &str) -> Result<()> {
        debug!(name = %name, "Destroying container");
        let _ = self.run_container_cmd(&["destroy", name]).await;
        Ok(())
    }

    /// Clean up leftover artifacts (network interface, profiles, etc.)
    async fn cleanup_artifacts(&self, name: &str) {
        // Remove nspawn config
        let nspawn_config = PathBuf::from(format!("/etc/systemd/nspawn/{}.nspawn", name));
        let _ = std::fs::remove_file(&nspawn_config);

        // Remove nspawn unix-export socket directory (prevents "Mount point exists already" error)
        let unix_export = PathBuf::from(format!("/run/systemd/nspawn/unix-export/{}", name));
        let _ = std::fs::remove_dir_all(&unix_export);

        // Remove container profiles
        let profile_dir = PathBuf::from(format!("/nix/var/nix/profiles/per-container/{}", name));
        let _ = std::fs::remove_dir_all(&profile_dir);

        // Remove container root
        let container_root = PathBuf::from(format!("/var/lib/nixos-containers/{}", name));
        let _ = std::fs::remove_dir_all(&container_root);

        // Remove network interface (shell out to ip)
        let _ = Command::new("ip")
            .args(["link", "delete", &format!("ve-{}", name)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;

        // Remove state files
        let _ = std::fs::remove_file(self.state_dir.join(format!("{}.token", name)));
    }

    /// Full cleanup of a container
    pub async fn cleanup_container(&self, name: &str) -> Result<()> {
        info!(name = %name, "Cleaning up container");

        self.stop(name).await?;
        self.destroy(name).await?;
        self.cleanup_artifacts(name).await;

        info!(name = %name, "Container cleaned up");
        Ok(())
    }
}
