# CDK Infrastructure & GitHub Actions Runner

This repository contains the Infrastructure as Code (IaC) and custom runner implementation for the **CDK (Cashu Development Kit)** project (`cashubtc/cdk`).

It defines a highly specialized "warm pool" of ephemeral NixOS containers designed to run CI/CD workloads, specifically fuzzing and integration tests for the CDK ecosystem.

## Overview

The primary purpose of this infrastructure is to provide **reproducible, isolated, and high-performance** runners for the CDK project. Unlike standard GitHub-hosted runners, these self-hosted runners:
*   Are pre-provisioned ("warm pool") for instant job pickup.
*   Run in fresh, ephemeral NixOS containers that are destroyed after every job.
*   Support native Nix builds and caching (`cachix`).
*   Include Docker support for containerized actions.

## Hosts

The infrastructure currently defines two dedicated runner hosts:

*   **`cdk-runner-01`**: Primary runner host (assigned `fuzz-a` label).
*   **`cdk-runner-02`**: Secondary runner host (assigned `fuzz-b` label).

These hosts are configured via Nix Flakes and deployed using `nixos-rebuild`.

## Architecture

The system is built on a custom Rust controller (`runner-controller`) that manages the lifecycle of NixOS containers.

1.  **Rust Controller**:
    -   Monitors the `cashubtc/cdk` repository for queued jobs.
    -   Maintains a pool of idle containers (e.g., 7 per host).
    -   Communicates with the GitHub API to register/deregister runners.
    -   Exposes a local status endpoint.

2.  **Ephemeral Containers**:
    -   Created from a template (`/etc/nixos/ci-container-template.nix`).
    -   Each container runs a single job and is then destroyed.
    -   Network isolated (dedicated subnets).

## Prerequisites

-   **NixOS**: The target machines must run NixOS.
-   **Nix Flakes**: Enabled in the configuration.
-   **GitHub PAT**: A Personal Access Token with `repo` scope is required to register runners.
-   **Agenix**: Used to encrypt the GitHub token.

## Installation & Deployment

### 1. Secrets Management

The GitHub Runner token is managed via `agenix`. To update or rotate the token:

1.  Edit the secret file:
    ```bash
    agenix -e secrets/github-runner.age
    ```
2.  Paste the new GitHub PAT.

### 2. Configuration

The runner configuration is defined in `hosts/runner/runner-controller.nix`. Key parameters include:

-   `githubRepo`: Set to `"cashubtc/cdk"`.
-   `maxConcurrentJobs`: Defaults to `7` (adjust based on host resources).
-   `runnerLabels`: Base labels include `["self-hosted", "ci", "nix", "x64", "Linux"]`.
    -   Host-specific labels (e.g., `fuzz-a`) are injected in `flake.nix`.

### 3. Deploying to Hosts

This project uses `just` to simplify deployment and management tasks.

#### Deploying updates

To apply the current configuration to the runner hosts:

```bash
# Apply to runner 01
just apply-runner-01

# Apply to runner 02
just apply-runner-02

# Apply to all runners
just apply-all
```

#### Bootstrapping new hosts

If setting up a fresh machine, use the bootstrap commands (requires root SSH access):

```bash
just bootstrap-runner-01
# or with a specific IP
just bootstrap-runner-01 IP=1.2.3.4
```

## Operational Commands

### Helper Scripts (On Host)

Helper scripts are available on the runner hosts for management:

| Command | Description |
|---------|-------------|
| `runner-status` | Displays the current pool size, active containers, and controller status. |
| `cleanup-github-runners` | Removes offline/stale runners from the GitHub UI. |
| `cleanup-all-containers` | **Destructive**: Stops and destroys all active containers and resets the pool. |

### Management via Justfile (Local)

The `justfile` provides convenient wrappers for common operational tasks:

| Command | Description |
|---------|-------------|
| `just status-all` | Checks systemd status of runners on all hosts via SSH. |
| `just storage-all` | Checks disk usage on all hosts (useful for monitoring Docker cleanup). |
| `just set-token-runner-01 <TOKEN>` | Updates the GitHub token on runner 01 and restarts the controller. |
| `just agenix-edit` | Edits the encrypted secrets file. |
| `just check` | Runs flake checks to validate configuration. |

### Monitoring

View logs for the main controller:
```bash
journalctl -u runner-controller -f
```

View logs for a specific runner container (e.g., `3a1f9-r0`):
```bash
sudo journalctl -M 3a1f9-r0 -u github-runner -f
```

## Development

The Rust controller source code is located in `runner-controller/`. To work on it:

1.  Enter the dev environment:
    ```bash
    nix develop
    ```
2.  Build and test:
    ```bash
    cargo build --package runner-controller
    cargo nextest run
    ```

## Acknowledgments

This infrastructure and runner implementation is partially modeled after the [Fedimint Infrastructure](https://github.com/fedimint/fedimint-infra).

## License

MIT
