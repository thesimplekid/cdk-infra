# GitHub Actions Runner Pool

A Rust controller for a fixed-capacity pool of ephemeral GitHub Actions runners on NixOS. Each runner runs inside a NixOS container managed by `nixos-container`.

## Overview

The controller keeps a warm pool of runner slots available:

1. Maintains `MAX_CONCURRENT` NixOS containers.
2. Registers one ephemeral GitHub Actions runner per container.
3. Lets GitHub schedule matching jobs onto idle runners.
4. Replaces a container after its ephemeral runner completes one job.
5. Reconciles local state, container state, and GitHub runner state after restarts.

This is a fixed-capacity warm pool, not job-queue autoscaling. The host has a fixed amount of compute, and `MAX_CONCURRENT` is the capacity limit.

```text
NixOS host
  runner-controller.service
    slot 0 -> abc12-r0 -> ephemeral GitHub runner
    slot 1 -> abc12-r1 -> ephemeral GitHub runner
    slot 2 -> abc12-r2 -> ephemeral GitHub runner
    slot 3 -> abc12-r3 -> ephemeral GitHub runner
    slot 4 -> abc12-r4 -> ephemeral GitHub runner
    slot 5 -> abc12-r5 -> ephemeral GitHub runner
```

## Configuration

The controller is configured via environment variables in the systemd service:

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_REPO` | required | Repository in `owner/repo` format |
| `GITHUB_TOKEN_FILE` | required | Path to GitHub PAT with runner administration permissions |
| `MAX_CONCURRENT` | 6 | Number of warm runner slots |
| `POLL_INTERVAL` | 10 | Seconds between reconciliation ticks |
| `JOB_TIMEOUT` | 7200 | Maximum observed busy duration for a runner |
| `RUNNER_STARTUP_TIMEOUT` | 600 | Maximum time for a container to register and become online |
| `RUNNER_LABELS` | self-hosted,ci,nix,x64,Linux | Comma-separated runner labels |
| `STATE_DIR` | /var/lib/runner-controller | State directory for tracking |
| `HTTP_PORT` | 8080 | HTTP API port for status/health |

## Lifecycle

1. **Startup reconciliation**
   The controller lists runner containers, removes stale old-style `j*` containers, and recovers state for existing pool containers.

2. **Slot maintenance**
   Each slot maps to a stable container name. Missing slots are created with a fresh GitHub registration token.

3. **Runner registration**
   The container's `github-runner.service` configures an ephemeral runner using the provided labels and starts `Runner.Listener`.

4. **Job execution**
   GitHub assigns jobs to idle registered runners. The controller checks GitHub runner state and records when a runner is observed as busy.

5. **Replacement**
   Completed, failed, timed-out, or unhealthy containers are deregistered from GitHub, destroyed, and replaced.

6. **Shutdown**
   Normal controller shutdown is non-destructive. Existing runner containers are left running so deploys and service restarts do not cancel active jobs.

## Resource Policy

The current runner hosts are sized for Rust-heavy CI:

```text
16 CPU cores
32 GB RAM
6 runner slots
350% CPU quota per container
7 GB memory max per container
```

The per-container caps preserve headroom for individual heavy Rust jobs, but six simultaneous peak jobs can overcommit the host. Monitor memory pressure and reduce per-container limits if the pool runs all slots at sustained load.

## HTTP API

- `GET /health` - health check
- `GET /status` - JSON status with pool size, active containers, timeouts, and per-container runtime/busy time

Example:

```json
{
  "pool_size": 6,
  "active_containers": 6,
  "containers": [
    {
      "name": "abc12-r0",
      "slot": 0,
      "running_seconds": 145,
      "busy_seconds": null
    }
  ],
  "poll_interval_seconds": 10,
  "job_timeout_seconds": 7200,
  "runner_startup_timeout_seconds": 600,
  "uptime_seconds": 3600
}
```

## Helper Scripts

### runner-status

Shows current controller status, active containers, and GitHub runners:

```bash
runner-status
```

### cleanup-github-runners

Removes offline GitHub runners that no longer have active containers:

```bash
cleanup-github-runners
```

### cleanup-all-containers

Emergency cleanup. Stops runner containers, deregisters GitHub runners, and removes local artifacts:

```bash
cleanup-all-containers
```

## Logs

View controller logs:

```bash
journalctl -u runner-controller -f
```

View container logs:

```bash
nixos-container list
nixos-container run abc12-r0 -- journalctl -u github-runner
```

## Notes

- GitHub is the scheduler. The controller does not poll workflow-job queues.
- `JOB_TIMEOUT` applies to observed busy time, not total container age.
- Normal service restarts do not destroy containers. Use `cleanup-all-containers` for explicit destructive cleanup.
