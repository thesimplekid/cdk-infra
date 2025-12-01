# On-Demand GitHub Actions Runner Controller
# Implements ARC-style job detection with NixOS containers
# See NIXOS-RUNNER-CONTROLLER-PLAN.md for full documentation
{ config, pkgs, lib, hostName, adminKeys, inputs, ... }:

let
  # Configuration
  githubRepo = "thesimplekid/cdk";
  maxConcurrentJobs = 7;
  pollIntervalSeconds = 10;
  jobTimeoutSeconds = 7200;  # 2 hours

  # Labels this runner provides (jobs must request a subset of these)
  runnerLabels = [ "self-hosted" "ci" "nix" "x64" "Linux" ];

  # Container template - written to /etc/nixos/ci-container-template.nix
  # Uses github-runner from nixpkgs (Runner.Listener binary)
  containerTemplate = ''
    { config, pkgs, lib, ... }:
    {
      boot.isContainer = true;
      system.stateVersion = "23.11";

      networking = {
        nameservers = [ "8.8.8.8" "1.1.1.1" ];
        firewall.enable = false;
        useHostResolvConf = false;
      };

      services.resolved.enable = false;

      boot.tmp.useTmpfs = false;
      boot.tmp.cleanOnBoot = true;

      # Docker configuration
      virtualisation.docker = {
        enable = true;
        enableOnBoot = true;
        autoPrune = {
          enable = true;
          dates = "daily";
          flags = [ "--all" "--volumes" ];
        };
        daemon.settings = {
          storage-driver = "overlay2";
          iptables = false;
          ip-masq = false;
          bridge = "none";
          exec-opts = [ "native.cgroupdriver=systemd" ];
          log-level = "warn";
        };
      };

      # GitHub runner user with Docker access
      users.groups.github-runner = { };
      users.users.github-runner = {
        isNormalUser = true;
        group = "github-runner";
        home = "/home/github-runner";
        extraGroups = [ "docker" ];
        createHome = true;
        uid = 1000;
      };

      systemd.tmpfiles.rules = [
        "d /home/github-runner 0755 github-runner github-runner -"
        "d /home/github-runner/.cache 0755 github-runner github-runner -"
        "d /var/lib/github-runner 0755 github-runner github-runner -"
        "d /var/lib/github-runner-work 0755 github-runner github-runner -"
        "d /var/log/github-runner 0755 github-runner github-runner -"
        "L+ /bin/bash - - - - /run/current-system/sw/bin/bash"
      ];

      environment.systemPackages = with pkgs; [
        git just cachix curl jq xz gnupg gawk vim htop lsof netcat procps
        gnutar gzip
        icu openssl zlib
        stdenv.cc.cc.lib
        github-runner  # GitHub Actions runner from nixpkgs
      ];

      programs.nix-ld = {
        enable = true;
        libraries = with pkgs; [
          stdenv.cc.cc.lib
          icu
          openssl
          zlib
        ];
      };

      environment.sessionVariables.LD_LIBRARY_PATH = lib.makeLibraryPath [
        pkgs.stdenv.cc.cc.lib
        pkgs.icu
        pkgs.openssl
        pkgs.zlib
      ];

      nix.settings = {
        experimental-features = [ "nix-command" "flakes" ];
        trusted-users = [ "github-runner" ];
      };

      # GitHub Actions Runner - using github-runner from nixpkgs
      # This is designed for ephemeral containers with dynamic registration tokens
      systemd.services.github-runner = {
        description = "GitHub Actions Runner";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" "docker.service" ];
        wants = [ "network-online.target" ];

        path = with pkgs; [
          bashInteractive coreutils curl gnutar gzip git docker nix jq findutils
          inetutils  # provides hostname
          github-runner
        ];

        environment = {
          HOME = "/var/lib/github-runner";
          RUNNER_ROOT = "/var/lib/github-runner";
        };

        script = '''
          set -euo pipefail

          RUNNER_NAME="$(hostname)"
          GITHUB_REPO="thesimplekid/cdk"
          TOKEN_FILE="/var/lib/github-runner-token"
          STATE_DIR="/var/lib/github-runner"
          WORK_DIR="/var/lib/github-runner-work"
          LOGS_DIR="/var/log/github-runner"

          echo "Waiting for network..."
          for i in $(seq 1 30); do
            if curl -sf --max-time 5 https://api.github.com > /dev/null 2>&1; then
              echo "Network is ready"
              break
            fi
            echo "Waiting for network... attempt $i"
            sleep 2
          done

          echo "Waiting for registration token..."
          for i in $(seq 1 30); do
            if [ -f "$TOKEN_FILE" ] && [ -s "$TOKEN_FILE" ]; then
              break
            fi
            echo "Waiting for token file... attempt $i"
            sleep 1
          done

          if [ ! -f "$TOKEN_FILE" ] || [ ! -s "$TOKEN_FILE" ]; then
            echo "ERROR: Token file not found or empty: $TOKEN_FILE"
            exit 1
          fi

          REG_TOKEN=$(cat "$TOKEN_FILE")

          # Clean state for ephemeral runner
          find "$STATE_DIR/" -mindepth 1 -delete 2>/dev/null || true
          find "$WORK_DIR/" -mindepth 1 -delete 2>/dev/null || true

          echo "Configuring runner $RUNNER_NAME..."
          cd "$STATE_DIR"
          config.sh \
            --unattended \
            --disableupdate \
            --work "$WORK_DIR" \
            --url "https://github.com/$GITHUB_REPO" \
            --labels "self-hosted,ci,nix,x64,Linux" \
            --name "$RUNNER_NAME" \
            --replace \
            --ephemeral \
            --token "$REG_TOKEN"

          # Move _diag to logs dir
          mkdir -p "$LOGS_DIR"
          if [ -d "$STATE_DIR/_diag" ]; then
            cp -r "$STATE_DIR/_diag/." "$LOGS_DIR/" || true
            rm -rf "$STATE_DIR/_diag"
          fi

          echo "Starting runner..."
          exec Runner.Listener run --startuptype service
        ''';

        serviceConfig = {
          Type = "simple";
          User = "github-runner";
          WorkingDirectory = "/var/lib/github-runner";
          Restart = "no";  # Don't restart - ephemeral runner exits after one job
          StateDirectory = "github-runner";
          LogsDirectory = "github-runner";
          RuntimeDirectory = "github-runner";
          KillSignal = "SIGINT";
        };
      };
    }
  '';

  # nspawn configuration for Docker support (generated per-container with token path)
  # The TOKEN_FILE_PATH placeholder gets replaced with the actual path at runtime
  # Note: Network settings are handled by nixos-container, not nspawn config
  nspawnConfigTemplate = ''
    [Exec]
    SystemCallFilter=add_key keyctl bpf
    Capability=all

    [Files]
    Bind=/sys/fs/bpf
    BindReadOnly=/sys/module
    BindReadOnly=/lib/modules
    BindReadOnly=/run/secrets
    BindReadOnly=/run/agenix
  '';

  # Convert runner labels to JSON array for comparison
  runnerLabelsJson = builtins.toJSON runnerLabels;

  # Job listener script
  jobListener = pkgs.writeShellScriptBin "job-listener" ''
    set -euo pipefail

    # Configuration
    GITHUB_TOKEN=$(cat /run/secrets/github-runner/token)
    GITHUB_REPO="${githubRepo}"
    MAX_CONCURRENT=${toString maxConcurrentJobs}
    POLL_INTERVAL=${toString pollIntervalSeconds}
    JOB_TIMEOUT=${toString jobTimeoutSeconds}
    RUNNER_LABELS='${runnerLabelsJson}'
    NIXOS_CONTAINER="/run/current-system/sw/bin/nixos-container"

    # State directory
    STATE_DIR="/var/lib/job-listener"
    mkdir -p "$STATE_DIR"

    # Logging helper
    log() {
      echo "[$(${pkgs.coreutils}/bin/date -Iseconds)] $1"
    }

    # GitHub API helper with error handling
    github_api() {
      local endpoint=$1
      local response
      response=$(${pkgs.curl}/bin/curl -sf \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com$endpoint" 2>/dev/null) || {
        log "ERROR: API call failed for $endpoint"
        echo "{}"
        return 1
      }
      echo "$response"
    }

    # Get registration token from GitHub
    get_registration_token() {
      ${pkgs.curl}/bin/curl -s -X POST \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/$GITHUB_REPO/actions/runners/registration-token" \
        | ${pkgs.jq}/bin/jq -r '.token'
    }

    # Get removal token from GitHub
    get_removal_token() {
      ${pkgs.curl}/bin/curl -s -X POST \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/$GITHUB_REPO/actions/runners/remove-token" \
        | ${pkgs.jq}/bin/jq -r '.token'
    }

    # Check if job labels match our runner labels
    # Job labels must be a subset of runner labels
    labels_match() {
      local job_labels=$1
      local match=true

      # For each label the job requires, check if we provide it
      for label in $(echo "$job_labels" | ${pkgs.jq}/bin/jq -r '.[]'); do
        if ! echo "$RUNNER_LABELS" | ${pkgs.jq}/bin/jq -e "index(\"$label\")" > /dev/null 2>&1; then
          match=false
          break
        fi
      done

      $match
    }

    # Count active job containers
    count_active_containers() {
      local count
      count=$($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep -c "^j[0-9]" 2>/dev/null) || count=0
      echo "$count" | ${pkgs.coreutils}/bin/tr -d '[:space:]'
    }

    # List active job containers
    list_containers() {
      $NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep "^j[0-9]" || true
    }

    # Convert job ID to short container name (max 11 chars for NixOS containers)
    # Format: j + last 7 digits of job ID = 8 chars
    job_id_to_container_name() {
      local job_id=$1
      echo "j''${job_id: -7}"
    }

    # Get a unique subnet octet (100-199)
    get_free_subnet() {
      local used_subnets=$(list_containers | while read c; do
        $NIXOS_CONTAINER show-ip "$c" 2>/dev/null | ${pkgs.gnugrep}/bin/grep -oP '192\.168\.\K[0-9]+' || true
      done | ${pkgs.coreutils}/bin/sort -u)

      for octet in $(${pkgs.coreutils}/bin/seq 100 199); do
        if ! echo "$used_subnets" | ${pkgs.gnugrep}/bin/grep -q "^$octet$"; then
          echo $octet
          return
        fi
      done
      echo 100  # Fallback
    }

    # Spawn a container for a specific job
    spawn_container_for_job() {
      local job_id=$1
      local container_name=$(job_id_to_container_name "$job_id")
      local subnet_octet=$(get_free_subnet)
      local token_file="$STATE_DIR/$container_name.token"

      log "Spawning container $container_name for job $job_id (subnet 192.168.$subnet_octet.0/24)"

      # Clean up any existing broken container with same name first
      if $NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep -q "^$container_name$"; then
        log "Cleaning up existing container $container_name first"
        $NIXOS_CONTAINER stop "$container_name" 2>/dev/null || true
        $NIXOS_CONTAINER destroy "$container_name" 2>/dev/null || true
      fi

      # Clean up any leftover profile directory
      ${pkgs.coreutils}/bin/rm -rf "/nix/var/nix/profiles/per-container/$container_name" 2>/dev/null || true
      ${pkgs.coreutils}/bin/rm -rf "/var/lib/nixos-containers/$container_name" 2>/dev/null || true

      # Clean up any leftover network interface from previous failed attempts
      ${pkgs.iproute2}/bin/ip link delete "ve-$container_name" 2>/dev/null || true

      # Get registration token and write to file
      log "Getting registration token for $container_name..."
      local reg_token=$(get_registration_token)
      if [ -z "$reg_token" ] || [ "$reg_token" = "null" ]; then
        log "ERROR: Failed to get registration token"
        return 1
      fi
      echo "$reg_token" > "$token_file"
      ${pkgs.coreutils}/bin/chmod 644 "$token_file"

      # Verify token file was created
      if [ ! -f "$token_file" ]; then
        log "ERROR: Token file was not created at $token_file"
        return 1
      fi
      log "Token file created: $token_file"

      # Write nspawn configuration for Docker support
      ${pkgs.coreutils}/bin/mkdir -p /etc/systemd/nspawn
      ${pkgs.coreutils}/bin/cat > "/etc/systemd/nspawn/$container_name.nspawn" << 'NSPAWN'
${nspawnConfigTemplate}
NSPAWN

      # Create container
      if ! $NIXOS_CONTAINER create "$container_name" \
        --config-file /etc/nixos/ci-container-template.nix \
        --local-address "192.168.$subnet_octet.11" \
        --host-address "192.168.$subnet_octet.10"; then
        log "ERROR: Failed to create container $container_name"
        ${pkgs.coreutils}/bin/rm -f "/etc/systemd/nspawn/$container_name.nspawn"
        ${pkgs.coreutils}/bin/rm -f "$token_file"
        return 1
      fi

      # Write token directly into container's filesystem (before starting)
      local container_root="/var/lib/nixos-containers/$container_name"
      ${pkgs.coreutils}/bin/mkdir -p "$container_root/var/lib"

      # Verify token file still exists before copying
      if [ ! -f "$token_file" ]; then
        log "ERROR: Token file disappeared before copy: $token_file"
        $NIXOS_CONTAINER destroy "$container_name" 2>/dev/null || true
        ${pkgs.coreutils}/bin/rm -f "/etc/systemd/nspawn/$container_name.nspawn"
        return 1
      fi

      if ! ${pkgs.coreutils}/bin/cp "$token_file" "$container_root/var/lib/github-runner-token"; then
        log "ERROR: Failed to copy token file to container"
        $NIXOS_CONTAINER destroy "$container_name" 2>/dev/null || true
        ${pkgs.coreutils}/bin/rm -f "/etc/systemd/nspawn/$container_name.nspawn"
        ${pkgs.coreutils}/bin/rm -f "$token_file"
        return 1
      fi
      ${pkgs.coreutils}/bin/chmod 644 "$container_root/var/lib/github-runner-token"
      log "Token written to $container_root/var/lib/github-runner-token"

      # Start container - the NixOS github-runner service will handle registration and job execution
      if ! $NIXOS_CONTAINER start "$container_name"; then
        log "ERROR: Failed to start container $container_name"
        $NIXOS_CONTAINER destroy "$container_name" 2>/dev/null || true
        ${pkgs.coreutils}/bin/rm -f "/etc/systemd/nspawn/$container_name.nspawn"
        ${pkgs.coreutils}/bin/rm -f "$token_file"
        ${pkgs.coreutils}/bin/rm -rf "/nix/var/nix/profiles/per-container/$container_name" 2>/dev/null || true
        ${pkgs.coreutils}/bin/rm -rf "/var/lib/nixos-containers/$container_name" 2>/dev/null || true
        return 1
      fi

      # Store state info for monitoring
      echo "$(${pkgs.coreutils}/bin/date +%s)" > "$STATE_DIR/$container_name.started"
      echo "$job_id" > "$STATE_DIR/$container_name.jobid"

      log "Container $container_name started (job: $job_id) - NixOS github-runner service will handle the rest"
    }

    # Deregister runner using GitHub API (more reliable than config.sh remove)
    deregister_runner() {
      local container_name=$1
      log "Deregistering runner $container_name via API..."

      # Find runner ID by name using the API
      local runner_id=$(${pkgs.curl}/bin/curl -sf \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/$GITHUB_REPO/actions/runners" \
        | ${pkgs.jq}/bin/jq -r ".runners[] | select(.name == \"$container_name\") | .id")

      if [ -n "$runner_id" ] && [ "$runner_id" != "null" ]; then
        log "Found runner $container_name with ID $runner_id, deleting..."
        ${pkgs.curl}/bin/curl -sf -X DELETE \
          -H "Authorization: token $GITHUB_TOKEN" \
          -H "Accept: application/vnd.github.v3+json" \
          "https://api.github.com/repos/$GITHUB_REPO/actions/runners/$runner_id" \
          && log "Runner $container_name deleted from GitHub" \
          || log "Failed to delete runner $container_name from GitHub"
      else
        log "Runner $container_name not found on GitHub (already removed or never registered)"
      fi
    }

    # Cleanup a container
    cleanup_container() {
      local container_name=$1
      log "Cleaning up container $container_name"

      deregister_runner "$container_name"

      # Stop the systemd service first to prevent restart loops
      ${pkgs.systemd}/bin/systemctl stop "container@$container_name.service" 2>/dev/null || true

      $NIXOS_CONTAINER stop "$container_name" 2>/dev/null || true
      $NIXOS_CONTAINER destroy "$container_name" 2>/dev/null || true
      ${pkgs.coreutils}/bin/rm -f "/etc/systemd/nspawn/$container_name.nspawn"
      ${pkgs.coreutils}/bin/rm -f "$STATE_DIR/$container_name.token"
      ${pkgs.coreutils}/bin/rm -f "$STATE_DIR/$container_name.started"
      ${pkgs.coreutils}/bin/rm -f "$STATE_DIR/$container_name.jobid"
      ${pkgs.coreutils}/bin/rm -rf "/nix/var/nix/profiles/per-container/$container_name" 2>/dev/null || true
      ${pkgs.coreutils}/bin/rm -rf "/var/lib/nixos-containers/$container_name" 2>/dev/null || true
      ${pkgs.iproute2}/bin/ip link delete "ve-$container_name" 2>/dev/null || true

      log "Container $container_name destroyed"
    }

    # Check if github-runner service inside container has completed
    is_runner_completed() {
      local container_name=$1

      # First check if container is still running
      if ! $NIXOS_CONTAINER run "$container_name" -- true 2>/dev/null; then
        return 0  # Container is not responding
      fi

      # Check the github-runner service
      local status=$($NIXOS_CONTAINER run "$container_name" -- systemctl is-active github-runner.service 2>/dev/null || echo "unknown")
      case "$status" in
        active|activating|reloading)
          return 1  # Runner is still active
          ;;
        failed)
          return 0  # Runner failed
          ;;
        inactive)
          # Check if the service ever ran by looking at its result
          local result=$($NIXOS_CONTAINER run "$container_name" -- systemctl show github-runner.service --property=Result 2>/dev/null | cut -d= -f2)
          if [ "$result" = "success" ] || [ "$result" = "exit-code" ]; then
            return 0  # Service ran and exited
          fi
          return 1  # Service hasn't run yet
          ;;
        *)
          return 1  # Unknown state, assume not completed
          ;;
      esac
    }

    # Check for completed or timed-out containers
    check_containers() {
      for container in $(list_containers); do
        local started_file="$STATE_DIR/$container.started"

        # Check if runner service has completed (ephemeral job done)
        if is_runner_completed "$container"; then
          log "Container $container runner completed"
          cleanup_container "$container"
          continue
        fi

        # Check for timeout
        if [ -f "$started_file" ]; then
          local started=$(cat "$started_file")
          local now=$(${pkgs.coreutils}/bin/date +%s)
          local age=$((now - started))

          if [ "$age" -gt "$JOB_TIMEOUT" ]; then
            log "Container $container exceeded timeout (''${age}s), force killing"
            cleanup_container "$container"
          fi
        else
          # Orphaned container without started file
          log "Orphaned container $container found (no started file)"
          cleanup_container "$container"
        fi
      done
    }

    # Fetch and process queued jobs
    process_queued_jobs() {
      # Get queued workflow runs
      local runs=$(github_api "/repos/$GITHUB_REPO/actions/runs?status=queued&per_page=100")
      local queued_count=$(echo "$runs" | ${pkgs.jq}/bin/jq -r '.total_count // 0')

      # Also check waiting runs (jobs waiting for specific runner)
      local waiting_runs=$(github_api "/repos/$GITHUB_REPO/actions/runs?status=waiting&per_page=100")
      local waiting_count=$(echo "$waiting_runs" | ${pkgs.jq}/bin/jq -r '.total_count // 0')

      # Also check pending runs
      local pending_runs=$(github_api "/repos/$GITHUB_REPO/actions/runs?status=pending&per_page=100")
      local pending_count=$(echo "$pending_runs" | ${pkgs.jq}/bin/jq -r '.total_count // 0')

      # Also check in_progress runs - they may have queued jobs inside
      local in_progress_runs=$(github_api "/repos/$GITHUB_REPO/actions/runs?status=in_progress&per_page=100")
      local in_progress_count=$(echo "$in_progress_runs" | ${pkgs.jq}/bin/jq -r '.total_count // 0')

      log "Poll: queued=$queued_count, waiting=$waiting_count, pending=$pending_count, in_progress=$in_progress_count"

      # Combine run IDs
      local run_ids=$(echo "$runs" | ${pkgs.jq}/bin/jq -r '.workflow_runs[]?.id // empty')
      run_ids="$run_ids $(echo "$waiting_runs" | ${pkgs.jq}/bin/jq -r '.workflow_runs[]?.id // empty')"
      run_ids="$run_ids $(echo "$pending_runs" | ${pkgs.jq}/bin/jq -r '.workflow_runs[]?.id // empty')"
      run_ids="$run_ids $(echo "$in_progress_runs" | ${pkgs.jq}/bin/jq -r '.workflow_runs[]?.id // empty')"

      for run_id in $run_ids; do
        [ -z "$run_id" ] && continue

        # Get jobs for this run
        local jobs=$(github_api "/repos/$GITHUB_REPO/actions/runs/$run_id/jobs")

        # Process each job
        echo "$jobs" | ${pkgs.jq}/bin/jq -c '.jobs[]? // empty' | while read -r job; do
          [ -z "$job" ] && continue

          local job_id=$(echo "$job" | ${pkgs.jq}/bin/jq -r '.id')
          local job_status=$(echo "$job" | ${pkgs.jq}/bin/jq -r '.status')
          local job_labels=$(echo "$job" | ${pkgs.jq}/bin/jq -c '.labels')
          local runner_id=$(echo "$job" | ${pkgs.jq}/bin/jq -r '.runner_id // "null"')

          log "  Job $job_id: status=$job_status, runner=$runner_id, labels=$job_labels"

          # Skip if job already has a runner assigned (0 or null means no runner)
          if [ "$runner_id" != "null" ] && [ "$runner_id" != "0" ] && [ -n "$runner_id" ]; then
            log "    -> Skipping: runner already assigned ($runner_id)"
            continue
          fi

          # Skip if job is not waiting for a runner
          case "$job_status" in
            queued|waiting|pending) ;;
            *)
              log "    -> Skipping: status is $job_status"
              continue
              ;;
          esac

          # Check if labels match
          if ! labels_match "$job_labels"; then
            log "    -> Skipping: labels don't match"
            continue
          fi

          # Check if we already have a container for this job
          local container_name=$(job_id_to_container_name "$job_id")
          if [ -f "$STATE_DIR/$container_name.started" ]; then
            log "    -> Skipping: container already exists"
            continue
          fi

          # Check concurrency limit
          local current=$(count_active_containers)
          if [ "$current" -ge "$MAX_CONCURRENT" ]; then
            log "At max concurrency ($current/$MAX_CONCURRENT), skipping job $job_id"
            continue
          fi

          # Spawn container for this job
          log "    -> Spawning container for job $job_id"
          spawn_container_for_job "$job_id" || log "    -> Failed to spawn container for job $job_id"
        done
      done
    }

    # Reconcile on startup
    reconcile_on_startup() {
      log "Reconciling state on startup..."

      # Clean up any containers without active runner services
      for container in $(list_containers); do
        # If runner service is still active, leave it alone
        if ! is_runner_completed "$container"; then
          log "Container $container has active runner service"
          continue
        fi

        # Otherwise clean it up
        log "Cleaning up stale container $container"
        cleanup_container "$container"
      done

      # Clean up stale token files (pattern: j*.token)
      for token_file in "$STATE_DIR"/j*.token; do
        [ -f "$token_file" ] || continue
        local container=$(basename "$token_file" .token)
        if ! $NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep -q "^$container$"; then
          log "Removing stale token file for $container"
          rm -f "$token_file"
          rm -f "$STATE_DIR/$container.started"
          rm -f "$STATE_DIR/$container.jobid"
        fi
      done
    }

    # Graceful shutdown handler
    shutdown_handler() {
      log "Received shutdown signal, stopping listener..."
      exit 0
    }

    trap shutdown_handler SIGTERM SIGINT

    # Main loop
    log "Job listener starting (polling every ''${POLL_INTERVAL}s, max concurrent: $MAX_CONCURRENT)"
    reconcile_on_startup

    while true; do
      # Check existing containers first
      check_containers

      # Process any queued jobs
      process_queued_jobs

      # Wait before next poll
      sleep "$POLL_INTERVAL"
    done
  '';

  # Status script
  listenerStatus = pkgs.writeShellScriptBin "runner-status" ''
    NIXOS_CONTAINER="/run/current-system/sw/bin/nixos-container"
    STATE_DIR="/var/lib/job-listener"
    GITHUB_TOKEN=$(cat /run/secrets/github-runner/token 2>/dev/null || echo "")
    GITHUB_REPO="${githubRepo}"

    echo "=== NixOS Runner Controller Status ==="
    echo ""
    echo "Listener: $(${pkgs.systemd}/bin/systemctl is-active job-listener 2>/dev/null || echo 'not running')"
    echo "Max concurrent jobs: ${toString maxConcurrentJobs}"
    echo "Poll interval: ${toString pollIntervalSeconds}s"
    echo ""

    count=$($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep -c '^j[0-9]' 2>/dev/null) || count=0
    echo "Active containers: $count/${toString maxConcurrentJobs}"
    echo ""

    if [ "$count" -gt 0 ]; then
      echo "Running jobs:"
      for container in $($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep "^j[0-9]" || true); do
        jobid_file="$STATE_DIR/$container.jobid"
        started_file="$STATE_DIR/$container.started"
        job_id="unknown"
        [ -f "$jobid_file" ] && job_id=$(cat "$jobid_file")
        if [ -f "$started_file" ]; then
          started=$(cat "$started_file")
          now=$(${pkgs.coreutils}/bin/date +%s)
          age=$((now - started))
          echo "  $container (job $job_id, running ''${age}s)"
        else
          echo "  $container (job $job_id)"
        fi
      done
      echo ""
    fi

    if [ -n "$GITHUB_TOKEN" ]; then
      echo "GitHub runners:"
      ${pkgs.curl}/bin/curl -sf \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/$GITHUB_REPO/actions/runners" 2>/dev/null \
        | ${pkgs.jq}/bin/jq -r '.runners[]? | "  \(.name): \(.status)"' || echo "  (failed to fetch)"
    fi
  '';

  # Cleanup stale GitHub runners
  cleanupGithubRunners = pkgs.writeShellScriptBin "cleanup-github-runners" ''
    set -euo pipefail

    GITHUB_TOKEN=$(cat /run/secrets/github-runner/token)
    GITHUB_REPO="${githubRepo}"
    NIXOS_CONTAINER="/run/current-system/sw/bin/nixos-container"

    echo "Fetching runners from GitHub..."

    runners=$(${pkgs.curl}/bin/curl -s \
      -H "Authorization: token $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github.v3+json" \
      "https://api.github.com/repos/$GITHUB_REPO/actions/runners?per_page=100")

    active_containers=$($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep "^j[0-9]" || echo "")

    echo "$runners" | ${pkgs.jq}/bin/jq -r '.runners[] | select(.status == "offline") | "\(.id) \(.name)"' | while read -r id name; do
      if echo "$active_containers" | ${pkgs.gnugrep}/bin/grep -q "^$name$"; then
        echo "Skipping $name (id: $id) - container still exists"
        continue
      fi

      echo "Deleting offline runner: $name (id: $id)"
      ${pkgs.curl}/bin/curl -s -X DELETE \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/$GITHUB_REPO/actions/runners/$id"
    done

    echo ""
    echo "Remaining runners:"
    ${pkgs.curl}/bin/curl -s \
      -H "Authorization: token $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github.v3+json" \
      "https://api.github.com/repos/$GITHUB_REPO/actions/runners" \
      | ${pkgs.jq}/bin/jq -r '.runners[] | "  \(.name): \(.status)"'
  '';

  # Emergency cleanup script
  cleanupAll = pkgs.writeShellScriptBin "cleanup-all-containers" ''
    set -euo pipefail

    NIXOS_CONTAINER="/run/current-system/sw/bin/nixos-container"
    GITHUB_TOKEN=$(cat /run/secrets/github-runner/token 2>/dev/null || echo "")
    GITHUB_REPO="${githubRepo}"
    STATE_DIR="/var/lib/job-listener"

    # Deregister runner via GitHub API
    deregister_runner() {
      local name=$1
      if [ -z "$GITHUB_TOKEN" ]; then
        return
      fi

      local runner_id=$(${pkgs.curl}/bin/curl -sf \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/$GITHUB_REPO/actions/runners" \
        | ${pkgs.jq}/bin/jq -r ".runners[] | select(.name == \"$name\") | .id")

      if [ -n "$runner_id" ] && [ "$runner_id" != "null" ]; then
        echo "  Deleting runner $name (ID: $runner_id) from GitHub..."
        ${pkgs.curl}/bin/curl -sf -X DELETE \
          -H "Authorization: token $GITHUB_TOKEN" \
          -H "Accept: application/vnd.github.v3+json" \
          "https://api.github.com/repos/$GITHUB_REPO/actions/runners/$runner_id" || true
      fi
    }

    echo "Stopping and destroying all job containers..."

    for container in $($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep "^j[0-9]" || true); do
      echo "Cleaning up: $container"

      deregister_runner "$container"

      $NIXOS_CONTAINER stop "$container" 2>/dev/null || true
      $NIXOS_CONTAINER destroy "$container" 2>/dev/null || true
      ${pkgs.coreutils}/bin/rm -f "/etc/systemd/nspawn/$container.nspawn"
      ${pkgs.iproute2}/bin/ip link delete "ve-$container" 2>/dev/null || true
    done

    # Clean up state files
    ${pkgs.coreutils}/bin/rm -f "$STATE_DIR"/j*.token
    ${pkgs.coreutils}/bin/rm -f "$STATE_DIR"/j*.started
    ${pkgs.coreutils}/bin/rm -f "$STATE_DIR"/j*.jobid

    echo "Cleanup complete"
  '';

in {
  # Import common modules
  imports = [
    ../../modules/common.nix
  ];

  # Boot configuration
  boot.loader.grub = {
    efiSupport = true;
    efiInstallAsRemovable = true;
  };

  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.tmp.cleanOnBoot = true;

  # Basic services
  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      PermitRootLogin = "prohibit-password";
    };
  };
  services.resolved.enable = true;

  # System settings
  system.stateVersion = "23.11";
  networking = {
    inherit hostName;
    enableIPv6 = true;
    firewall.allowPing = true;
  };

  users.users.root.openssh.authorizedKeys.keys = adminKeys;

  # User 'tsk' with sudo privileges
  users.users.tsk = {
    isNormalUser = true;
    createHome = true;
    home = "/home/tsk";
    shell = pkgs.fish;
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = adminKeys;
    hashedPassword = "!";
  };

  security.sudo.wheelNeedsPassword = false;
  programs.fish.enable = true;

  # Nix configuration
  nix = {
    extraOptions = ''
      experimental-features = nix-command flakes
    '';
    settings = {
      max-jobs = 2;
      auto-optimise-store = true;
      trusted-users = [ "root" ];
    };
    gc = {
      automatic = true;
      persistent = true;
      dates = "monthly";
      options = "--delete-older-than 30d";
    };
  };

  services.journald.extraConfig = "SystemMaxUse=1G";

  # Install helper scripts and system packages
  environment.systemPackages = (map lib.lowPrio [
    pkgs.curl
    pkgs.gitMinimal
    pkgs.helix
    pkgs.tmux
    pkgs.btop
    pkgs.htop
    pkgs.psmisc
    inputs.agenix.packages."${pkgs.system}".default
  ]) ++ [
    jobListener
    listenerStatus
    cleanupGithubRunners
    cleanupAll
  ];

  # Write container template
  environment.etc."nixos/ci-container-template.nix".text = containerTemplate;

  # Enable NixOS containers
  boot.enableContainers = true;

  # Network configuration for container subnets
  networking.nat = {
    enable = true;
    internalInterfaces = [ "ve-+" ];
    externalInterface = "enp1s0";
  };

  networking.firewall = {
    trustedInterfaces = [ "ve-+" ];
    extraCommands = ''
      iptables -I FORWARD -i ve-+ -j ACCEPT
      iptables -I FORWARD -o ve-+ -j ACCEPT
    '';
  };

  # Job listener service
  systemd.services.job-listener = {
    description = "GitHub Actions Job Listener";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "agenix.service" ];
    wants = [ "network-online.target" ];

    path = with pkgs; [
      coreutils
      findutils
      gnugrep
      gnused
      util-linux
      nix
      gnutar
      gzip
      bash
      iproute2
      systemd
    ];

    environment = {
      NIX_PATH = builtins.concatStringsSep ":" config.nix.nixPath;
    };

    preStart = ''
      while [ ! -f /run/secrets/github-runner/token ]; do
        echo "Waiting for GitHub runner token..."
        sleep 1
      done
    '';

    serviceConfig = {
      Type = "simple";
      ExecStart = "${jobListener}/bin/job-listener";
      Restart = "always";
      RestartSec = "10s";
      StateDirectory = "job-listener";
      StateDirectoryMode = "0755";
    };
  };


  # Secrets
  age.secrets.github-runner-token = {
    file = ../../secrets/github-runner.age;
    path = "/run/secrets/github-runner/token";
    mode = "0644";
    owner = "root";
  };
}
