# Ephemeral NixOS Container System for CI Jobs
# See EPHEMERAL-NIXOS-CONTAINERS-GUIDE.md for full documentation
{ config, pkgs, lib, hostName, adminKeys, inputs, ... }:

let
  # Configuration
  poolSize = 7;  # Number of containers to maintain
  githubRepo = "thesimplekid/cdk";  # Your GitHub repo

  # Container template - written to /etc/nixos/ci-container-template.nix
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
        "d /home/github-runner/tmp 0755 github-runner github-runner -"
        "d /home/github-runner/.cache 0755 github-runner github-runner -"
        "d /var/lib/github-runner-work 0755 github-runner github-runner -"
        # GitHub Actions runner scripts expect /bin/bash (FHS path)
        "L+ /bin/bash - - - - /run/current-system/sw/bin/bash"
      ];

      environment.systemPackages = with pkgs; [
        git just cachix curl jq xz gnupg gawk vim htop lsof netcat procps
        gnutar gzip  # Required for extracting GitHub Actions runner
        # GitHub Actions runner dependencies (.NET Core)
        icu openssl zlib
        stdenv.cc.cc.lib  # provides libstdc++.so.6
      ];

      # FHS compatibility for GitHub Actions runner (.NET binaries)
      programs.nix-ld = {
        enable = true;
        libraries = with pkgs; [
          stdenv.cc.cc.lib
          icu
          openssl
          zlib
        ];
      };

      # Also set LD_LIBRARY_PATH system-wide for the dependency checker
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
    }
  '';

  # nspawn configuration for Docker support
  nspawnConfig = ''
    [Exec]
    SystemCallFilter=add_key keyctl bpf
    Capability=all

    [Files]
    Bind=/sys/fs/bpf
    BindReadOnly=/sys/module
    BindReadOnly=/lib/modules
    BindReadOnly=/run/secrets
    BindReadOnly=/run/agenix
    BindReadOnly=/var/cache/github-runner

    [Network]
    Private=yes
  '';

  # Container pool manager
  poolManager = pkgs.writeShellScriptBin "container-pool-manager" ''
    set -euo pipefail

    POOL_SIZE=${toString poolSize}
    GITHUB_TOKEN=$(cat /run/secrets/github-runner/token)
    GITHUB_REPO="${githubRepo}"
    HOST_NAME="${hostName}"

    # Path to nixos-container
    NIXOS_CONTAINER="/run/current-system/sw/bin/nixos-container"

    # Function to count active CI containers
    count_containers() {
      local count
      count=$($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep -c "^ci" 2>/dev/null) || true
      echo "''${count:-0}"
    }

    # Function to list CI containers
    list_containers() {
      $NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep "^ci" || true
    }

    # Function to get registration token from GitHub
    get_registration_token() {
      ${pkgs.curl}/bin/curl -s -X POST \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/$GITHUB_REPO/actions/runners/registration-token" \
        | ${pkgs.jq}/bin/jq -r '.token'
    }

    # Function to get removal token from GitHub
    get_removal_token() {
      ${pkgs.curl}/bin/curl -s -X POST \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/$GITHUB_REPO/actions/runners/remove-token" \
        | ${pkgs.jq}/bin/jq -r '.token'
    }

    # Function to deregister runner before destroying container
    deregister_runner() {
      local container_id=$1
      echo "[$(${pkgs.coreutils}/bin/date)] Deregistering runner in $container_id..."

      local removal_token=$(get_removal_token)

      # Try to gracefully deregister the runner
      $NIXOS_CONTAINER run "$container_id" -- bash -c "
        cd /home/github-runner/actions-runner 2>/dev/null || exit 0
        if [ -f .runner ]; then
          ./config.sh remove --token '$removal_token' 2>/dev/null || true
        fi
      " 2>/dev/null || true

      echo "[$(${pkgs.coreutils}/bin/date)] Runner deregistration attempted for $container_id"
    }

    # Function to get a unique subnet octet (100-199)
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

    # Function to spawn a new container
    spawn_container() {
      # Short container name: ci-XXXXX (last 5 digits of timestamp + 2 random digits)
      local ts=$(${pkgs.coreutils}/bin/date +%s)
      local short_ts=''${ts: -5}
      local short_rand=$((RANDOM % 100))
      local container_id="ci$short_ts$short_rand"
      local subnet_octet=$(get_free_subnet)

      echo "[$(${pkgs.coreutils}/bin/date)] Creating container: $container_id (subnet 192.168.$subnet_octet.0/24)"

      # Write nspawn configuration for this container (enables Docker)
      ${pkgs.coreutils}/bin/mkdir -p /etc/systemd/nspawn
      ${pkgs.coreutils}/bin/cat > "/etc/systemd/nspawn/$container_id.nspawn" << 'NSPAWN'
${nspawnConfig}
NSPAWN

      # Create container with custom network
      $NIXOS_CONTAINER create "$container_id" \
        --config-file /etc/nixos/ci-container-template.nix \
        --local-address "192.168.$subnet_octet.11" \
        --host-address "192.168.$subnet_octet.10"

      # Start container
      $NIXOS_CONTAINER start "$container_id"

      # Wait for Docker to be ready inside container
      echo "[$(${pkgs.coreutils}/bin/date)] Waiting for Docker daemon in $container_id..."
      local retries=0
      while ! $NIXOS_CONTAINER run "$container_id" -- docker info &>/dev/null; do
        retries=$((retries + 1))
        if [ $retries -gt 30 ]; then
          echo "[$(${pkgs.coreutils}/bin/date)] ERROR: Docker failed to start in $container_id after 30s"
          $NIXOS_CONTAINER destroy "$container_id" 2>/dev/null || true
          ${pkgs.coreutils}/bin/rm -f "/etc/systemd/nspawn/$container_id.nspawn"
          return 1
        fi
        sleep 1
      done
      echo "[$(${pkgs.coreutils}/bin/date)] Docker ready in $container_id (took ''${retries}s)"

      # Get registration token
      local token=$(get_registration_token)

      # Setup and run GitHub runner inside container
      $NIXOS_CONTAINER run "$container_id" -- bash -c "
        set -eo pipefail

        # Set up LD_LIBRARY_PATH for .NET binaries (GitHub Actions runner)
        source /etc/set-environment 2>/dev/null || true
        export LD_LIBRARY_PATH=\"''${NIX_LD_LIBRARY_PATH:-}:''${LD_LIBRARY_PATH:-}\"

        # Create runner directory
        mkdir -p /home/github-runner/actions-runner
        cd /home/github-runner/actions-runner

        # Download runner (use cached version if available)
        if [ -f /var/cache/github-runner/actions-runner-linux-x64.tar.gz ]; then
          cp /var/cache/github-runner/actions-runner-linux-x64.tar.gz .
        else
          curl -o actions-runner-linux-x64.tar.gz -L \
            https://github.com/actions/runner/releases/download/v2.321.0/actions-runner-linux-x64-2.321.0.tar.gz
        fi

        tar xzf ./actions-runner-linux-x64.tar.gz
        rm actions-runner-linux-x64.tar.gz

        # Fix ownership
        chown -R github-runner:github-runner /home/github-runner/actions-runner

        # Configure runner (pass LD_LIBRARY_PATH to sudo)
        sudo -E -u github-runner ./config.sh \
          --url https://github.com/$GITHUB_REPO \
          --token $token \
          --name $container_id \
          --labels self-hosted,ci,nix,x64,Linux,ephemeral \
          --work /var/lib/github-runner-work \
          --ephemeral \
          --unattended \
          --disableupdate

        # Run runner (blocks until job completes, then exits due to --ephemeral)
        echo 'Starting GitHub Actions runner...'
        sudo -E -u github-runner ./run.sh || true
        echo 'Runner exited'
      " &

      # Store PID to track runner process
      echo $! > /var/run/container-pool/runner-$container_id.pid

      echo "[$(${pkgs.coreutils}/bin/date)] Container $container_id started and runner registered"
    }

    # Main reconciliation loop
    echo "[$(${pkgs.coreutils}/bin/date)] Container pool manager starting (target pool size: $POOL_SIZE)"

    while true; do
      current=$(count_containers)
      needed=$((POOL_SIZE - current))

      if [ "$needed" -gt 0 ]; then
        echo "[$(${pkgs.coreutils}/bin/date)] Pool size: $current/$POOL_SIZE - spawning $needed container(s)"
        for i in $(${pkgs.coreutils}/bin/seq 1 $needed); do
          spawn_container
          # Stagger spawning to avoid resource spikes
          sleep 5
        done
      fi

      # Clean up completed containers (runner exited = job done)
      for container in $(list_containers); do
        pid_file="/var/run/container-pool/runner-$container.pid"
        if [ -f "$pid_file" ]; then
          pid=$(${pkgs.coreutils}/bin/cat "$pid_file")
          if ! kill -0 "$pid" 2>/dev/null; then
            # Runner process exited, deregister and destroy the container
            echo "[$(${pkgs.coreutils}/bin/date)] Container $container job completed, cleaning up"
            deregister_runner "$container"
            $NIXOS_CONTAINER stop "$container" 2>/dev/null || true
            $NIXOS_CONTAINER destroy "$container" 2>/dev/null || true
            ${pkgs.coreutils}/bin/rm -f "$pid_file"
            ${pkgs.coreutils}/bin/rm -f "/etc/systemd/nspawn/$container.nspawn"
            echo "[$(${pkgs.coreutils}/bin/date)] Container $container destroyed"
          fi
        else
          # Container exists but no PID file - orphaned, clean it up
          echo "[$(${pkgs.coreutils}/bin/date)] Orphaned container $container found, cleaning up"
          deregister_runner "$container"
          $NIXOS_CONTAINER stop "$container" 2>/dev/null || true
          $NIXOS_CONTAINER destroy "$container" 2>/dev/null || true
          ${pkgs.coreutils}/bin/rm -f "/etc/systemd/nspawn/$container.nspawn"
        fi
      done

      # Wait before next reconciliation
      sleep 10
    done
  '';

  # Emergency cleanup script
  cleanupAll = pkgs.writeShellScriptBin "cleanup-all-containers" ''
    set -euo pipefail

    NIXOS_CONTAINER="/run/current-system/sw/bin/nixos-container"
    GITHUB_TOKEN=$(cat /run/secrets/github-runner/token 2>/dev/null || echo "")
    GITHUB_REPO="${githubRepo}"

    # Function to get removal token
    get_removal_token() {
      if [ -z "$GITHUB_TOKEN" ]; then
        echo ""
        return
      fi
      ${pkgs.curl}/bin/curl -s -X POST \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/$GITHUB_REPO/actions/runners/remove-token" \
        | ${pkgs.jq}/bin/jq -r '.token // empty'
    }

    echo "Stopping and destroying all CI containers..."

    for container in $($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep "^ci" || true); do
      echo "Cleaning up: $container"

      # Try to deregister runner first
      removal_token=$(get_removal_token)
      if [ -n "$removal_token" ]; then
        echo "  Deregistering runner..."
        $NIXOS_CONTAINER run "$container" -- bash -c "
          cd /home/github-runner/actions-runner 2>/dev/null || exit 0
          if [ -f .runner ]; then
            ./config.sh remove --token '$removal_token' 2>/dev/null || true
          fi
        " 2>/dev/null || true
      fi

      $NIXOS_CONTAINER stop "$container" 2>/dev/null || true
      $NIXOS_CONTAINER destroy "$container" 2>/dev/null || true
      ${pkgs.coreutils}/bin/rm -f "/etc/systemd/nspawn/$container.nspawn"
    done

    # Clean up PID files
    ${pkgs.coreutils}/bin/rm -f /var/run/container-pool/runner-ci*.pid

    echo "Cleanup complete"
  '';

  # Orphan cleanup (backup safety net)
  orphanCleanup = pkgs.writeShellScriptBin "cleanup-orphaned-containers" ''
    set -euo pipefail

    NIXOS_CONTAINER="/run/current-system/sw/bin/nixos-container"
    GITHUB_TOKEN=$(cat /run/secrets/github-runner/token 2>/dev/null || echo "")
    GITHUB_REPO="${githubRepo}"

    # Function to get removal token
    get_removal_token() {
      if [ -z "$GITHUB_TOKEN" ]; then
        echo ""
        return
      fi
      ${pkgs.curl}/bin/curl -s -X POST \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/$GITHUB_REPO/actions/runners/remove-token" \
        | ${pkgs.jq}/bin/jq -r '.token // empty'
    }

    echo "Checking for orphaned containers..."

    for container in $($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep "^ci" || true); do
      # Check if container has a PID file (meaning pool manager knows about it)
      pid_file="/var/run/container-pool/runner-$container.pid"

      # If no PID file exists, check how long the container service has been running
      if [ ! -f "$pid_file" ]; then
        # Get container service start time, clean up if running > 2 hours without PID file
        start_time=$(${pkgs.systemd}/bin/systemctl show "container@$container" --property=ActiveEnterTimestamp --value 2>/dev/null || echo "")
        if [ -n "$start_time" ]; then
          start_epoch=$(${pkgs.coreutils}/bin/date -d "$start_time" +%s 2>/dev/null || echo 0)
          current_epoch=$(${pkgs.coreutils}/bin/date +%s)
          age=$((current_epoch - start_epoch))

          if [ "$age" -gt 7200 ]; then
            echo "Container $container is orphaned and too old ($age seconds), force cleanup"

            # Deregister runner before destroying
            removal_token=$(get_removal_token)
            if [ -n "$removal_token" ]; then
              echo "  Deregistering runner..."
              $NIXOS_CONTAINER run "$container" -- bash -c "
                cd /home/github-runner/actions-runner 2>/dev/null || exit 0
                if [ -f .runner ]; then
                  ./config.sh remove --token '$removal_token' 2>/dev/null || true
                fi
              " 2>/dev/null || true
            fi

            $NIXOS_CONTAINER stop "$container" 2>/dev/null || true
            $NIXOS_CONTAINER destroy "$container" 2>/dev/null || true
            ${pkgs.coreutils}/bin/rm -f "/etc/systemd/nspawn/$container.nspawn"
          fi
        fi
      fi
    done

    echo "Orphan cleanup complete"
  '';

  # Script to clean up stale/offline runners from GitHub
  cleanupGithubRunners = pkgs.writeShellScriptBin "cleanup-github-runners" ''
    set -euo pipefail

    GITHUB_TOKEN=$(cat /run/secrets/github-runner/token)
    GITHUB_REPO="${githubRepo}"

    echo "Fetching runners from GitHub..."

    # Get all runners
    runners=$(${pkgs.curl}/bin/curl -s \
      -H "Authorization: token $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github.v3+json" \
      "https://api.github.com/repos/$GITHUB_REPO/actions/runners?per_page=100")

    # Get list of currently active container names
    active_containers=$(/run/current-system/sw/bin/nixos-container list 2>/dev/null | ${pkgs.gnugrep}/bin/grep "^ci" || echo "")

    # Find and delete offline runners
    echo "$runners" | ${pkgs.jq}/bin/jq -r '.runners[] | select(.status == "offline") | "\(.id) \(.name)"' | while read -r id name; do
      # Check if this runner name matches an active container
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

  # Status script
  poolStatus = pkgs.writeShellScriptBin "container-pool-status" ''
    NIXOS_CONTAINER="/run/current-system/sw/bin/nixos-container"

    echo "Container Pool Status"
    echo "====================="
    echo ""
    echo "Target pool size: ${toString poolSize}"
    count=$($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep -c '^ci' 2>/dev/null) || count=0
    echo "Current containers: ''${count:-0}"
    echo ""
    echo "Active containers:"
    for container in $($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep "^ci" || true); do
      status=$(${pkgs.systemd}/bin/systemctl is-active "container@$container" 2>/dev/null || echo "unknown")
      ip=$($NIXOS_CONTAINER show-ip "$container" 2>/dev/null || echo "N/A")
      echo "  $container: $status (IP: $ip)"
    done
    echo ""
    echo "Pool manager: $(${pkgs.systemd}/bin/systemctl is-active container-pool-manager 2>/dev/null || echo 'not running')"
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
    poolManager
    cleanupAll
    orphanCleanup
    poolStatus
    cleanupGithubRunners
  ];

  # Write container template to /etc/nixos/ci-container-template.nix
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
      # Enable forwarding for container traffic
      iptables -I FORWARD -i ve-+ -j ACCEPT
      iptables -I FORWARD -o ve-+ -j ACCEPT
    '';
  };

  # Container pool manager service
  systemd.services.container-pool-manager = {
    description = "GitHub Actions Container Pool Manager";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "agenix.service" ];
    wants = [ "network-online.target" ];

    # Ensure PATH includes all necessary tools for nixos-container
    path = with pkgs; [
      coreutils
      findutils
      gnugrep
      gnused
      util-linux  # provides mountpoint
      nix
      gnutar
      gzip
      bash
    ];

    # Set NIX_PATH so nixos-container can find nixpkgs
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
      ExecStart = "${poolManager}/bin/container-pool-manager";
      Restart = "always";
      RestartSec = "10s";
      RuntimeDirectory = "container-pool";
      RuntimeDirectoryMode = "0755";
    };
  };

  # Orphan cleanup timer (safety net)
  systemd.timers.orphan-cleanup = {
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "10min";
      OnUnitActiveSec = "30min";
      Unit = "orphan-cleanup.service";
    };
  };

  systemd.services.orphan-cleanup = {
    description = "Clean up orphaned CI containers";
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${orphanCleanup}/bin/cleanup-orphaned-containers";
    };
  };

  # Cache runner tarball on activation (speeds up container creation)
  system.activationScripts.cache-runner = ''
    mkdir -p /var/cache/github-runner
    cd /var/cache/github-runner
    if [ ! -f actions-runner-linux-x64.tar.gz ]; then
      echo "Caching GitHub Actions runner..."
      ${pkgs.curl}/bin/curl -L -o actions-runner-linux-x64.tar.gz \
        https://github.com/actions/runner/releases/download/v2.321.0/actions-runner-linux-x64-2.321.0.tar.gz || true
    fi
  '';

  systemd.tmpfiles.rules = [
    "d /var/cache/github-runner 0755 root root -"
  ];

  # Secrets
  age.secrets.github-runner-token = {
    file = ../../secrets/github-runner.age;
    path = "/run/secrets/github-runner/token";
    mode = "0644";
    owner = "root";
  };
}
