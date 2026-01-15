# On-Demand GitHub Actions Runner Controller
# Implements ARC-style job detection with NixOS containers
# See docs/runner-controller.md for documentation
{ config, pkgs, lib, hostName, adminKeys, inputs, runnerController, extraLabels ? [], ... }:

let
  # Configuration
  githubRepo = "cashubtc/cdk";
  maxConcurrentJobs = 7;
  pollIntervalSeconds = 10;
  jobTimeoutSeconds = 7200;  # 2 hours

  # Labels this runner provides (jobs must request a subset of these)
  runnerLabels = [ "self-hosted" "ci" "nix" "x64" "Linux" ] ++ extraLabels;

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
        git gh just cachix curl jq xz gnupg gawk vim htop lsof netcat procps
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
        trusted-users = [ "root" "github-runner" ];
        substituters = [
          "https://cache.nixos.org"
          "https://cashudevkit.cachix.org"
        ];
        trusted-public-keys = [
          "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
          "cashudevkit.cachix.org-1:zFKdvMiTllKWxIFNTjXgisZsOFufmaZXjWJNcmc8r+4="
        ];
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
          cachix
          gh
        ];

        environment = {
          HOME = "/var/lib/github-runner";
          RUNNER_ROOT = "/var/lib/github-runner";
        };

        script = '''
          set -euo pipefail

          RUNNER_NAME="$(hostname)"
          GITHUB_REPO="${githubRepo}"
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
            --labels "${lib.concatStringsSep "," runnerLabels}" \
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
          # Required for cachix compatibility - stricter settings break cachix
          PrivateTmp = false;
          ProtectSystem = "full";
        };
      };
    }
  '';

  # nspawn configuration for Docker support
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

  # Status script
  listenerStatus = pkgs.writeShellScriptBin "runner-status" ''
    NIXOS_CONTAINER="/run/current-system/sw/bin/nixos-container"
    STATE_DIR="/var/lib/runner-controller"
    GITHUB_TOKEN=$(cat /run/secrets/github-runner/token 2>/dev/null || echo "")
    GITHUB_REPO="${githubRepo}"

    echo "=== NixOS Runner Controller Status (Warm Pool) ==="
    echo ""
    echo "Controller: $(${pkgs.systemd}/bin/systemctl is-active runner-controller 2>/dev/null || echo 'not running')"
    echo "Pool size: ${toString maxConcurrentJobs}"
    echo "Poll interval: ${toString pollIntervalSeconds}s"
    echo ""

    count=$($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep -cE '^[a-f0-9]+-r[0-9]+$' 2>/dev/null) || count=0
    echo "Active pool containers: $count/${toString maxConcurrentJobs}"
    echo ""

    if [ "$count" -gt 0 ]; then
      echo "Pool slots:"
      for container in $($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep -E "^[a-f0-9]+-r[0-9]+$" || true); do
        echo "  $container"
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

    # Match new hash-prefixed container names
    active_containers=$($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep -E "^[a-f0-9]+-r[0-9]+$" || echo "")

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
    STATE_DIR="/var/lib/runner-controller"

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

    echo "Stopping and destroying all runner containers..."

    # Match new hash-prefixed container names
    for container in $($NIXOS_CONTAINER list 2>/dev/null | ${pkgs.gnugrep}/bin/grep -E "^[a-f0-9]+-r[0-9]+$" || true); do
      echo "Cleaning up: $container"

      deregister_runner "$container"

      $NIXOS_CONTAINER stop "$container" 2>/dev/null || true
      $NIXOS_CONTAINER destroy "$container" 2>/dev/null || true
      ${pkgs.coreutils}/bin/rm -f "/etc/systemd/nspawn/$container.nspawn"
      ${pkgs.iproute2}/bin/ip link delete "ve-$container" 2>/dev/null || true
    done

    # Clean up state files for hash-prefixed names
    ${pkgs.coreutils}/bin/rm -f "$STATE_DIR"/*-r*.*

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

  # System user for container UID mapping (matches github-runner UID 1000 in containers)
  # This allows the host's nix-daemon to trust container processes
  users.groups.github-runner = { gid = 1000; };
  users.users.github-runner = {
    isSystemUser = true;
    group = "github-runner";
    uid = 1000;
  };

  # User 'tsk' with sudo privileges
  users.users.tsk = {
    isNormalUser = true;
    uid = 1001;
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
      # Trust github-runner user (UID 1000 in containers, mapped to host)
      trusted-users = [ "root" "github-runner" ];
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

  # Rust runner-controller service
  systemd.services.runner-controller = {
    description = "GitHub Actions Runner Controller (Rust)";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "agenix.service" ];
    wants = [ "network-online.target" ];

    path = with pkgs; [
      coreutils
      iproute2
      systemd
      nix
      gnutar
      gzip
    ];

    environment = {
      GITHUB_REPO = githubRepo;
      GITHUB_TOKEN_FILE = "/run/secrets/github-runner/token";
      MAX_CONCURRENT = toString maxConcurrentJobs;
      POLL_INTERVAL = toString pollIntervalSeconds;
      JOB_TIMEOUT = toString jobTimeoutSeconds;
      RUNNER_LABELS = lib.concatStringsSep "," runnerLabels;
      STATE_DIR = "/var/lib/runner-controller";
      HTTP_PORT = "8080";
      RUST_LOG = "info";
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
      ExecStart = "${runnerController}/bin/runner-controller";
      Restart = "always";
      RestartSec = "10s";
      StateDirectory = "runner-controller";
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
