{ lib, pkgs, config, hostName, adminKeys, inputs, ... }:

let
  # Runner names - 4 runners for parallel CI capacity
  runnerNames = [ "a" "b" "c" "d" ];

  # Helper to generate IP addresses for containers
  # runner-a gets .100.11, runner-b gets .101.11, etc.
  getContainerIP = name:
    let
      index = lib.lists.findFirstIndex (x: x == name) 0 runnerNames;
    in {
      host = "192.168.${toString (100 + index)}.10";
      container = "192.168.${toString (100 + index)}.11";
    };

  # Shared configuration for all runner containers
  makeRunnerContainer = name:
    let
      ips = getContainerIP name;
    in {
      autoStart = true;
      privateNetwork = true;
      hostAddress = ips.host;
      localAddress = ips.container;

      # Extra flags combining nspawn config with direct bind mounts
      # CRITICAL: Include system-call-filter for keyring operations (from fixed version)
      extraFlags = [
        "--capability=all"  # Grant all capabilities
        "--system-call-filter=add_key"  # Allow add_key syscall for keyrings
        "--system-call-filter=keyctl"  # Allow keyctl syscall for keyrings
        "--system-call-filter=request_key"  # Allow request_key syscall
        "--bind-ro=/run/secrets:/run/secrets"
        "--bind-ro=/run/agenix:/run/agenix"
        "--bind=/var/cache/runner-${name}:/var/cache/runner-${name}"
      ];

      # Allow access to devices Docker needs
      allowedDevices = [
        { modifier = "rwm"; node = "/dev/fuse"; }
        { modifier = "rwm"; node = "/dev/net/tun"; }
        { modifier = "rwm"; node = "char-*"; }
      ];

      # Bind mount for sharing the GitHub token
      bindMounts = {
        "/run/secrets" = {
          hostPath = "/run/secrets";
          isReadOnly = true;
        };
        # Also mount agenix directory since token is a symlink to there
        "/run/agenix" = {
          hostPath = "/run/agenix";
          isReadOnly = true;
        };
        # Optional: Share cache directory for faster builds
        "/var/cache/runner-${name}" = {
          hostPath = "/var/cache/runner-${name}";
          isReadOnly = false;
        };
      };

      config = { config, pkgs, ... }: {
        # Container system configuration
        system.stateVersion = "23.11";

        # Basic networking setup
        networking = {
          defaultGateway = ips.host;
          nameservers = [ "8.8.8.8" "1.1.1.1" ];
          firewall.enable = false;  # Not needed inside container
          useHostResolvConf = false;  # Don't use host's resolv.conf
        };

        # Ensure resolved is disabled and use direct DNS
        services.resolved.enable = false;

        # Use disk-based /tmp for large builds (same as host config)
        boot.tmp.useTmpfs = false;
        boot.tmp.cleanOnBoot = true;

        # Enable Docker with configuration for running in containers
        virtualisation.docker = {
          enable = true;
          # Enable docker compose command
          enableOnBoot = true;
          # Auto-prune to save space
          autoPrune = {
            enable = true;
            dates = "daily";
            flags = [ "--all" "--volumes" ];  # More aggressive: remove ALL images and volumes
          };
          # Use daemon settings optimized for container environment with cgroups v2
          daemon.settings = {
            # Use overlay2 storage driver (works with cgroups v2)
            storage-driver = "overlay2";
            # Keep network features disabled in containers
            iptables = false;
            ip-masq = false;
            bridge = "none";
            # Use systemd cgroup driver for cgroups v2
            exec-opts = [
              "native.cgroupdriver=systemd"
            ];
            # Log level
            log-level = "warn";
          };
        };

        # Cgroups configuration handled by systemd defaults

        # Create github-runner user inside container
        users.groups.github-runner = { };
        users.users.github-runner = {
          isNormalUser = true;
          group = "github-runner";
          home = "/home/github-runner";
          extraGroups = [ "docker" ];  # Need docker group for Docker daemon access
          createHome = true;
          uid = 1000;  # Fixed UID for consistency
        };

        # Create necessary directories
        systemd.tmpfiles.rules = [
          "d /home/github-runner/tmp 0755 github-runner github-runner -"
          "d /home/github-runner/.cache 0755 github-runner github-runner -"
          "d /var/lib/github-runner-work 0755 github-runner github-runner -"
          "d /var/cache/runner-${name} 0755 github-runner github-runner -"
        ];

        # The GitHub runner service
        services.github-runners."${hostName}-${name}" = {
          enable = true;
          ephemeral = true;
          replace = true;
          name = "${hostName}-${name}";
          url = "https://github.com/thesimplekid/cdk";
          tokenFile = "/run/secrets/github-runner/token";
          user = "github-runner";

          extraLabels = [ "self-hosted" "ci" "nix" "x64" "Linux" "container-${name}" ];

          workDir = "/var/lib/github-runner-work";

          serviceOverrides = {
            # Fast restart for ephemeral runners
            Restart = lib.mkForce "always";
            RestartSec = "5s";

            # Clean up Docker containers and fix permissions before each new job
            ExecStartPre = [
              # Stop and remove all Docker containers
              "${pkgs.bash}/bin/bash -c '${pkgs.docker}/bin/docker stop $(${pkgs.docker}/bin/docker ps -q) 2>/dev/null || true; ${pkgs.docker}/bin/docker rm $(${pkgs.docker}/bin/docker ps -aq) 2>/dev/null || true'"

              # Remove Docker volumes
              "${pkgs.bash}/bin/bash -c '${pkgs.docker}/bin/docker volume prune -f 2>/dev/null || true'"

              # MORE AGGRESSIVE cleanup of all Docker-created directories
              # This specifically targets the misc/keycloak path and other common Docker data dirs
              "${pkgs.bash}/bin/bash -c 'find /var/lib/github-runner-work -type d \\( -name postgres_data -o -name mysql_data -o -name docker_data -o -name keycloak_data \\) -exec rm -rf {} + 2>/dev/null || true'"

              # Clean up only the DATA directories inside misc/keycloak (preserve config files)
              "${pkgs.bash}/bin/bash -c 'rm -rf /var/lib/github-runner-work/*/cdk/misc/keycloak/postgres_data 2>/dev/null || true'"
              "${pkgs.bash}/bin/bash -c 'rm -rf /var/lib/github-runner-work/*/cdk/misc/keycloak/mysql_data 2>/dev/null || true'"
              "${pkgs.bash}/bin/bash -c 'rm -rf /var/lib/github-runner-work/*/cdk/misc/keycloak/keycloak_data 2>/dev/null || true'"

              # Clean up any leftover Docker compose directories
              "${pkgs.bash}/bin/bash -c 'find /var/lib/github-runner-work -type d -name .docker -exec rm -rf {} + 2>/dev/null || true'"

              # Fix both ownership AND permissions on the work directory
              "${pkgs.bash}/bin/bash -c 'chown -R github-runner:github-runner /var/lib/github-runner-work 2>/dev/null || true'"
              "${pkgs.bash}/bin/bash -c 'find /var/lib/github-runner-work -type d -exec chmod 755 {} + 2>/dev/null || true'"
              "${pkgs.bash}/bin/bash -c 'find /var/lib/github-runner-work -type f -exec chmod 644 {} + 2>/dev/null || true'"
            ];

            # Clean up after job completes
            ExecStopPost = [
              # Stop any leftover Docker containers
              "${pkgs.bash}/bin/bash -c '${pkgs.docker}/bin/docker stop $(${pkgs.docker}/bin/docker ps -q) 2>/dev/null || true'"
              # Remove only the DATA directories (preserve keycloak config files)
              "${pkgs.bash}/bin/bash -c 'rm -rf /var/lib/github-runner-work/*/cdk/misc/keycloak/postgres_data 2>/dev/null || true'"
              "${pkgs.bash}/bin/bash -c 'rm -rf /var/lib/github-runner-work/*/cdk/misc/keycloak/mysql_data 2>/dev/null || true'"
              "${pkgs.bash}/bin/bash -c 'rm -rf /var/lib/github-runner-work/*/cdk/misc/keycloak/keycloak_data 2>/dev/null || true'"
            ];

            # Service overrides from original config
            PrivateUsers = false;
            ProtectHome = false;
            PrivateMounts = false;
            PrivateTmp = false;
            ProtectSystem = false;  # Changed from "full" to false for more permissions

            Environment = lib.mkForce [
              "HOME=/home/github-runner"
              "RUNNER_CACHE_DIR=/home/github-runner/.cache"
              "TMPDIR=/home/github-runner/tmp"
              "RUNNER_TEMP=/home/github-runner/tmp"
              "TEMP=/home/github-runner/tmp"
              "TMP=/home/github-runner/tmp"
              "CONTAINER_NAME=${name}"  # So tests can identify which container they're in
              "PATH=/run/current-system/sw/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
              "DOCKER_BUILDKIT=0"  # Disable BuildKit which can have issues in containers
            ];

            # SystemCallFilter and capabilities for Docker in privileged container
            SystemCallFilter = lib.mkForce [];  # Allow all system calls in privileged container
            NoNewPrivileges = false;  # Docker needs to escalate privileges
            KeyringMode = "shared";  # IMPORTANT: Allow access to kernel keyrings
            PrivateDevices = false;  # Allow access to all devices
            DevicePolicy = "auto";  # Allow automatic device access
          };

          extraPackages = with pkgs; [
            gawk
            cachix
            gnupg
            curl
            jq
            xz
            git
            nix
            # Docker wrapper that fixes permissions
            (writeShellScriptBin "docker" ''
              # Run the actual docker command
              ${docker}/bin/docker "$@"
              RESULT=$?

              # After docker compose up or docker run with volumes, fix permissions
              if [[ "$1" == "compose" && "$2" == "up" ]] || [[ "$1" == "run" && "$*" == *"-v"* ]]; then
                (
                  sleep 3  # Give Docker time to create directories
                  find /var/lib/github-runner-work -type d \( -name "postgres_data" -o -name "mysql_data" \) -exec chmod -R 755 {} + 2>/dev/null || true
                ) &
              fi

              exit $RESULT
            '')
            # Add docker-compose wrapper that fixes permissions after running
            (writeShellScriptBin "docker-compose" ''
              # Run the actual docker compose command
              ${docker}/bin/docker compose "$@"
              RESULT=$?

              # After docker-compose up, fix permissions on any created volumes
              if [[ "$1" == "up" ]] || [[ "$2" == "up" ]]; then
                (
                  sleep 2  # Give Docker time to create directories
                  echo "Fixing Docker volume permissions..."
                  find /var/lib/github-runner-work -type d \( -name "postgres_data" -o -name "mysql_data" \) -exec chmod -R 755 {} + 2>/dev/null || true
                ) &
              fi

              exit $RESULT
            '')
          ];
        };

        # Cleanup services inside container (similar to original cleanup.nix)
        systemd.services.cleanup-runner-tmp = {
          description = "Cleanup runner tmp files";
          serviceConfig = {
            Type = "oneshot";
            User = "root";
            ExecStart = "${pkgs.bash}/bin/bash -c '${pkgs.findutils}/bin/find /home/github-runner/tmp -type f -mmin +60 -delete 2>/dev/null || true'";
          };
        };

        # Service to fix Docker-created file permissions
        systemd.services.fix-docker-permissions = {
          description = "Fix permissions for Docker-created files";
          serviceConfig = {
            Type = "oneshot";
            User = "root";
            ExecStart = "${pkgs.bash}/bin/bash -c '${pkgs.findutils}/bin/find /var/lib/github-runner-work -type d \\( -name postgres_data -o -name mysql_data -o -name keycloak_data \\) -exec chmod -R 755 {} + 2>/dev/null || true; ${pkgs.findutils}/bin/find /var/lib/github-runner-work -type d \\( -name postgres_data -o -name mysql_data -o -name keycloak_data \\) -exec chown -R github-runner:github-runner {} + 2>/dev/null || true; ${pkgs.findutils}/bin/find /var/lib/github-runner-work/*/cdk/misc -type d -exec chmod 755 {} + 2>/dev/null || true; ${pkgs.findutils}/bin/find /var/lib/github-runner-work/*/cdk/misc -type f -exec chmod 644 {} + 2>/dev/null || true; ${pkgs.findutils}/bin/find /var/lib/github-runner-work -type f -user root -exec chown github-runner:github-runner {} + 2>/dev/null || true; ${pkgs.findutils}/bin/find /var/lib/github-runner-work -type f -user root -exec chmod 644 {} + 2>/dev/null || true'";
          };
        };

        systemd.timers.cleanup-runner-tmp = {
          wantedBy = [ "timers.target" ];
          partOf = [ "cleanup-runner-tmp.service" ];
          timerConfig = {
            OnCalendar = "hourly";
            Persistent = true;
          };
        };

        systemd.timers.fix-docker-permissions = {
          wantedBy = [ "timers.target" ];
          partOf = [ "fix-docker-permissions.service" ];
          timerConfig = {
            OnCalendar = "*:0/5";  # Every 5 minutes
            Persistent = true;
          };
        };

        # Container-specific packages
        environment.systemPackages = with pkgs; [
          vim
          htop
          lsof
          netcat
          procps
        ];

        # Nix configuration inside container
        nix = {
          settings = {
            experimental-features = [ "nix-command" "flakes" ];
            trusted-users = [ "github-runner" ];
          };
        };
      };
    };
in
{
  # Import base configuration modules (but not the old github-runner.nix)
  imports = [
    ./cleanup.nix
    ../../modules/common.nix
  ];

  # Boot configuration
  boot.loader.grub = {
    efiSupport = true;
    efiInstallAsRemovable = true;
  };

  # Basic services
  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      PermitRootLogin = "prohibit-password";
    };
  };
  services.resolved.enable = true;

  # System packages (will be merged with management scripts below)

  # System settings
  system.stateVersion = "23.11";
  networking.enableIPv6 = true;
  users.users.root.openssh.authorizedKeys.keys = adminKeys;

  # User 'tsk' with sudo privileges
  users.users.tsk = {
    isNormalUser = true;
    createHome = true;
    home = "/home/tsk";
    shell = pkgs.fish;
    extraGroups = [ "wheel" ]; # Enable sudo for the user
    openssh.authorizedKeys.keys = adminKeys;
    hashedPassword = "!"; # Lock password login, only allow SSH key authentication
  };

  # Allow wheel group to use sudo
  security.sudo.wheelNeedsPassword = false;

  # Enable fish shell
  programs.fish.enable = true;

  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.tmp.cleanOnBoot = true;

  networking = {
    inherit hostName;
    firewall.allowPing = true;
  };

  # Nix configuration
  nix = {
    extraOptions = ''
      experimental-features = nix-command flakes
    '';
    settings = {
      max-jobs = 2;
      auto-optimise-store = true;
      trusted-users = [ "root" "github-runner" ];
    };
    gc = {
      automatic = true;
      persistent = true;
      dates = "monthly";
      options = "--delete-older-than 30d";
    };
  };

  services.journald.extraConfig = "SystemMaxUse=1G";

  # Enable container support
  boot.enableContainers = true;

  # Host-level secret management
  age.secrets = {
    github-runner-token = {
      file = ../../secrets/github-runner.age;
      path = "/run/secrets/github-runner/token";
      owner = "root";
      group = "root";
      mode = "644";  # Containers need to read this
    };
  };

  # Setup network for containers - merge with existing networking config
  networking.nat = {
    enable = true;
    internalInterfaces = [ "ve-+" ];  # All container veth interfaces
    externalInterface = "enp1s0";  # Your server's external interface
  };

  # Additional firewall rules for containers
  networking.firewall = {
    # Allow forwarding for containers
    extraCommands = ''
      # Enable forwarding for container traffic
      iptables -I FORWARD -i ve-+ -j ACCEPT
      iptables -I FORWARD -o ve-+ -j ACCEPT
    '';
    trustedInterfaces = [ "ve-+" ];  # Trust all container interfaces
  };

  # Create the containers
  containers = lib.listToAttrs (map (name: {
    name = "runner-${name}";
    value = makeRunnerContainer name;
  }) runnerNames);

  # Create cache directories on the host
  systemd.tmpfiles.rules = lib.flatten [
    (map (name: "d /var/cache/runner-${name} 0755 root root -") runnerNames)
  ];

  # Create systemd-nspawn configuration files for Docker 20.10+ support
  environment.etc = lib.listToAttrs (map (name: {
    name = "systemd/nspawn/runner-${name}.nspawn";
    value = {
      text = ''
        [Exec]
        # Allow Docker to work inside the container
        SystemCallFilter=add_key keyctl bpf
        Capability=all

        [Files]
        # Bind mount necessary for Docker
        Bind=/sys/fs/bpf
        BindReadOnly=/sys/module
        BindReadOnly=/lib/modules
        # Bind mount for GitHub runner token and secrets
        BindReadOnly=/run/secrets
        BindReadOnly=/run/agenix
        # Optional cache directory
        Bind=/var/cache/runner-${name}

        [Network]
        # Use private network as configured
        Private=yes
      '';
    };
  }) runnerNames);

  # Management helper scripts and system packages
  environment.systemPackages = (map lib.lowPrio [
    pkgs.curl
    pkgs.gitMinimal
    pkgs.helix
    pkgs.tmux
    pkgs.btop
    pkgs.htop
    pkgs.psmisc
    inputs.agenix.packages."${pkgs.system}".default
  ]) ++ (with pkgs; [
    (writeShellScriptBin "runner-status" ''
      # Check if running as root
      if [ "$EUID" -ne 0 ]; then
        echo "Error: This command requires root privileges"
        echo "Please run: sudo runner-status"
        exit 1
      fi

      echo "GitHub Runner Container Status"
      echo "=============================="
      echo ""
      for runner in ${lib.concatStringsSep " " runnerNames}; do
        echo "Container runner-$runner:"
        CONTAINER_STATUS=$(systemctl is-active container@runner-$runner.service 2>/dev/null || echo "inactive")
        echo "  Container: $CONTAINER_STATUS"

        if [ "$CONTAINER_STATUS" = "active" ]; then
          RUNNER_STATUS=$(nixos-container run runner-$runner -- systemctl is-active github-runner-${hostName}-$runner 2>/dev/null || echo "inactive")
          echo "  Runner service: $RUNNER_STATUS"
          echo "  IP: $(nixos-container show-ip runner-$runner 2>/dev/null || echo 'N/A')"

          # Show if runner is currently processing a job
          if [ "$RUNNER_STATUS" = "active" ]; then
            JOB_STATUS=$(nixos-container run runner-$runner -- journalctl -u github-runner-${hostName}-$runner -n 50 --no-pager 2>/dev/null | grep -i "running job" | tail -1 || echo "")
            if [ -n "$JOB_STATUS" ]; then
              echo "  Status: Running job"
            else
              echo "  Status: Idle/Waiting"
            fi
          fi
        else
          echo "  Container is not running"
        fi
        echo ""
      done
    '')

    (writeShellScriptBin "runner-logs" ''
      # Check if running as root
      if [ "$EUID" -ne 0 ]; then
        echo "Error: This command requires root privileges"
        echo "Please run: sudo runner-logs <a|b|c|d> [follow]"
        exit 1
      fi

      if [ $# -eq 0 ]; then
        echo "Usage: runner-logs <a|b|c|d> [follow]"
        echo "Example: runner-logs a follow"
        exit 1
      fi

      RUNNER=$1
      FOLLOW=""
      if [ "$2" = "follow" ]; then
        FOLLOW="-f -n 0"  # Follow from the end, showing only new entries
      else
        FOLLOW="-n 100 -r"  # Show last 100 lines in reverse chronological order
      fi

      if nixos-container run runner-$RUNNER -- true 2>/dev/null; then
        nixos-container run runner-$RUNNER -- journalctl -u github-runner-${hostName}-$RUNNER $FOLLOW
      else
        echo "Container runner-$RUNNER is not running"
        exit 1
      fi
    '')

    (writeShellScriptBin "runner-shell" ''
      # Check if running as root
      if [ "$EUID" -ne 0 ]; then
        echo "Error: This command requires root privileges"
        echo "Please run: sudo runner-shell <a|b|c|d>"
        exit 1
      fi

      if [ $# -eq 0 ]; then
        echo "Usage: runner-shell <a|b|c|d>"
        exit 1
      fi
      nixos-container root-login runner-$1
    '')

    (writeShellScriptBin "runner-restart" ''
      # Check if running as root
      if [ "$EUID" -ne 0 ]; then
        echo "Error: This command requires root privileges"
        echo "Please run: sudo runner-restart <a|b|c|d|all>"
        exit 1
      fi

      if [ $# -eq 0 ]; then
        echo "Usage: runner-restart <a|b|c|d|all>"
        exit 1
      fi

      if [ "$1" = "all" ]; then
        for runner in ${lib.concatStringsSep " " runnerNames}; do
          echo "Restarting runner-$runner..."
          systemctl restart container@runner-$runner
        done
      else
        echo "Restarting runner-$1..."
        systemctl restart container@runner-$1
      fi
    '')

    (writeShellScriptBin "runner-test-ports" ''
      # Check if running as root
      if [ "$EUID" -ne 0 ]; then
        echo "Error: This command requires root privileges"
        echo "Please run: sudo runner-test-ports"
        exit 1
      fi

      echo "Testing port availability in each container..."
      echo ""
      for runner in ${lib.concatStringsSep " " runnerNames}; do
        echo "Container runner-$runner:"
        if nixos-container run runner-$runner -- true 2>/dev/null; then
          echo -n "  Port 5433 (PostgreSQL): "
          nixos-container run runner-$runner -- bash -c "nc -zv localhost 5433 2>&1 | grep -q 'refused' && echo 'Available' || echo 'In use'"
          echo -n "  Port 8085 (CLN): "
          nixos-container run runner-$runner -- bash -c "nc -zv localhost 8085 2>&1 | grep -q 'refused' && echo 'Available' || echo 'In use'"
        else
          echo "  Container not running"
        fi
        echo ""
      done
    '')

    (writeShellScriptBin "runner-test-docker" ''
      # Check if running as root
      if [ "$EUID" -ne 0 ]; then
        echo "Error: This command requires root privileges"
        echo "Please run: sudo runner-test-docker"
        exit 1
      fi

      echo "Testing Docker functionality in each container..."
      echo ""
      for runner in ${lib.concatStringsSep " " runnerNames}; do
        echo "Container runner-$runner:"
        if nixos-container run runner-$runner -- true 2>/dev/null; then
          echo "  Testing Docker hello-world:"
          nixos-container run runner-$runner -- docker run --rm hello-world 2>&1 | head -5
          echo "  Testing Alpine echo:"
          nixos-container run runner-$runner -- docker run --rm alpine echo "Docker works in container runner-$runner!"
        else
          echo "  Container not running"
        fi
        echo ""
      done
    '')

    (writeShellScriptBin "runner-disk-usage" ''
      # Check if running as root
      if [ "$EUID" -ne 0 ]; then
        echo "Error: This command requires root privileges"
        echo "Please run: sudo runner-disk-usage"
        exit 1
      fi

      echo "Disk Usage for Runner Containers"
      echo "================================="
      echo ""
      for runner in ${lib.concatStringsSep " " runnerNames}; do
        echo "Container runner-$runner:"
        if [ -d "/var/lib/nixos-containers/runner-$runner" ]; then
          echo "  Total container size:"
          du -sh /var/lib/nixos-containers/runner-$runner 2>/dev/null || echo "  Unable to calculate"
          echo ""
          echo "  Docker data breakdown:"
          du -sh /var/lib/nixos-containers/runner-$runner/var/lib/docker/* 2>/dev/null | sort -hr | head -10 || echo "  No Docker data"
          echo ""
          echo "  Docker info:"
          nixos-container run runner-$runner -- docker system df 2>/dev/null || echo "  Container not running"
        else
          echo "  Container directory does not exist"
        fi
        echo ""
        echo "---"
        echo ""
      done
    '')

    (writeShellScriptBin "runner-cleanup-now" ''
      # Check if running as root
      if [ "$EUID" -ne 0 ]; then
        echo "Error: This command requires root privileges"
        echo "Please run: sudo runner-cleanup-now <a|b|c|d|all>"
        exit 1
      fi

      if [ $# -eq 0 ]; then
        echo "Usage: runner-cleanup-now <a|b|c|d|all>"
        echo "Immediately run Docker cleanup on specified runner(s)"
        exit 1
      fi

      if [ "$1" = "all" ]; then
        for runner in ${lib.concatStringsSep " " runnerNames}; do
          echo "Cleaning runner-$runner..."
          nixos-container run runner-$runner -- docker system prune -af --volumes 2>/dev/null || echo "  Failed to clean runner-$runner"
          echo ""
        done
      else
        echo "Cleaning runner-$1..."
        nixos-container run runner-$1 -- docker system prune -af --volumes
      fi
    '')
  ]);

  # Host-level services
  systemd.services = lib.mkMerge ([
    # Cleanup service for all containers
    {
      cleanup-all-containers = {
        description = "Cleanup all runner containers";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c '${lib.concatMapStringsSep " ; " (name:
            "echo 'Cleaning runner-${name}...' && " +
            "nixos-container run runner-${name} -- docker system prune -af --volumes 2>/dev/null || true"
          ) runnerNames}'";
        };
      };
    }
  ] ++ (map (name: {
    "container@runner-${name}" = {
      after = [ "agenix-install-secrets.service" ];
      wants = [ "agenix-install-secrets.service" ];
    };
  }) runnerNames));

  systemd.timers.cleanup-all-containers = {
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = "*-*-* 00,06,12,18:00:00";  # Run 4 times per day (midnight, 6am, noon, 6pm)
      Persistent = true;
    };
  };
}