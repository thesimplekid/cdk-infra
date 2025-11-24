{ lib, pkgs, config, hostName, adminKeys, inputs, ... }:

let
  # Runner names
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

        # Enable Docker inside the container with special configuration
        virtualisation.docker = {
          enable = true;
          autoPrune = {
            enable = true;
            dates = "daily";
          };
          # Docker daemon needs special config for running in containers
          daemon.settings = {
            # Use vfs storage driver for better compatibility in containers
            storage-driver = "vfs";
            # Disable some security features that don't work in containers
            seccomp-profile = "";
            apparmor = false;
            selinux-enabled = false;
          };
        };

        # Create github-runner user inside container
        users.groups.github-runner = { };
        users.users.github-runner = {
          isNormalUser = true;
          group = "github-runner";
          home = "/home/github-runner";
          extraGroups = [ "docker" ];
          createHome = true;
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

            # Service overrides from original config
            PrivateUsers = false;
            ProtectHome = false;
            PrivateMounts = false;
            PrivateTmp = false;
            ProtectSystem = "full";

            Environment = lib.mkForce [
              "HOME=/home/github-runner"
              "RUNNER_CACHE_DIR=/home/github-runner/.cache"
              "TMPDIR=/home/github-runner/tmp"
              "RUNNER_TEMP=/home/github-runner/tmp"
              "TEMP=/home/github-runner/tmp"
              "TMP=/home/github-runner/tmp"
              "CONTAINER_NAME=${name}"  # So tests can identify which container they're in
            ];

            # Remove most SystemCallFilter restrictions for Docker compatibility
            SystemCallFilter = lib.mkForce [];

            # Docker needs additional capabilities inside containers
            CapabilityBoundingSet = [
              "CAP_SETUID"
              "CAP_SETGID"
              "CAP_SYS_ADMIN"
              "CAP_NET_ADMIN"
              "CAP_DAC_OVERRIDE"
              "CAP_CHOWN"
              "CAP_FOWNER"
              "CAP_SETPCAP"
            ];
            AmbientCapabilities = [
              "CAP_SETUID"
              "CAP_SETGID"
              "CAP_SYS_ADMIN"
            ];
            NoNewPrivileges = false;
            # Docker needs access to /proc/sys
            ProtectKernelTunables = false;
            # Docker needs access to kernel modules
            ProtectKernelModules = false;
          };

          extraPackages = with pkgs; [
            gawk
            docker
            cachix
            gnupg
            curl
            jq
            xz
            git
            nix
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

        systemd.timers.cleanup-runner-tmp = {
          wantedBy = [ "timers.target" ];
          partOf = [ "cleanup-runner-tmp.service" ];
          timerConfig = {
            OnCalendar = "hourly";
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
  services.openssh.enable = true;
  services.resolved.enable = true;

  # System packages (will be merged with management scripts below)

  # System settings
  system.stateVersion = "23.11";
  networking.enableIPv6 = true;
  users.users.root.openssh.authorizedKeys.keys = adminKeys;
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
      echo "GitHub Runner Container Status"
      echo "=============================="
      echo ""
      for runner in ${lib.concatStringsSep " " runnerNames}; do
        echo "Container runner-$runner:"
        systemctl is-active container@runner-$runner.service || true
        if systemctl is-active container@runner-$runner.service >/dev/null 2>&1; then
          echo "  Runner service:"
          nixos-container run runner-$runner -- systemctl is-active github-runner-${hostName}-$runner || echo "  Not running"
          echo "  IP: $(nixos-container show-ip runner-$runner 2>/dev/null || echo 'N/A')"
        fi
        echo ""
      done
    '')

    (writeShellScriptBin "runner-logs" ''
      if [ $# -eq 0 ]; then
        echo "Usage: runner-logs <a|b|c|d> [follow]"
        echo "Example: runner-logs a follow"
        exit 1
      fi

      RUNNER=$1
      FOLLOW=""
      if [ "$2" = "follow" ]; then
        FOLLOW="-f"
      fi

      if nixos-container run runner-$RUNNER -- true 2>/dev/null; then
        nixos-container run runner-$RUNNER -- journalctl -u github-runner-${hostName}-$RUNNER $FOLLOW
      else
        echo "Container runner-$RUNNER is not running"
        exit 1
      fi
    '')

    (writeShellScriptBin "runner-shell" ''
      if [ $# -eq 0 ]; then
        echo "Usage: runner-shell <a|b|c|d>"
        exit 1
      fi
      nixos-container root-login runner-$1
    '')

    (writeShellScriptBin "runner-restart" ''
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
  ]);

  # Host-level cleanup service for all containers
  systemd.services.cleanup-all-containers = {
    description = "Cleanup all runner containers";
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.bash}/bin/bash -c '${lib.concatMapStringsSep " ; " (name:
        "nixos-container run runner-${name} -- docker system prune -af 2>/dev/null || true"
      ) runnerNames}'";
    };
  };

  systemd.timers.cleanup-all-containers = {
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = "daily";
      Persistent = true;
    };
  };
}