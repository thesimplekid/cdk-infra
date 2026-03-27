# CDK Mint Server Configuration
# Runs cdk-mintd with PostgreSQL backend, fronted by Caddy for automatic HTTPS
{ config, pkgs, lib, hostName, adminKeys, inputs, cdkMintd, cdkMintdLdk, ... }:

let
  # Mint configuration
  mintDomain = "testnut.cashudevkit.org";
  mintListenHost = "127.0.0.1";
  mintListenPort = 8085;

  # Mutinynet mint configuration
  mint2Domain = "mutiny.cashudevkit.org";
  mint2ListenHost = "127.0.0.1";
  mint2ListenPort = 8086;

  # Mutinynet LDK dashboard configuration
  dashDomain = "dash.mutiny.cashudevkit.org";
  dashUpstreamPort = 8091;

  # Caddy snippet template for dash basic auth - hash injected at runtime
  dashCaddyTemplate = pkgs.writeText "caddy-dash.tpl" ''
    ${dashDomain} {
      basic_auth {
        admin @BCRYPT_HASH@
      }
      reverse_proxy 127.0.0.1:${toString dashUpstreamPort}
    }
  '';

  # Forgejo configuration
  forgejoDomain = "forgejo.cashudevkit.org";
  forgejoListenHost = "127.0.0.1";
  forgejoListenPort = 3000;

  # cdk-mintd config template. The mnemonic is injected at runtime from agenix
  # so it never ends up in the Nix store.
  mintConfigTemplate = pkgs.writeText "cdk-mintd-config.toml.tpl" ''
    [info]
    url = "https://${mintDomain}/"
    listen_host = "${mintListenHost}"
    listen_port = ${toString mintListenPort}
    mnemonic = "@MINT_MNEMONIC@"
    input_fee_ppk = 100
    use_keyset_v2 = false

    [info.quote_ttl]
    mint_ttl = 600
    melt_ttl = 600

    [info.http_cache]
    backend = "memory"
    ttl = 60
    tti = 60

    [mint_management_rpc]
    enabled = false

    [mint_info]
    name = "mintd cdk test mint"
    description = "These are not real sats for testing only"
    description_long = "These sats are not backed by anything and should only be used for testing"
    motd = "Will rug your fake sats any day now"
    contact_email = "tsk@thesimplekid.com"

    [database]
    engine = "sqlite"

    [database.sqlite]
    path = "/var/lib/cdk-mintd/cdk-mintd.sqlite"

    [ln]
    ln_backend = "fakewallet"

    [fake_wallet]
    supported_units = ["sat", "usd"]
    fee_percent = 0.02
    reserve_fee_min = 1
    min_delay_time = 1
    max_delay_time = 3

    [limits]
    max_inputs = 1000
    max_outputs = 1000
  '';

  # The cdk-mintd binary from the static package
  # The static build names the binary with version and arch suffix
  # We create a wrapper that finds and runs it
  cdkMintdBin = pkgs.writeShellScriptBin "cdk-mintd" ''
    exec $(find ${cdkMintd}/bin -type f -name 'cdk-mintd*' | head -1) "$@"
  '';

  # Mutinynet mint config template (LDK node backend on signet/mutinynet)
  mint2ConfigTemplate = pkgs.writeText "cdk-mintd-mutiny-config.toml.tpl" ''
    [info]
    url = "https://${mint2Domain}/"
    listen_host = "${mint2ListenHost}"
    listen_port = ${toString mint2ListenPort}
    mnemonic = "@MINT_MNEMONIC@"

    [info.quote_ttl]
    mint_ttl = 600
    melt_ttl = 120

    [info.http_cache]
    backend = "memory"
    ttl = 60
    tti = 60

    [mint_management_rpc]
    enabled = false

    [mint_info]
    name = "cdk mutinynet mint"
    description = "A CDK mint on Mutinynet for testing"
    description_long = "This mint runs on Mutinynet (signet) using an integrated LDK node. Not real sats."
    motd = "Mutinynet testing mint"
    contact_email = "tsk@thesimplekid.com"

    [database]
    engine = "sqlite"

    [database.sqlite]
    path = "/var/lib/cdk-mintd-mutiny/cdk-mintd.sqlite"

    [ln]
    ln_backend = "ldknode"

    [ldk_node]
    fee_percent = 0.02
    reserve_fee_min = 2
    bitcoin_network = "signet"
    chain_source_type = "esplora"
    ldk_node_mnemonic = "@MINT_MNEMONIC@"
    esplora_url = "https://mutinynet.com/api"
    gossip_source_type = "rgs"
    rgs_url = "https://rgs.mutinynet.com/snapshot/0"
    storage_dir_path = "/var/lib/cdk-mintd-mutiny/ldk-node"
    log_dir_path = "/var/lib/cdk-mintd-mutiny/ldk-node/ldk_node.log"

    ldk_node_host = "0.0.0.0"
    ldk_node_port = 9735


    [limits]
    max_inputs = 1000
    max_outputs = 1000
  '';

  # The cdk-mintd LDK binary from the static package
  cdkMintdLdkBin = pkgs.writeShellScriptBin "cdk-mintd-ldk" ''
    exec $(find ${cdkMintdLdk}/bin -type f -name 'cdk-mintd*' | head -1) "$@"
  '';

in {
  # Import common modules
  imports = [
    ../../modules/common.nix
  ];

  # Boot configuration
  boot.loader.grub = {
    enable = true;
    device = "nodev";
    devices = lib.mkForce [ ];
    efiSupport = false;
    mirroredBoots = [
      {
        path = "/boot";
        devices = [ "/dev/sda" ];
      }
    ];
  };
  boot.loader.efi.canTouchEfiVariables = false;
  boot.kernelParams = [
    "net.ifnames=0"
    "biosdevname=0"
    "console=tty0"
    "console=ttyS0,115200n8"
  ];

  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.tmp.cleanOnBoot = true;

  # This host intentionally runs without swap.

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
  cdk.enableDockerCleanup = false;
  networking = {
    inherit hostName;
    enableIPv6 = true;
    useDHCP = false;
    interfaces.eth0 = {
      ipv4.addresses = [
        {
          address = "80.71.235.189";
          prefixLength = 24;
        }
      ];
    };
    defaultGateway = {
      address = "80.71.235.1";
      interface = "eth0";
    };
    nameservers = [ "9.9.9.9" "149.112.112.112" ];
    firewall = {
      enable = true;
      allowPing = true;
      allowedTCPPorts = [ 22 80 443 9735 ];
    };
  };

  users.users.root.openssh.authorizedKeys.keys = adminKeys;

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
      auto-optimise-store = true;
    };
  };

  services.journald.extraConfig = "SystemMaxUse=1G";

  # System packages
  environment.systemPackages = map lib.lowPrio [
    pkgs.curl
    pkgs.gitMinimal
    pkgs.helix
    pkgs.tmux
    pkgs.btop
    pkgs.htop
    pkgs.psmisc
    inputs.agenix.packages."${pkgs.system}".default
  ];

  # ============================================================
  # Caddy - Reverse proxy with automatic HTTPS
  # ============================================================
  services.caddy = {
    enable = true;
    # Import the runtime-generated dash config (with basic auth secret)
    extraConfig = ''
      import /var/lib/caddy/dash.caddy
    '';
    virtualHosts."${mintDomain}" = {
      extraConfig = ''
        reverse_proxy ${mintListenHost}:${toString mintListenPort}
      '';
    };
    virtualHosts."${mint2Domain}" = {
      extraConfig = ''
        reverse_proxy ${mint2ListenHost}:${toString mint2ListenPort}
      '';
    };
    virtualHosts."${forgejoDomain}" = {
      extraConfig = ''
        reverse_proxy ${forgejoListenHost}:${toString forgejoListenPort}
      '';
    };
  };

  # Inject the bcrypt hash into the dash Caddyfile snippet before Caddy starts
  systemd.services.caddy = {
    after = [ "agenix.service" ];
    preStart = ''
      hash=$(tr -d '\n' < /run/secrets/caddy/dash-basicauth-hash)
      install -m 0400 -o caddy -g caddy ${dashCaddyTemplate} /var/lib/caddy/dash.caddy
      ${pkgs.gnused}/bin/sed -i "s|@BCRYPT_HASH@|$hash|" /var/lib/caddy/dash.caddy
    '';
  };

  # ============================================================
  # Forgejo - Self-hosted Git forge
  # ============================================================
  services.forgejo = {
    enable = true;
    package = pkgs.forgejo;
    stateDir = "/var/lib/forgejo";
    settings = {
      server = {
        DOMAIN = forgejoDomain;
        ROOT_URL = "https://${forgejoDomain}/";
        HTTP_ADDR = forgejoListenHost;
        HTTP_PORT = forgejoListenPort;
        DISABLE_SSH = true;
      };
      service = {
        DISABLE_REGISTRATION = false;
      };
      actions = {
        ENABLED = true;
      };
      mailer = {
        ENABLED = false;
      };
      session = {
        COOKIE_SECURE = true;
      };
    };
  };

  # ============================================================
  # cdk-mintd service
  # ============================================================

  # System user for cdk-mintd
  users.groups.cdk-mintd = {};
  users.users.cdk-mintd = {
    isSystemUser = true;
    group = "cdk-mintd";
    home = "/var/lib/cdk-mintd";
    createHome = true;
  };

  age.secrets.cdk-mintd-mnemonic = {
    file = ../../secrets/cdk-mintd-mnemonic.age;
    path = "/run/secrets/cdk-mintd/mnemonic";
    owner = "cdk-mintd";
    group = "cdk-mintd";
    mode = "0400";
  };

  # Bcrypt hash for dash.mutiny basic auth (generate with: caddy hash-password)
  age.secrets.dash-basicauth-hash = {
    file = ../../secrets/dash-basicauth-hash.age;
    path = "/run/secrets/caddy/dash-basicauth-hash";
    owner = "caddy";
    group = "caddy";
    mode = "0400";
  };

  systemd.services.cdk-mintd = {
    description = "CDK Mint Daemon";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "agenix.service" ];
    wants = [ "network-online.target" ];

    preStart = ''
      install -d -m 0750 -o cdk-mintd -g cdk-mintd /var/lib/cdk-mintd/runtime
      mnemonic=$(tr -d '\n' < /run/secrets/cdk-mintd/mnemonic)
      install -m 0400 -o cdk-mintd -g cdk-mintd ${mintConfigTemplate} /var/lib/cdk-mintd/runtime/config.toml
      ${pkgs.gnused}/bin/sed -i "s|@MINT_MNEMONIC@|$mnemonic|" /var/lib/cdk-mintd/runtime/config.toml
    '';

    serviceConfig = {
      Type = "simple";
      User = "cdk-mintd";
      Group = "cdk-mintd";
      Environment = "RUST_LOG=debug";
      ExecStart = "${cdkMintdBin}/bin/cdk-mintd --config /var/lib/cdk-mintd/runtime/config.toml";
      Restart = "always";
      RestartSec = "5s";
      StateDirectory = "cdk-mintd";
      StateDirectoryMode = "0750";
      WorkingDirectory = "/var/lib/cdk-mintd";

      # Hardening
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      ReadWritePaths = [ "/var/lib/cdk-mintd" ];
    };
  };

  # ============================================================
  # cdk-mintd-mutiny service (Mutinynet LDK node)
  # ============================================================

  # System user for cdk-mintd-mutiny
  users.groups.cdk-mintd-mutiny = {};
  users.users.cdk-mintd-mutiny = {
    isSystemUser = true;
    group = "cdk-mintd-mutiny";
    home = "/var/lib/cdk-mintd-mutiny";
    createHome = true;
  };

  age.secrets.cdk-mintd-mutiny-mnemonic = {
    file = ../../secrets/cdk-mintd-mutiny-mnemonic.age;
    path = "/run/secrets/cdk-mintd-mutiny/mnemonic";
    owner = "cdk-mintd-mutiny";
    group = "cdk-mintd-mutiny";
    mode = "0400";
  };

  systemd.services.cdk-mintd-mutiny = {
    description = "CDK Mint Daemon (Mutinynet LDK)";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "agenix.service" ];
    wants = [ "network-online.target" ];

    preStart = ''
      install -d -m 0750 -o cdk-mintd-mutiny -g cdk-mintd-mutiny /var/lib/cdk-mintd-mutiny/runtime
      install -d -m 0750 -o cdk-mintd-mutiny -g cdk-mintd-mutiny /var/lib/cdk-mintd-mutiny/ldk-node
      mnemonic=$(tr -d '\n' < /run/secrets/cdk-mintd-mutiny/mnemonic)
      install -m 0400 -o cdk-mintd-mutiny -g cdk-mintd-mutiny ${mint2ConfigTemplate} /var/lib/cdk-mintd-mutiny/runtime/config.toml
      ${pkgs.gnused}/bin/sed -i "s|@MINT_MNEMONIC@|$mnemonic|g" /var/lib/cdk-mintd-mutiny/runtime/config.toml
    '';

    serviceConfig = {
      Type = "simple";
      User = "cdk-mintd-mutiny";
      Group = "cdk-mintd-mutiny";
      Environment = "RUST_LOG=debug";
      ExecStart = "${cdkMintdLdkBin}/bin/cdk-mintd-ldk --config /var/lib/cdk-mintd-mutiny/runtime/config.toml";
      Restart = "always";
      RestartSec = "5s";
      StateDirectory = "cdk-mintd-mutiny";
      StateDirectoryMode = "0750";
      WorkingDirectory = "/var/lib/cdk-mintd-mutiny";

      # Hardening
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      ReadWritePaths = [ "/var/lib/cdk-mintd-mutiny" ];
    };
  };
}
