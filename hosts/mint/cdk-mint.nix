# CDK Mint Server Configuration
# Runs cdk-mintd with PostgreSQL backend, fronted by Caddy for automatic HTTPS
{ config, pkgs, lib, hostName, adminKeys, inputs, cdkMintd, cdkMintdLdk, cdkMintdOnchain, cdkMintdBls, ... }:

let
  # Mint configuration
  mintDomain = "testnut.cashudevkit.org";
  mintListenHost = "127.0.0.1";
  mintListenPort = 8085;

  # Mutinynet mint configuration
  mint2Domain = "mutiny.cashudevkit.org";
  mint2ListenHost = "127.0.0.1";
  mint2ListenPort = 8086;

  # Onchain mutinynet mint configuration
  onchainDomain = "onchain.cashudevkit.org";
  onchainListenHost = "127.0.0.1";
  onchainListenPort = 8087;

  # BLS fake mint configuration
  blsDomain = "bls.thesimplekid.dev";
  blsListenHost = "127.0.0.1";
  blsListenPort = 8088;

  # Mutinynet LDK dashboard configuration
  dashDomain = "dash.mutiny.cashudevkit.org";
  dashUpstreamPort = 8091;

  # Private local Mutinynet Esplora backend for the onchain mint.
  mutinynetBitcoindImage = "localhost/cdk-mutinynet-bitcoind:d091f70435c9";
  mutinynetContainerNetwork = "cdk-mutinynet";

  mutinynetBitcoindEntrypoint = pkgs.writeText "mutinynet-bitcoind-entrypoint.sh" ''
    #!/bin/sh
    set -eu

    mkdir -p /root/.bitcoin
    cat > /root/.bitcoin/bitcoin.conf <<EOF
    signet=1
    txindex=1
    blockfilterindex=1
    peerblockfilters=1
    coinstatsindex=1
    dnsseed=0
    persistmempool=1
    uacomment=''${UACOMMENT:-MutinyNet}
    dbcache=''${DBCACHE:-150}

    [signet]
    server=1
    listen=1
    rest=1
    acceptnonstdtxn=1
    v2transport=1
    signetblocktime=''${BLOCKPRODUCTIONDELAY:-30}
    signetchallenge=''${SIGNETCHALLENGE}
    addnode=''${ADDNODE:-45.79.52.207:38333}
    rpcbind=0.0.0.0:38332
    rpcallowip=0.0.0.0/0
    zmqpubrawblock=tcp://0.0.0.0:28332
    zmqpubrawtx=tcp://0.0.0.0:28333
    EOF

    exec /usr/local/bin/bitcoind \
      -datadir=/root/.bitcoin \
      -conf=/root/.bitcoin/bitcoin.conf \
      -printtoconsole
  '';

  mutinynetBitcoindDockerfile = pkgs.writeText "mutinynet-bitcoind.Dockerfile" ''
    FROM debian:bookworm-slim

    ARG BITCOIN_VERSION=d091f70435c9
    ARG BITCOIN_SHA256=9ec137bbaf7c3187eb138745f77dab5d50e668dd2e0649e46a0bd760415bdf0d
    ARG BITCOIN_URL=https://github.com/benthecarman/bitcoin/releases/download/mutinynet-inq-29/bitcoin-d091f70435c9-x86_64-linux-gnu.tar.gz

    RUN apt-get update \
      && apt-get install -y --no-install-recommends ca-certificates coreutils wget \
      && rm -rf /var/lib/apt/lists/*

    WORKDIR /tmp
    RUN wget -O bitcoin.tar.gz "$BITCOIN_URL" \
      && echo "$BITCOIN_SHA256  bitcoin.tar.gz" | sha256sum -c - \
      && mkdir -p /tmp/bitcoin \
      && tar -xzf bitcoin.tar.gz -C /tmp/bitcoin --strip-components=1 \
      && install -m 0755 /tmp/bitcoin/bin/bitcoind /usr/local/bin/bitcoind \
      && install -m 0755 /tmp/bitcoin/bin/bitcoin-cli /usr/local/bin/bitcoin-cli \
      && install -m 0755 /tmp/bitcoin/bin/bitcoin-wallet /usr/local/bin/bitcoin-wallet \
      && install -m 0755 /tmp/bitcoin/bin/bitcoin-util /usr/local/bin/bitcoin-util \
      && rm -rf /tmp/bitcoin /tmp/bitcoin.tar.gz

    COPY entrypoint.sh /usr/local/bin/entrypoint.sh
    RUN chmod +x /usr/local/bin/entrypoint.sh

    VOLUME ["/root/.bitcoin"]
    EXPOSE 28332 28333 38332 38333
    ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
  '';

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
    min_mint = 1
    max_mint = 500000
    min_melt = 1
    max_melt = 500000

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

  blsConfigTemplate = pkgs.writeText "cdk-mintd-bls-config.toml.tpl" ''
    [info]
    url = "https://${blsDomain}/"
    listen_host = "${blsListenHost}"
    listen_port = ${toString blsListenPort}
    mnemonic = "@MINT_MNEMONIC@"
    input_fee_ppk = 100

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
    name = "cdk bls test mint"
    description = "These are not real sats for testing only"
    description_long = "These sats are not backed by anything and should only be used for BLS testing"
    motd = "BLS fake sats for testing"
    contact_email = "tsk@thesimplekid.com"

    [database]
    engine = "sqlite"

    [database.sqlite]
    path = "/var/lib/cdk-mintd-bls/cdk-mintd.sqlite"

    [ln]
    ln_backend = "fakewallet"
    min_mint = 1
    max_mint = 500000
    min_melt = 1
    max_melt = 500000

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

  cdkMintdBlsBin = pkgs.writeShellScriptBin "cdk-mintd-bls" ''
    exec $(find ${cdkMintdBls}/bin -type f -name 'cdk-mintd*' | head -1) "$@"
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
    min_mint = 1
    max_mint = 500000
    min_melt = 1
    max_melt = 500000

    [ldk_node]
    fee_percent = 0.02
    reserve_fee_min = 2
    bitcoin_network = "signet"
    chain_source_type = "esplora"
    ldk_node_mnemonic = "@MINT_MNEMONIC@"
    # esplora_url = "https://mutinynet.com/api"
    esplora_url = "http://127.0.0.1:3003"
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

  # Mutinynet mint config template (onchain backend on signet/mutinynet)
  onchainConfigTemplate = pkgs.writeText "cdk-mintd-onchain-config.toml.tpl" ''
    [info]
    url = "https://${onchainDomain}/"
    listen_host = "${onchainListenHost}"
    listen_port = ${toString onchainListenPort}
    mnemonic = "@MINT_MNEMONIC@"

    [info.quote_ttl]
    mint_ttl = 600
    melt_ttl = 120

    [info.http_cache]
    backend = "memory"
    ttl = 60
    tti = 60

    [info.logging]
    # Where to output logs: "stderr" (standard error stream), "file", or "both" (default: "both")
    output = "both"
    # Log level for console output (default: "info")
    console_level = "debug"  


    [mint_management_rpc]
    enabled = false

    [mint_info]
    name = "cdk onchain test mint"
    description = "A CDK onchain mint on Mutinynet for testing"
    description_long = "This mint runs on Mutinynet (signet) using the onchain backend. Not real sats."
    motd = "Mutinynet onchain testing mint"
    contact_email = "tsk@thesimplekid.com"

    [database]
    engine = "sqlite"

    [database.sqlite]
    path = "/var/lib/cdk-mintd-onchain/cdk-mintd.sqlite"

    [ln]
    # Required ln backend `cln`, `lnd`, `fakewallet`, 'lnbits'
    # ln_backend = "grpcprocessor"
    ln_backend = "none"
    min_mint = 1
    max_mint = 500000
    min_melt = 1
    max_melt = 500000

    [onchain]
    onchain_backend = "bdk"
    min_mint=1
    max_mint=500000
    min_melt=1
    max_melt=500000

    [bdk]
    network = "signet"
    chain_source_type = "esplora"
    # Switch this to http://127.0.0.1:3003 after mutinynet-electrs finishes indexing.
    # esplora_url = "https://mutinynet.com/api"
    esplora_url = "http://127.0.0.1:3003"
    mnemonic = "@MINT_MNEMONIC@"
    num_confs = 2
    fee_percent = 0.02
    reserve_fee_min = 2

    [bdk.batch_config]
    quote_fixed_safety_sat = 200      # flat sats added after the raw fee estimate
    fee_options = ["immediate", "standard", "economy"]



    [limits]
    max_inputs = 1000
    max_outputs = 1000
    '';

  # The cdk-mintd LDK binary from the static package
  cdkMintdLdkBin = pkgs.writeShellScriptBin "cdk-mintd-ldk" ''
    exec $(find ${cdkMintdLdk}/bin -type f -name 'cdk-mintd*' | head -1) "$@"
  '';

  cdkMintdOnchainBin = pkgs.writeShellScriptBin "cdk-mintd-onchain" ''
    exec $(find ${cdkMintdOnchain}/bin -type f -name 'cdk-mintd*' | head -1) "$@"
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

  # Swap: the VM has only ~2 GiB RAM and bitcoind IBD on Mutinynet (with
  # txindex + blockfilterindex + coinstatsindex) can push RSS past that,
  # leading to kernel OOM kills that restart bitcoind mid-sync. A 4 GiB
  # swapfile gives the kernel somewhere to page cold pages and lets IBD
  # complete without repeated OOM restarts.
  swapDevices = [
    {
      device = "/var/lib/swapfile";
      size = 4096; # MiB
    }
  ];
  # Prefer to avoid swap unless we really need it — keep hot paths in RAM.
  boot.kernel.sysctl."vm.swappiness" = 10;

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
    inputs.agenix.packages."${pkgs.stdenv.hostPlatform.system}".default
  ];

  # ============================================================
  # Private Mutinynet Esplora backend
  # ============================================================
  virtualisation.podman = {
    enable = true;
    dockerCompat = true;
  };
  virtualisation.oci-containers.backend = "podman";

  systemd.tmpfiles.rules = [
    "d /var/lib/mutinynet-bitcoind 0750 root root -"
    "d /var/lib/mutinynet-electrs 0750 root root -"
  ];

  systemd.services.mutinynet-container-network = {
    description = "Create private Mutinynet container network";
    wantedBy = [ "multi-user.target" ];
    after = [ "podman.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      ${pkgs.podman}/bin/podman network exists ${mutinynetContainerNetwork} \
        || ${pkgs.podman}/bin/podman network create ${mutinynetContainerNetwork}
    '';
  };

  systemd.services.mutinynet-bitcoind-image = {
    description = "Build Mutinynet bitcoind container image";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "podman.service" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      context=/var/lib/mutinynet-bitcoind-image/context
      install -d -m 0755 "$context"
      install -m 0644 ${mutinynetBitcoindDockerfile} "$context/Dockerfile"
      install -m 0755 ${mutinynetBitcoindEntrypoint} "$context/entrypoint.sh"
      ${pkgs.podman}/bin/podman build -t ${mutinynetBitcoindImage} "$context"
    '';
  };

  virtualisation.oci-containers.containers = {
    mutinynet-bitcoind = {
      image = mutinynetBitcoindImage;
      autoStart = true;
      volumes = [
        "/var/lib/mutinynet-bitcoind:/root/.bitcoin"
      ];
      environment = {
        UACOMMENT = "MutinyNet";
        SIGNETCHALLENGE = "512102f7561d208dd9ae99bf497273e16f389bdbd6c4742ddb8e6b216e64fa2928ad8f51ae";
        ADDNODE = "45.79.52.207:38333";
        BLOCKPRODUCTIONDELAY = "30";
        DBCACHE = "150";
      };
      extraOptions = [
        "--network=${mutinynetContainerNetwork}"
        "--network-alias=mutinynet-bitcoind"
      ];
    };

    mutinynet-electrs = {
      image = "mempool/electrs:v3.3.0";
      autoStart = true;
      dependsOn = [ "mutinynet-bitcoind" ];
      volumes = [
        "/var/lib/mutinynet-bitcoind:/root/.bitcoin:ro"
        "/var/lib/mutinynet-electrs:/root/.electrs"
      ];
      cmd = [
        "-c"
        ''
          while [ ! -s /root/.bitcoin/signet/.cookie ]; do
            sleep 1
          done

          exec /bin/electrs \
            -vvvv \
            --address-search \
            --cookie "$(cat /root/.bitcoin/signet/.cookie)" \
            --network signet \
            --daemon-rpc-addr mutinynet-bitcoind:38332 \
            --blocks-dir /root/.bitcoin/signet/blocks \
            --timestamp \
            --jsonrpc-import \
            --db-dir /root/.electrs \
            --electrum-rpc-addr 0.0.0.0:50001 \
            --http-addr 0.0.0.0:3003 \
            --electrum-banner "CDK Mutinynet Electrum Server"
        ''
      ];
      ports = [
        "127.0.0.1:3003:3003"
        "127.0.0.1:50001:50001"
      ];
      extraOptions = [
        "--entrypoint=/bin/sh"
        "--network=${mutinynetContainerNetwork}"
      ];
    };
  };

  systemd.services.podman-mutinynet-bitcoind = {
    after = [ "mutinynet-container-network.service" "mutinynet-bitcoind-image.service" ];
    requires = [ "mutinynet-container-network.service" "mutinynet-bitcoind-image.service" ];
  };

  systemd.services.podman-mutinynet-electrs = {
    after = [ "mutinynet-container-network.service" "podman-mutinynet-bitcoind.service" ];
    requires = [ "mutinynet-container-network.service" ];
  };

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
    virtualHosts."${onchainDomain}" = {
      extraConfig = ''
        reverse_proxy ${onchainListenHost}:${toString onchainListenPort}
      '';
    };
    virtualHosts."${blsDomain}" = {
      extraConfig = ''
        reverse_proxy ${blsListenHost}:${toString blsListenPort}
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

  age.secrets.cdk-mintd-bls-mnemonic = {
    file = ../../secrets/cdk-mintd-mnemonic.age;
    path = "/run/secrets/cdk-mintd-bls/mnemonic";
    owner = "cdk-mintd-bls";
    group = "cdk-mintd-bls";
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
  # cdk-mintd-bls service (BLS fake mint)
  # ============================================================

  users.groups.cdk-mintd-bls = {};
  users.users.cdk-mintd-bls = {
    isSystemUser = true;
    group = "cdk-mintd-bls";
    home = "/var/lib/cdk-mintd-bls";
    createHome = true;
  };

  systemd.services.cdk-mintd-bls = {
    description = "CDK Mint Daemon (BLS fakewallet)";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "agenix.service" ];
    wants = [ "network-online.target" ];

    preStart = ''
      install -d -m 0750 -o cdk-mintd-bls -g cdk-mintd-bls /var/lib/cdk-mintd-bls/runtime
      mnemonic=$(tr -d '\n' < /run/secrets/cdk-mintd-bls/mnemonic)
      install -m 0400 -o cdk-mintd-bls -g cdk-mintd-bls ${blsConfigTemplate} /var/lib/cdk-mintd-bls/runtime/config.toml
      ${pkgs.gnused}/bin/sed -i "s|@MINT_MNEMONIC@|$mnemonic|g" /var/lib/cdk-mintd-bls/runtime/config.toml
    '';

    serviceConfig = {
      Type = "simple";
      User = "cdk-mintd-bls";
      Group = "cdk-mintd-bls";
      Environment = "RUST_LOG=debug";
      ExecStart = "${cdkMintdBlsBin}/bin/cdk-mintd-bls --config /var/lib/cdk-mintd-bls/runtime/config.toml";
      Restart = "always";
      RestartSec = "5s";
      StateDirectory = "cdk-mintd-bls";
      StateDirectoryMode = "0750";
      WorkingDirectory = "/var/lib/cdk-mintd-bls";

      # Hardening
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      ReadWritePaths = [ "/var/lib/cdk-mintd-bls" ];
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

  age.secrets.cdk-mintd-onchain-mnemonic = {
    file = ../../secrets/cdk-mintd-onchain-mnemonic.age;
    path = "/run/secrets/cdk-mintd-onchain/mnemonic";
    owner = "cdk-mintd-onchain";
    group = "cdk-mintd-onchain";
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

  # ============================================================
  # cdk-mintd-onchain service (Mutinynet onchain backend)
  # ============================================================

  users.groups.cdk-mintd-onchain = {};
  users.users.cdk-mintd-onchain = {
    isSystemUser = true;
    group = "cdk-mintd-onchain";
    home = "/var/lib/cdk-mintd-onchain";
    createHome = true;
  };

  systemd.services.cdk-mintd-onchain = {
    description = "CDK Mint Daemon (Mutinynet onchain)";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "agenix.service" "podman-mutinynet-electrs.service" ];
    wants = [ "network-online.target" "podman-mutinynet-electrs.service" ];

    preStart = ''
      install -d -m 0750 -o cdk-mintd-onchain -g cdk-mintd-onchain /var/lib/cdk-mintd-onchain/runtime
      mnemonic=$(tr -d '\n' < /run/secrets/cdk-mintd-onchain/mnemonic)
      install -m 0400 -o cdk-mintd-onchain -g cdk-mintd-onchain ${onchainConfigTemplate} /var/lib/cdk-mintd-onchain/runtime/config.toml
      ${pkgs.gnused}/bin/sed -i "s|@MINT_MNEMONIC@|$mnemonic|g" /var/lib/cdk-mintd-onchain/runtime/config.toml
    '';

    serviceConfig = {
      Type = "simple";
      User = "cdk-mintd-onchain";
      Group = "cdk-mintd-onchain";
      Environment = "RUST_LOG=debug";
      ExecStart = "${cdkMintdOnchainBin}/bin/cdk-mintd-onchain --config /var/lib/cdk-mintd-onchain/runtime/config.toml";
      Restart = "always";
      RestartSec = "5s";
      StateDirectory = "cdk-mintd-onchain";
      StateDirectoryMode = "0750";
      WorkingDirectory = "/var/lib/cdk-mintd-onchain";

      # Hardening
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      ReadWritePaths = [ "/var/lib/cdk-mintd-onchain" ];
    };
  };
}
