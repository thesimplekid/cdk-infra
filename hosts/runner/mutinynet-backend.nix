{ pkgs, ... }:

let
  esploraDomain = "esplora.mutiny.cashudevkit.org";
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
    rpcbind=0.0.0.0:38332
    rpcallowip=0.0.0.0/0
    zmqpubrawblock=tcp://0.0.0.0:28332
    zmqpubrawtx=tcp://0.0.0.0:28333
    EOF

    addnodes=''${ADDNODES:-''${ADDNODE:-45.79.52.207:38333}}
    printf "%s" "$addnodes" | tr ',' '\n' | while IFS= read -r node; do
      [ -n "$node" ] || continue
      printf "addnode=%s\n" "$node" >> /root/.bitcoin/bitcoin.conf
    done

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
in
{
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
        ADDNODES = "45.79.52.207:38333,80.71.235.189:38333";
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

  services.caddy = {
    enable = true;
    virtualHosts."${esploraDomain}".extraConfig = ''
      reverse_proxy 127.0.0.1:3003
    '';
  };

  networking.firewall.allowedTCPPorts = [ 80 443 ];
}
