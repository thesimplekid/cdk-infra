# Runner IPs/hostnames
runner_01_ip := "49.13.4.180"
runner_01_host := "cdk-runner-01.cashudevkit.org"
runner_02_ip := "91.99.191.146"
runner_02_host := "cdk-runner-02.cashudevkit.org"

default:
  @just --list

# ============ Generic Commands ============

# Apply configuration to a host
apply HOST SSH_HOST:
  nixos-rebuild switch --cores 8 -L --flake .#{{HOST}} --target-host "{{SSH_HOST}}"

# Bootstrap host using nixos-anywhere
bootstrap HOST SSH_HOST:
  nix run github:nix-community/nixos-anywhere -- --flake .#{{HOST}} {{SSH_HOST}}

# Build host configuration locally (test before deploying)
build HOST:
  nix build -L ".#nixosConfigurations.{{HOST}}.config.system.build.toplevel"

# Show runner status via SSH
status HOST:
  ssh root@{{HOST}} systemctl status 'github-runner-*'

# Show storage overview via SSH
storage HOST:
  ssh root@{{HOST}} sudo runner-storage

# Copy GitHub runner token to a host and restart controller
set-token SSH_HOST TOKEN:
  echo "{{TOKEN}}" | ssh "{{SSH_HOST}}" 'mkdir -p /run/secrets/github-runner && cat > /run/secrets/github-runner/token && chmod 644 /run/secrets/github-runner/token && systemctl restart runner-controller'

# ============ Runner 01 Commands ============

# Apply to cdk-runner-01
apply-runner-01:
  just apply cdk-runner-01 "root@{{runner_01_ip}}"

# Bootstrap cdk-runner-01
bootstrap-runner-01 IP=runner_01_ip:
  just bootstrap cdk-runner-01 "root@{{IP}}"

# Build runner-01 config
build-runner-01:
  just build cdk-runner-01

# Show runner-01 status
status-runner-01:
  just status {{runner_01_host}}

# Show runner-01 storage
storage-runner-01:
  just storage {{runner_01_host}}

# Set token for runner-01
set-token-runner-01 TOKEN:
  just set-token "root@{{runner_01_host}}" "{{TOKEN}}"

# ============ Runner 02 Commands ============

# Apply to cdk-runner-02
apply-runner-02:
  just apply cdk-runner-02 "root@{{runner_02_ip}}"

# Bootstrap cdk-runner-02
bootstrap-runner-02 IP=runner_02_ip:
  just bootstrap cdk-runner-02 "root@{{IP}}"

# Build runner-02 config
build-runner-02:
  just build cdk-runner-02

# Show runner-02 status
status-runner-02:
  just status {{runner_02_host}}

# Show runner-02 storage
storage-runner-02:
  just storage {{runner_02_host}}

# Set token for runner-02
set-token-runner-02 TOKEN:
  just set-token "root@{{runner_02_host}}" "{{TOKEN}}"

# ============ All Runners Commands ============

# Apply to all runners
apply-all:
  just apply-runner-01
  just apply-runner-02

# Build all runner configs
build-all:
  just build-runner-01
  just build-runner-02

# Show status for all runners
status-all:
  @echo "=== Runner 01 ==="
  -just status-runner-01
  @echo ""
  @echo "=== Runner 02 ==="
  -just status-runner-02

# Show storage for all runners
storage-all:
  @echo "=== Runner 01 ==="
  just storage-runner-01
  @echo ""
  @echo "=== Runner 02 ==="
  just storage-runner-02

# ============ Secrets Management ============

# Edit agenix secret
agenix-edit PATH="secrets/github-runner.age" IDENTITY="$HOME/.ssh/id_ed25519":
  agenix -e "{{PATH}}" -i "{{IDENTITY}}"

# Rekey all secrets (run after adding new host keys)
agenix-rekey IDENTITY="$HOME/.ssh/id_ed25519":
  agenix -r -i "{{IDENTITY}}"

# ============ Validation ============

# Check flake for problems
check:
  nix flake check
  just --evaluate
