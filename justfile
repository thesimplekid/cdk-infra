default:
  @just --list

# Apply configuration to a host
apply HOST SSH_HOST:
  nixos-rebuild switch --cores 8 -L --flake .#{{HOST}} --target-host "{{SSH_HOST}}"

# Apply to cdk-runner-01
apply-runner-01:
  just apply cdk-runner-01 "root@46.62.230.211"

# Bootstrap host using nixos-anywhere
bootstrap HOST SSH_HOST:
  nix run github:nix-community/nixos-anywhere -- --flake .#{{HOST}} {{SSH_HOST}}

# Bootstrap cdk-runner-01
bootstrap-runner-01 IP:
  just bootstrap cdk-runner-01 "root@{{IP}}"

# Edit agenix secret
agenix-edit PATH="secrets/github-runner.age" IDENTITY="$HOME/.ssh/id_ed25519.cdk":
  agenix -e "{{PATH}}" -i "{{IDENTITY}}"

# Rekey all secrets (run after adding new host keys)
agenix-rekey IDENTITY="$HOME/.ssh/id_ed25519.cdk":
  agenix -r -i "{{IDENTITY}}"

# Build host configuration locally (test before deploying)
build HOST:
  nix build -L ".#nixosConfigurations.{{HOST}}.config.system.build.toplevel"

# Build runner-01 config
build-runner-01:
  just build cdk-runner-01

# Check flake for problems
check:
  nix flake check
  just --evaluate

# Show runner status via SSH
status HOST:
  ssh root@{{HOST}} systemctl status 'github-runner-*'

# Show runner-01 status
status-runner-01:
  just status cdk-runner-01.cashudevkit.org

# Show storage overview via SSH
storage HOST:
  ssh root@{{HOST}} sudo runner-storage

# Show runner-01 storage
storage-runner-01:
  just storage cdk-runner-01.cashudevkit.org
# Copy GitHub runner token to a host and restart controller
set-token SSH_HOST TOKEN:
  echo "{{TOKEN}}" | ssh "{{SSH_HOST}}" 'mkdir -p /run/secrets/github-runner && cat > /run/secrets/github-runner/token && chmod 644 /run/secrets/github-runner/token && systemctl restart runner-controller'