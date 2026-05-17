# Resource limits for ephemeral CI containers
{ config, lib, ... }:

{
  # Apply resource limits to all runner containers via systemd.
  # Runner hosts are 16-core / 32 GB machines. The warm pool has six slots;
  # these per-container caps keep individual Rust-heavy jobs bounded, but
  # simultaneous peak usage can still overcommit the host.
  # Note: Wildcard matching for dynamic container names
  systemd.services."container@" = {
    serviceConfig = {
      # CPU: 3.5 cores per container
      CPUQuota = "350%";
      CPUWeight = 100;

      # Memory: 7 GB per container
      MemoryMax = "7G";
      MemoryHigh = "6G";
      MemorySwapMax = "0";  # No swap

      # Tasks limit (prevent fork bombs)
      TasksMax = 2000;

      # I/O limits
      IOWeight = 100;
    };
  };

  # System-wide limits
  boot.kernel.sysctl = {
    # Increase max user namespaces for containers
    "user.max_user_namespaces" = 15000;

    # Network tuning
    "net.ipv4.ip_forward" = 1;
  };
}
