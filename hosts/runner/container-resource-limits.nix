# Resource limits for ephemeral CI containers
{ config, lib, ... }:

{
  # Apply resource limits to all ci- containers via systemd
  # Note: Wildcard matching for dynamic container names
  systemd.services."container@" = {
    serviceConfig = {
      # CPU: 8 cores per container
      CPUQuota = "800%";
      CPUWeight = 100;

      # Memory: 16 GB per container
      MemoryMax = "16G";
      MemoryHigh = "14G";
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
