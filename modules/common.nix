{ pkgs, ... }:

let
  gcNix = "gc-nix-store";
  cleanupDocker = "cleanup-docker";
in
{
  services.sysstat = {
    enable = true;
    collect-frequency = "*:00/1";
  };

  systemd.services.${gcNix} =
    let
      script = pkgs.writeShellScript "gc-nix-store" ''
        ${pkgs.nix}/bin/nix-collect-garbage -d --delete-older-than 7d
      '';
    in
    {
      description = "GC the /nix store";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = script;
        User = "root";
      };
    };

  systemd.timers.${gcNix} = {
    description = "Timer for gc the /nix store";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = "daily";
    };
  };

  systemd.services.${cleanupDocker} =
    let
      script = pkgs.writeShellScript "cleanup-docker" ''
        ${pkgs.docker}/bin/docker image prune -af --filter "until=48h"
      '';
    in
    {
      description = "Clean up old docker images";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = script;
        User = "root";
      };
    };

  systemd.timers.${cleanupDocker} = {
    description = "Timer for cleaning up docker images";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = "daily";
    };
  };

  services.automatic-timezoned.enable = false;
  time.timeZone = "UTC";

  environment.systemPackages = [
    pkgs.sysstat
    pkgs.jq
  ];
}
