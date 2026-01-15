{ pkgs, ... }:

let
  cleanupDocker = "cleanup-docker";
in
{
  nix.gc = {
    automatic = true;
    persistent = true;
    dates = "daily";
    options = "--delete-older-than 7d";
  };

  services.sysstat = {
    enable = true;
    collect-frequency = "*:00/1";
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
