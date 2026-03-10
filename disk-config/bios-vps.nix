# Disk configuration for VPSes that boot with BIOS grub but still
# expect an EFI system partition in the stock image layout.
{ lib, ... }: {
  disko.devices = {
    disk.main = {
      device = "/dev/sda";
      type = "disk";
      content = {
        type = "gpt";
        partitions = {
          bios = {
            size = "1M";
            type = "EF02";
          };
          esp = {
            size = "122M";
            type = "EF00";
            content = {
              type = "filesystem";
              format = "vfat";
              mountpoint = "/boot/efi";
            };
          };
          root = {
            size = "100%";
            content = {
              type = "filesystem";
              format = "ext4";
              mountpoint = "/";
            };
          };
        };
      };
    };
  };

  # Force use of device paths
  fileSystems."/boot/efi" = lib.mkForce {
    device = "/dev/sda2";
    fsType = "vfat";
  };

  fileSystems."/" = lib.mkForce {
    device = "/dev/sda3";
    fsType = "ext4";
  };

  swapDevices = lib.mkForce [ ];
}
