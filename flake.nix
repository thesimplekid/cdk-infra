{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    agenix.url = "github:ryantm/agenix";
  };

  outputs = { nixpkgs, disko, agenix, ... }@inputs:
    let
      adminKeys = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJiA6Oq79afOa48iyOVfs7iVbs3Ug9Elj8GdtWLs2UcD tsk@thesimplekid.com"
      ];

      topLevelModule = {
        nixpkgs = {
          overlays = [ ];
        };
        nix = {
          registry = {
            nixpkgs.flake = nixpkgs;
          };
          nixPath = [ "nixpkgs=${nixpkgs}" ];
        };
      };

      makeRunnerVps = name:
        nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            topLevelModule
            ./modules/nixos-nixpkgs-last-modified.nix

            disko.nixosModules.disko
            agenix.nixosModules.default

            ./disk-config/hetzner-vps.nix
            ./hosts/runner/job-listener.nix  # On-demand containers (ARC-style)
            ./hosts/runner/container-resource-limits.nix
            ./hosts/runner/hardware-configuration-amd.nix
          ];
          specialArgs = {
            inherit inputs adminKeys;
            hostName = name;
          };
        };
    in
    {
      nixosConfigurations = {
        cdk-runner-01 = makeRunnerVps "cdk-runner-01";
      };

      devShells.x86_64-linux.default =
        nixpkgs.legacyPackages.x86_64-linux.mkShell {
          packages = with nixpkgs.legacyPackages.x86_64-linux; [
            agenix.packages.x86_64-linux.default
            just
          ];
        };
    };
}
