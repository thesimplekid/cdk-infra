{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    agenix.url = "github:ryantm/agenix";
  };

  outputs = { nixpkgs, disko, agenix, ... }@inputs:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      adminKeys = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA5JHd6Y0gX77Niuauv9SPxd1ZdrVsBSSIJdJZPpJVe8 root@nix-box"
        # TSK
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJiA6Oq79afOa48iyOVfs7iVbs3Ug9Elj8GdtWLs2UcD tsk@thesimplekid.com"
      ];

      # Rust runner controller package
      runnerController = pkgs.rustPlatform.buildRustPackage {
        pname = "runner-controller";
        version = "0.1.0";
        src = ./runner-controller;
        cargoLock.lockFile = ./runner-controller/Cargo.lock;

        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ pkgs.openssl ];

        meta = {
          description = "GitHub Actions Runner Controller for NixOS containers";
          license = pkgs.lib.licenses.mit;
        };
      };

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

      makeRunnerVps = name: extraLabels:
        nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            topLevelModule
            ./modules/nixos-nixpkgs-last-modified.nix

            disko.nixosModules.disko
            agenix.nixosModules.default

            ./disk-config/hetzner-vps.nix
            ./hosts/runner/runner-controller.nix  # On-demand containers (ARC-style)
            ./hosts/runner/container-resource-limits.nix
            ./hosts/runner/hardware-configuration-amd.nix
          ];
          specialArgs = {
            inherit inputs adminKeys runnerController extraLabels;
            hostName = name;
          };
        };
    in
    {
      # Expose the package
      packages.${system} = {
        runner-controller = runnerController;
        default = runnerController;
      };

      nixosConfigurations = {
        cdk-runner-01 = makeRunnerVps "cdk-runner-01" [ "fuzz-a" ];
        cdk-runner-02 = makeRunnerVps "cdk-runner-02" [ "fuzz-b" ];
      };

      devShells.x86_64-linux.default =
        let
          pkgs = nixpkgs.legacyPackages.x86_64-linux;
        in
        pkgs.mkShell {
          packages = [
            agenix.packages.x86_64-linux.default
            pkgs.just

            # Rust toolchain
            pkgs.rustc
            pkgs.cargo
            pkgs.rustfmt
            pkgs.clippy

            # Rust development tools
            pkgs.rust-analyzer
            pkgs.cargo-watch
            pkgs.cargo-nextest

            # Build dependencies
            pkgs.pkg-config
            pkgs.openssl
          ];

          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
        };
    };
}
