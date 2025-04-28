{
  description = "A Nix-flake-based Rust development environment";

  inputs = {
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:nixos/nixpkgs";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs = {self, ...} @ inputs:
    inputs.flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import inputs.nixpkgs {
        inherit system;
        overlays = [(import inputs.rust-overlay)];
      };

      # Target musl when building on 64-bit linux
      buildTarget =
        {"x86_64-linux" = "x86_64-unknown-linux-musl";}.${system}
        or pkgs.stdenv.hostPlatform.rust.rustcTargetSpec;
      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        targets = [
          buildTarget
          pkgs.stdenv.hostPlatform.rust.rustcTargetSpec
        ];
      };

      # Set-up build dependencies and configure rust
      craneLib = (inputs.crane.mkLib pkgs).overrideToolchain rustToolchain;

      cargo-details = pkgs.lib.importTOML ./Cargo.toml;
      pname = cargo-details.package.name;

      src = craneLib.cleanCargoSource (craneLib.path ./.);
      commonArgs = {
        inherit src pname;
        nativeBuildInputs = with pkgs; [pkg-config];
        CARGO_BUILD_TARGET = buildTarget;
      };

      # Compile and cache only cargo dependencies
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;

      # Compile and cache only workspace code (seperately from 3rc party dependencies)
      cargo-package = craneLib.buildPackage (commonArgs // {inherit cargoArtifacts;});
    in {
      checks = {
        inherit
          # Build the crate as part of `nix flake check` for convenience
          cargo-package
          ;

        # Run clippy (and deny all warnings) on the crate source,
        # again, resuing the dependency artifacts from above.
        #
        # Note that this is done as a separate derivation so that
        # we can block the CI if there are issues here, but not
        # prevent downstream consumers from building our crate by itself.
        cargo-clippy = craneLib.cargoClippy (commonArgs
          // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

        # Generate rust-generated documentation
        cargo-doc = craneLib.cargoDoc (commonArgs
          // {
            inherit cargoArtifacts;
            cargoDocExtraArgs = ""; # TODO: Figure out why seems to be required
          });

        # Check formatting
        cargo-fmt = craneLib.cargoFmt {inherit src;};

        # Run tests with cargo-nextest
        cargo-nextest =
          craneLib.cargoNextest (commonArgs
            // {inherit cargoArtifacts;});

        # Audit dependencies
        cargo-audit = craneLib.cargoAudit {
          inherit src;
          inherit (inputs) advisory-db;
        };
      };
      devShells.default = pkgs.mkShell {
        packages =
          (with pkgs; [
            cargo-audit
            cargo-auditable
            cargo-cross
            cargo-deny
            cargo-nextest
            cargo-outdated
            cargo-watch
            rust-analyzer

            # Editor stuffs
            helix
            lldb
            rust-analyzer
          ])
          ++ [
            # Packages made in this flake
            rustToolchain
            # cargo-package
          ];

        shellHook = ''
          ${rustToolchain}/bin/cargo --version
          ${pkgs.helix}/bin/hx --version
          ${pkgs.helix}/bin/hx --health rust
        '';
      };
      packages = {
        rust = cargo-package;
        docker = pkgs.dockerTools.buildImage {
          name = pname;
          tag = "v${cargo-details.package.version}";
          extraCommands = ''mkdir -p data'';
          config = {
            Cmd = "--help";
            Entrypoint = ["${cargo-package}/bin/${pname}"];
          };
        };
      };
      packages.default = cargo-package;

      # Now `nix fmt` works!
      formatter = pkgs.alejandra;
    });
}
