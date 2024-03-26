{
  description = "A Nix-flake-based Go 1.17 development environment";

  inputs.nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1.*.tar.gz";

  outputs = { self, nixpkgs }:
    let
      goVersion = 21; # Change this to update the whole stack
      overlays = [ (final: prev: { go = prev."go_1_${toString goVersion}"; }) ];
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forEachSupportedSystem = f: nixpkgs.lib.genAttrs supportedSystems (system: f {
        pkgs = import nixpkgs { inherit overlays system; };
      });
    in
    {
      devShells = forEachSupportedSystem ({ pkgs }: {
        default = pkgs.mkShell {
          hardeningDisable = [ "all" ];
          packages = with pkgs; [
            # go 1.20 (specified by overlay)
            go

            # goimports, godoc, etc.
            gotools
            go-tools
            # https://github.com/golangci/golangci-lint
            golangci-lint
            gopls
            delve
            
            
            libfido2

            #udev
          ];
        };
      });
    };
}
