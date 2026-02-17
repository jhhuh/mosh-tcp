{
  description = "mosh-tcp: Mosh (mobile shell) over TCP with length-prefixed framing";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });
    in {
      devShells = forAllSystems ({ pkgs }: {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Build tools
            autoconf
            automake
            libtool
            pkg-config

            # Required libraries
            protobuf_21
            zlib
            openssl
            ncurses

            # Runtime
            perl
            openssh
          ];
        };
      });
    };
}
