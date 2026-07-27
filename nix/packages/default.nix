{
  perSystem =
    { pkgs, ... }:
    {
      packages = {
        compact-midnight = pkgs.callPackage ./compact-midnight.nix { };
        compact-toolchain = pkgs.callPackage ./compact-toolchain.nix { };
      };
    };
}
