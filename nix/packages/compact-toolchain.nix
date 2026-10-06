{
  lib,
  stdenv,
  fetchzip,
  unzip,
}:

let
  platformInfo = {
    x86_64-linux = {
      compactPlatform = "x86_64-unknown-linux-musl";
      sha256 = "sha256-75nwiVASCtJQ+wXVe8P5wUDmy3TevYfZ88O+qtH0lJU=";
    };
    aarch64-darwin = {
      compactPlatform = "aarch64-darwin";
      sha256 = "sha256-QKfLjKbOBSIuxJXfYhkPgDJkn4CcsRsV6M1ULSRem9o=";
    };
  };

  currentPlatform = platformInfo.${stdenv.hostPlatform.system} or null;

  versionFile = builtins.readFile ../../.compact-version;
  versionMatch = builtins.match "([0-9]+[.][0-9]+[.][0-9]+)\n" versionFile;
  version = if versionMatch == null then
    throw ".compact-version must contain one stable semver followed by LF"
  else
    builtins.elemAt versionMatch 0;
in

assert lib.asserts.assertMsg (currentPlatform != null) ''
  compact-toolchain does not support system ${stdenv.hostPlatform.system}.
  Supported systems: ${lib.concatStringsSep ", " (lib.attrNames platformInfo)}
'';

stdenv.mkDerivation rec {
  pname = "compact-toolchain";
  inherit version;

  src = fetchzip {
    url = "https://github.com/midnightntwrk/compact/releases/download/compactc-v${version}/compactc_v${version}_${currentPlatform.compactPlatform}.zip";
    sha256 = currentPlatform.sha256;
    stripRoot = false;
  };

  nativeBuildInputs = [ unzip ];

  # The devtool resolves bin/compactc as an absolute symlink. The compactc
  # launcher then looks for compactc.bin and zkir beside its invocation path.
  dontRewriteSymlinks = true;

  installPhase = ''
    runHook preInstall

    compact_platform="${currentPlatform.compactPlatform}"
    mkdir -p $out/versions/${version}/$compact_platform
    cp -r * $out/versions/${version}/$compact_platform/

    mkdir -p $out/bin
    ln -s $out/versions/${version}/$compact_platform/compactc $out/bin/compactc
    ln -s $out/versions/${version}/$compact_platform/compactc.bin $out/bin/compactc.bin
    ln -s $out/versions/${version}/$compact_platform/fixup-compact $out/bin/fixup-compact
    ln -s $out/versions/${version}/$compact_platform/format-compact $out/bin/format-compact
    ln -s $out/versions/${version}/$compact_platform/zkir $out/bin/zkir
    ln -s $out/versions/${version}/$compact_platform/zkir-v3 $out/bin/zkir-v3

    runHook postInstall
  '';

  meta = with lib; {
    description = "Compact compiler toolchain v${version} providing COMPACT_DIRECTORY layout";
    homepage = "https://github.com/midnightntwrk/compact";
    license = lib.licenses.asl20;
    platforms = lib.attrNames platformInfo;
  };
}
