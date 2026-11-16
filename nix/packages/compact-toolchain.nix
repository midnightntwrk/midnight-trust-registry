{
  lib,
  stdenv,
  fetchurl,
  unzip,
}:

let
  platformInfo = {
    x86_64-linux = {
      compactPlatform = "x86_64-unknown-linux-musl";
      sha256 = "7017b6121ebb9d53a562984bca616d143ef84fc7ee18b4da6c3a0a6615cb5e97";
    };
    aarch64-darwin = {
      compactPlatform = "aarch64-darwin";
      sha256 = "a8126b2cc06230ed2c6558059a8945119e370ff222930e6a52f90870e8cc3c5d";
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

  src = fetchurl {
    url = "https://github.com/midnightntwrk/compact/releases/download/compactc-v${version}/compactc_v${version}_${currentPlatform.compactPlatform}.zip";
    sha256 = currentPlatform.sha256;
  };

  nativeBuildInputs = [ unzip ];
  sourceRoot = ".";

  # The devtool resolves bin/compactc as an absolute symlink.
  dontRewriteSymlinks = true;

  installPhase = ''
    runHook preInstall

    compact_platform="${currentPlatform.compactPlatform}"
    mkdir -p $out/versions/${version}/$compact_platform
    unzip -q "$src" -d $out/versions/${version}/$compact_platform

    # The upstream launcher otherwise searches beside bin/ instead of its real target.
    chmod +w $out/versions/${version}/$compact_platform/compactc
    substituteInPlace $out/versions/${version}/$compact_platform/compactc \
      --replace-fail 'thisdir="$(cd $(dirname $0) ; pwd -P)"' \
      "thisdir=\"$out/versions/${version}/$compact_platform\""

    mkdir -p $out/bin
    ln -s $out/versions/${version}/$compact_platform/compactc $out/bin/compactc
    ln -s $out/versions/${version}/$compact_platform/compactc.bin $out/bin/compactc.bin
    ln -s $out/versions/${version}/$compact_platform/fixup-compact $out/bin/fixup-compact
    ln -s $out/versions/${version}/$compact_platform/format-compact $out/bin/format-compact
    ln -s $out/versions/${version}/$compact_platform/zkir-v3 $out/bin/zkir-v3
    ln -s $out/versions/${version}/$compact_platform/zkir-v3 $out/bin/zkir

    runHook postInstall
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    test "$("$out/bin/compactc" --version | cut -d ' ' -f 1)" = "${version}"
    test "$("$out/bin/compactc" --ledger-version)" = "zkir-3.2.0-rc.2"
    "$out/bin/zkir" --help | grep -q compile
    runHook postInstallCheck
  '';

  meta = with lib; {
    description = "Compact compiler toolchain v${version} providing COMPACT_DIRECTORY layout";
    homepage = "https://github.com/midnightntwrk/compact";
    license = lib.licenses.asl20;
    platforms = lib.attrNames platformInfo;
  };
}
