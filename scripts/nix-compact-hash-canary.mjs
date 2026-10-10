import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fakeHash = `sha256-${"A".repeat(43)}=`;
const packages = ["compact-toolchain", "compact-midnight"];
export const supportedNixPlatforms = Object.freeze(["x86_64-linux", "aarch64-darwin"]);

export const nativeNixPlatform = (platform = process.platform, architecture = process.arch) => {
  if (platform === "linux" && architecture === "x64") return "x86_64-linux";
  if (platform === "darwin" && architecture === "arm64") return "aarch64-darwin";
  throw new Error(`Unsupported Compact Nix canary host: ${platform}/${architecture}`);
};

export const withStalePlatformHash = (source, system) => {
  if (!supportedNixPlatforms.includes(system)) throw new Error(`Unsupported Compact Nix platform: ${system}`);
  const pattern = new RegExp(`(${system}\\s*=\\s*\\{[^}]*sha256\\s*=\\s*")[^"]+("\\s*;)`, "g");
  const matches = [...source.matchAll(pattern)];
  if (matches.length !== 1 || matches[0]?.[0].includes(fakeHash)) {
    throw new Error(`Expected exactly one non-canary ${system} Compact fetch hash`);
  }
  return source.replace(pattern, `$1${fakeHash}$2`);
};

export const isFixedOutputHashMismatch = (stderr) =>
  /hash mismatch in fixed-output derivation/i.test(stderr) && stderr.includes(fakeHash);

export const checkStaleHashFails = (packageName, system = nativeNixPlatform()) => {
  if (!packages.includes(packageName)) throw new Error(`Unsupported Compact Nix package: ${packageName}`);
  const temporaryPath = mkdtempSync(join(tmpdir(), "tr-compact-nix-canary-"));
  const directory = realpathSync(temporaryPath);
  try {
    for (const file of ["flake.nix", "flake.lock", ".compact-version"]) {
      cpSync(join(root, file), join(directory, file));
    }
    cpSync(join(root, "nix"), join(directory, "nix"), { recursive: true });
    const expression = join(directory, `nix/packages/${packageName}.nix`);
    writeFileSync(expression, withStalePlatformHash(readFileSync(expression, "utf8"), system));

    const result = spawnSync(
      process.env.NIX_BIN ?? "nix",
      ["build", "--no-link", `path:${directory}#packages.${system}.${packageName}`],
      { encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 15 * 60 * 1000 },
    );
    if (result.error) throw result.error;
    if (result.status === 0) {
      throw new Error(`Nix accepted a deliberately stale ${system} ${packageName} fetch hash`);
    }
    if (!isFixedOutputHashMismatch(result.stderr)) {
      throw new Error(`Stale-hash canary failed for a reason other than a Compact fixed-output hash mismatch:\n${result.stderr.slice(-4000)}`);
    }
    console.log(`Nix rejected the deliberately stale ${system} ${packageName} fetch hash.`);
  } finally {
    rmSync(temporaryPath, { recursive: true, force: true });
  }
};

if (process.argv[1] && realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))) {
  try {
    for (const packageName of packages) checkStaleHashFails(packageName);
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  }
}
