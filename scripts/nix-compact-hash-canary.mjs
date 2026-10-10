import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fakeHash = `sha256-${"A".repeat(43)}=`;
const linuxHashPattern = /(x86_64-linux\s*=\s*\{[^}]*sha256\s*=\s*")[^"]+("\s*;)/g;

export const withStaleLinuxHash = (source) => {
  const matches = [...source.matchAll(linuxHashPattern)];
  if (matches.length !== 1 || matches[0]?.[0].includes(fakeHash)) {
    throw new Error("Expected exactly one non-canary x86_64-linux Compact fetch hash");
  }
  return source.replace(linuxHashPattern, `$1${fakeHash}$2`);
};

export const checkStaleHashFails = () => {
  const directory = mkdtempSync(join(tmpdir(), "tr-compact-nix-canary-"));
  try {
    for (const file of ["flake.nix", "flake.lock", ".compact-version"]) {
      cpSync(join(root, file), join(directory, file));
    }
    cpSync(join(root, "nix"), join(directory, "nix"), { recursive: true });
    const expression = join(directory, "nix/packages/compact-toolchain.nix");
    writeFileSync(expression, withStaleLinuxHash(readFileSync(expression, "utf8")));

    const result = spawnSync(
      "nix",
      ["build", "--no-link", `path:${directory}#compact-toolchain`],
      { encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 15 * 60 * 1000 },
    );
    if (result.error) throw result.error;
    if (result.status === 0) {
      throw new Error("Nix accepted a deliberately stale Linux Compact fetch hash");
    }
    if (!/hash mismatch/i.test(result.stderr)) {
      throw new Error(`Stale-hash canary failed for a reason other than a hash mismatch:\n${result.stderr.slice(-4000)}`);
    }
    console.log("Nix rejected the deliberately stale Linux Compact fetch hash.");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
};

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    checkStaleHashFails();
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  }
}
