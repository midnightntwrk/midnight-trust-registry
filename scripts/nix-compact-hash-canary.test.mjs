import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { isFixedOutputHashMismatch, nativeNixPlatform, supportedNixPackages, supportedNixPlatforms, withStalePlatformHash } from "./nix-compact-hash-canary.mjs";

const fakeHash = `sha256-${"A".repeat(43)}=`;
const expressions = ["compact-toolchain", "compact-midnight"].map((name) =>
  readFileSync(join(import.meta.dirname, `../nix/packages/${name}.nix`), "utf8"),
);

for (const [index, name] of ["compact-toolchain", "compact-midnight"].entries()) {
  const expression = expressions[index];
  for (const [platform, other] of [["x86_64-linux", "aarch64-darwin"], ["aarch64-darwin", "x86_64-linux"]]) {
    test(`${name} canary corrupts only the ${platform} fetch hash`, () => {
      const corrupted = withStalePlatformHash(expression, platform);
      assert.notEqual(corrupted, expression);
      assert.match(corrupted, new RegExp(`${platform}\\s*=\\s*\\{[^}]*sha256\\s*=\\s*"${fakeHash}"`));
      const unaffected = expression.match(new RegExp(`${other}\\s*=\\s*\\{[^}]*sha256\\s*=\\s*"[^"]+";`));
      assert.ok(unaffected);
      assert.ok(corrupted.includes(unaffected[0]));
    });
  }
}

test("the canary fails closed when the Nix layout changes", () => {
  assert.throws(() => withStalePlatformHash("{}", "x86_64-linux"), /exactly one/);
  assert.throws(() => withStalePlatformHash(`${expressions[0]}\n${expressions[0]}`, "x86_64-linux"), /exactly one/);
  assert.throws(() => withStalePlatformHash(expressions[0], "unsupported"), /Unsupported/);
});

test("the canary selects only supported native Nix platforms", () => {
  assert.equal(nativeNixPlatform("linux", "x64"), "x86_64-linux");
  assert.equal(nativeNixPlatform("darwin", "arm64"), "aarch64-darwin");
  assert.throws(() => nativeNixPlatform("darwin", "x64"), /Unsupported/);
});

test("canary platform coverage matches both Nix packages and the flake", () => {
  const expected = [...supportedNixPlatforms].sort();
  for (const expression of expressions) {
    const platforms = [...expression.matchAll(/^    ([a-z0-9_-]+) = \{$/gm)].map((match) => match[1]);
    assert.deepEqual(platforms.sort(), expected);
  }
  const flake = readFileSync(join(import.meta.dirname, "../flake.nix"), "utf8");
  const systems = flake.match(/systems\s*=\s*\[([^\]]+)\]/)?.[1]?.match(/"[a-z0-9_-]+"/g)?.map((value) => value.slice(1, -1));
  assert.deepEqual(systems?.sort(), expected);
});

test("canary package coverage matches exported Compact Nix packages", () => {
  const index = readFileSync(join(import.meta.dirname, "../nix/packages/default.nix"), "utf8");
  const compactPackages = [...index.matchAll(/^\s{8}(compact-[a-z0-9-]+)\s*=/gm)].map((match) => match[1]);
  assert.deepEqual(compactPackages.sort(), [...supportedNixPackages].sort());
  for (const name of compactPackages) {
    assert.match(index, new RegExp(`${name}\\s*=\\s*pkgs\\.callPackage\\s+\\./${name}\\.nix\\s+\\{\\s*\\};`));
  }
});

test("only the deliberate fixed-output mismatch satisfies the canary", () => {
  assert.equal(isFixedOutputHashMismatch(`hash mismatch in fixed-output derivation: specified ${fakeHash}`), true);
  assert.equal(isFixedOutputHashMismatch("hash mismatch in fixed-output derivation: different hash"), false);
  assert.equal(isFixedOutputHashMismatch(`NAR hash mismatch: ${fakeHash}`), false);
});

test("the CLI entrypoint runs when invoked through a symlink", () => {
  const directory = mkdtempSync(join(tmpdir(), "tr-compact-canary-link-"));
  try {
    const link = join(directory, "canary.mjs");
    symlinkSync(join(import.meta.dirname, "nix-compact-hash-canary.mjs"), link);
    const result = spawnSync(process.execPath, [link], {
      encoding: "utf8",
      env: { ...process.env, NIX_BIN: join(directory, "missing-nix") },
    });
    assert.notEqual(result.status, 0);
    const unsupportedHost = !((process.platform === "linux" && process.arch === "x64") ||
      (process.platform === "darwin" && process.arch === "arm64"));
    assert.match(result.stderr, unsupportedHost ? /Unsupported Compact Nix canary host/ : /spawnSync .*missing-nix ENOENT/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
