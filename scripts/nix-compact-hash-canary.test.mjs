import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import { withStaleLinuxHash } from "./nix-compact-hash-canary.mjs";

const expression = readFileSync(join(import.meta.dirname, "../nix/packages/compact-toolchain.nix"), "utf8");

test("the canary corrupts only the Linux Compact fetch hash", () => {
  const corrupted = withStaleLinuxHash(expression);
  assert.notEqual(corrupted, expression);
  assert.match(corrupted, /x86_64-linux\s*=\s*\{[^}]*sha256\s*=\s*"sha256-AAAA/);
  const darwin = expression.match(/aarch64-darwin\s*=\s*\{[^}]*sha256\s*=\s*"[^"]+";/);
  assert.ok(darwin);
  assert.ok(corrupted.includes(darwin[0]));
});

test("the canary fails closed when the Nix layout changes", () => {
  assert.throws(() => withStaleLinuxHash("{}"), /exactly one/);
  assert.throws(() => withStaleLinuxHash(`${expression}\n${expression}`), /exactly one/);
});
