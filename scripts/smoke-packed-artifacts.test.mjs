import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./smoke-packed-artifacts.mjs", import.meta.url));
const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });

test("local VC trial inputs cannot enter verified release-manifest mode", () => {
  const result = run(
    "--manifest", "missing.json",
    "--vc-consumer",
    "--local-vc-tarballs-dir", "missing",
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /cannot be used with a verified release manifest/u);
});

test("local VC trial inputs require an actual consumer smoke", () => {
  const result = run("--local-vc-tarballs-dir", "missing");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /require --vc-consumer or --actor-journey/u);
});

test("local VC trial directory cannot be omitted", () => {
  const result = run("--vc-consumer", "--local-vc-tarballs-dir");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /requires a directory path/u);
});
