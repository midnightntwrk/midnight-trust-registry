import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./smoke-packed-artifacts.mjs", import.meta.url));
const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });

test("obsolete local VC trial option is rejected", () => {
  const result = run("--vc-consumer", "--local-vc-tarballs-dir");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Unknown argument: --local-vc-tarballs-dir/u);
});
