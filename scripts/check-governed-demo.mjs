#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const started = performance.now();
const result = spawnSync(process.execPath, ["scripts/demo-governed-registry.mjs"], {
  cwd: root,
  stdio: ["ignore", "ignore", "inherit"],
});
if (result.error) throw result.error;
if (result.status !== 0) {
  throw new Error(`Governed demo failed with ${result.signal ?? `exit code ${result.status}`}`);
}
console.log(`[check-governed-demo] Passed in ${((performance.now() - started) / 1000).toFixed(1)}s`);
