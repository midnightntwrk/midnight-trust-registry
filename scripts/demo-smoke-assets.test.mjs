import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { assertUiIndexResponse, collectEmittedModuleAssets } from "./demo-smoke-assets.mjs";

const withDist = (run) => {
  const dist = fs.mkdtempSync(path.join(os.tmpdir(), "tr-demo-assets-"));
  try {
    return run(dist);
  } finally {
    fs.rmSync(dist, { recursive: true, force: true });
  }
};

test("recursively serves emitted modules and permits empty type-only output", () => withDist((dist) => {
  fs.mkdirSync(path.join(dist, "nested"));
  fs.writeFileSync(path.join(dist, "index.js"), 'import "./nested/app.js";\n');
  fs.writeFileSync(path.join(dist, "nested/app.js"), 'export { value } from "./value.js";\n');
  fs.writeFileSync(path.join(dist, "nested/value.js"), "export const value = 1;\n");
  fs.writeFileSync(path.join(dist, "types.js"), "");
  assert.deepEqual(collectEmittedModuleAssets(dist, "Test UI"), [
    "index.js", "nested/app.js", "nested/value.js", "types.js",
  ]);
}));

test("rejects a missing relative module before HTTP probing", () => withDist((dist) => {
  fs.writeFileSync(path.join(dist, "index.js"), 'import "./nested/missing.js";\n');
  assert.throws(() => collectEmittedModuleAssets(dist, "Test UI"), /Test UI .*imports missing module asset/);
}));

test("rejects a module import outside the build root", () => withDist((dist) => {
  fs.writeFileSync(path.join(dist, "index.js"), 'import "../outside.js";\n');
  assert.throws(() => collectEmittedModuleAssets(dist, "Test UI"), /Test UI .*imports outside dist/);
}));

test("requires the browser entry point", () => withDist((dist) => {
  fs.writeFileSync(path.join(dist, "other.js"), "");
  assert.throws(() => collectEmittedModuleAssets(dist, "Test UI"), /Test UI build is missing index.js/);
}));

test("ignores import text in comments and verifies relative JSON assets", () => withDist((dist) => {
  fs.writeFileSync(path.join(dist, "index.js"), '// import "./not-a-module.js";\nimport data from "./data.json" with { type: "json" };\nconsole.log(data);\n');
  fs.writeFileSync(path.join(dist, "data.json"), '{"value":1}\n');
  assert.deepEqual(collectEmittedModuleAssets(dist, "Test UI"), ["data.json", "index.js"]);
}));

test("rejects an empty reachable module but permits empty unreferenced output", () => withDist((dist) => {
  fs.writeFileSync(path.join(dist, "index.js"), 'import "./app.js";\n');
  fs.writeFileSync(path.join(dist, "app.js"), "");
  fs.writeFileSync(path.join(dist, "type-only.js"), "");
  assert.throws(() => collectEmittedModuleAssets(dist, "Test UI"), /Test UI reachable module is empty: app.js/);
}));

test("reports a non-2xx UI response with its status", () => {
  assert.throws(() => assertUiIndexResponse({ ok: false, status: 503 }, "applicant portal"), /HTTP 503/);
});
