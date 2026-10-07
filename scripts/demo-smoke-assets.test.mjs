import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { assertUiIndexResponse, collectEmittedJavaScriptAssets } from "./demo-smoke-assets.mjs";

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
  assert.deepEqual(collectEmittedJavaScriptAssets(dist), [
    "index.js", "nested/app.js", "nested/value.js", "types.js",
  ]);
}));

test("rejects a missing relative module before HTTP probing", () => withDist((dist) => {
  fs.writeFileSync(path.join(dist, "index.js"), 'import "./nested/missing.js";\n');
  assert.throws(() => collectEmittedJavaScriptAssets(dist), /imports missing JavaScript module/);
}));

test("rejects a module import outside the build root", () => withDist((dist) => {
  fs.writeFileSync(path.join(dist, "index.js"), 'import "../outside.js";\n');
  assert.throws(() => collectEmittedJavaScriptAssets(dist), /imports outside dist/);
}));

test("requires the browser entry point", () => withDist((dist) => {
  fs.writeFileSync(path.join(dist, "other.js"), "");
  assert.throws(() => collectEmittedJavaScriptAssets(dist), /missing index.js/);
}));

test("reports a non-2xx UI response with its status", () => {
  assert.throws(() => assertUiIndexResponse({ ok: false, status: 503 }, "applicant portal"), /HTTP 503/);
});
