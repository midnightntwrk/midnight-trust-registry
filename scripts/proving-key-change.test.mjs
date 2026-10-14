import assert from "node:assert/strict";
import test from "node:test";

import { provingInputsChanged } from "./proving-key-change.mjs";

test("ordinary documentation and TypeScript changes do not regenerate keys", () => {
  assert.equal(provingInputsChanged(["docs/spec/trust-registry.md", "packages/trust-registry-api/src/server.ts"], "pull_request"), false);
  assert.equal(provingInputsChanged(["pnpm-lock.yaml", "docs-site/package.json"], "pull_request"), false);
});

test("Compact inputs and dependency overrides require proving validation", () => {
  for (const path of [
    ".compact-version",
    "contracts/trust-registry/src/trust-registry.compact",
    "contracts/trust-registry/package.json",
    "pnpm-workspace.yaml",
    "scripts/compile-compact.mjs",
  ]) {
    assert.equal(provingInputsChanged([path], "pull_request"), true, path);
  }
});

test("manual and scheduled runs always validate proving keys", () => {
  assert.equal(provingInputsChanged([], "workflow_dispatch"), true);
  assert.equal(provingInputsChanged([], "schedule"), true);
});
