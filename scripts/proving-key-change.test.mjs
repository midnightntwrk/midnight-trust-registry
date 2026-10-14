import assert from "node:assert/strict";
import test from "node:test";

import { provingInputsChanged, workspaceConfigAffectsProving } from "./proving-key-change.mjs";

test("ordinary documentation and TypeScript changes do not regenerate keys", () => {
  assert.equal(provingInputsChanged(["docs/spec/trust-registry.md", "packages/trust-registry-api/src/server.ts"], "pull_request"), false);
  assert.equal(provingInputsChanged(["pnpm-lock.yaml", "docs-site/package.json"], "pull_request"), false);
});

test("Compact inputs and dependency overrides require proving validation", () => {
  for (const path of [
    ".compact-version",
    "contracts/trust-registry/src/trust-registry.compact",
    "contracts/trust-registry/package.json",
    "scripts/compile-compact.mjs",
  ]) {
    assert.equal(provingInputsChanged([path], "pull_request"), true, path);
  }
});

test("docs-only workspace additions do not trigger proving, but Midnight overrides do", () => {
  const before = {
    packages: ["contracts/*", "packages/*"],
    preferWorkspacePackages: true,
    overrides: { "@midnight-ntwrk/midnight-did-jubjub-schnorr": "0.7.0" },
  };
  const docsOnly = {
    ...before,
    packages: [...before.packages, "docs-site"],
    overrides: { ...before.overrides, "vitepress>vite": "6.4.3" },
  };
  assert.equal(workspaceConfigAffectsProving(before, docsOnly), false);
  assert.equal(provingInputsChanged(["pnpm-workspace.yaml"], "pull_request", false), false);
  assert.equal(workspaceConfigAffectsProving(before, {
    ...docsOnly,
    overrides: { ...docsOnly.overrides, "@midnight-ntwrk/midnight-did-jubjub-schnorr": "0.8.0" },
  }), true);
  assert.equal(workspaceConfigAffectsProving(before, {
    ...before,
    packages: [...before.packages, "dependencies/*"],
  }), true);
  assert.equal(provingInputsChanged(["pnpm-workspace.yaml"], "pull_request", true), true);
});

test("manual and scheduled runs always validate proving keys", () => {
  assert.equal(provingInputsChanged([], "workflow_dispatch"), true);
  assert.equal(provingInputsChanged([], "schedule"), true);
});
