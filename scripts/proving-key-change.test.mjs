import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { changedPaths, comparisonBase, provingInputsChanged, workspaceChangeIsRelevant, workspaceConfigAffectsProving } from "./proving-key-change.mjs";

test("ordinary documentation and TypeScript changes do not regenerate keys", () => {
  assert.equal(provingInputsChanged(["docs/spec/trust-registry.md", "packages/trust-registry-api/src/server.ts"], "pull_request"), false);
  assert.equal(provingInputsChanged(["pnpm-lock.yaml", "docs-site/package.json"], "pull_request"), false);
});

test("workspace proving comparison uses the entire push base", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "tr-proving-workspace-"));
  const git = (...args) => execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
  const commit = (message) => {
    git("add", ".");
    git("-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-m", message);
  };
  try {
    git("init", "-q");
    writeFileSync(path.join(cwd, "pnpm-workspace.yaml"), "packages:\n  - 'contracts/*'\noverrides:\n  '@midnight-ntwrk/example': 0.1.0\n");
    commit("base");
    const before = git("rev-parse", "HEAD");
    writeFileSync(path.join(cwd, "pnpm-workspace.yaml"), "packages:\n  - 'contracts/*'\noverrides:\n  '@midnight-ntwrk/example': 0.2.0\n");
    commit("override");
    writeFileSync(path.join(cwd, "README.md"), "docs\n");
    commit("docs");
    assert.equal(workspaceChangeIsRelevant(before, cwd), true);
    assert.equal(workspaceChangeIsRelevant("HEAD^1", cwd), false);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
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

test("push comparison includes earlier commits and fails closed without its base", () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "tr-proving-push-"));
  const git = (...args) => execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
  const commit = (message) => {
    git("add", ".");
    git("-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-m", message);
  };
  try {
    git("init", "-q");
    writeFileSync(path.join(cwd, "README.md"), "initial\n");
    commit("base");
    const before = git("rev-parse", "HEAD");
    writeFileSync(path.join(cwd, ".compact-version"), "0.16.0\n");
    commit("compiler input");
    writeFileSync(path.join(cwd, "README.md"), "updated\n");
    commit("docs");
    const base = comparisonBase("push", before);
    assert.equal(base, before);
    assert.deepEqual(changedPaths("HEAD^1", cwd), ["README.md"]);
    assert.deepEqual(changedPaths(base, cwd), [".compact-version", "README.md"]);
    assert.equal(provingInputsChanged(changedPaths(base, cwd), "push"), true);
    assert.deepEqual(changedPaths(comparisonBase("push", "0".repeat(40)), cwd), [".compact-version"]);
    assert.deepEqual(changedPaths(comparisonBase("push", "bad-base"), cwd), [".compact-version"]);
    assert.deepEqual(changedPaths("f".repeat(40), cwd), [".compact-version"]);
    assert.equal(comparisonBase("pull_request"), "HEAD^1");

    const targetBranch = git("branch", "--show-current");
    git("checkout", "-q", "-b", "pr-head");
    writeFileSync(path.join(cwd, ".compact-version"), "0.16.1\n");
    commit("PR compiler input");
    git("checkout", "-q", targetBranch);
    git("-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "merge", "--no-ff", "-m", "merge PR", "pr-head");
    assert.deepEqual(changedPaths(comparisonBase("pull_request"), cwd), [".compact-version"]);
    assert.equal(provingInputsChanged(changedPaths("HEAD^1", cwd), "pull_request"), true);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});
