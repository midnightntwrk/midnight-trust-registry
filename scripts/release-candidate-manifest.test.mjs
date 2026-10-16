import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  assertFullPackedContract,
  buildReleaseCandidateManifest,
  verifyReleaseCandidateArtifacts,
} from "./release-candidate-manifest.mjs";

const roots = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const put = (root, path, content) => {
  const absolute = join(root, path);
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, content);
};

test("candidate manifest binds signed source inputs and exact package bytes", () => {
  const root = mkdtempSync(join(tmpdir(), "tr-release-manifest-"));
  roots.push(root);
  put(root, "package.json", JSON.stringify({
    version: "0.1.0", packageManager: "pnpm@10.34.1",
    dependencies: { "@midnight-ntwrk/midnight-did": "0.7.0", "@midnight-ntwrk/credential-compact": "0.2.0" },
  }));
  put(root, ".compact-version", "0.31.1\n");
  put(root, "pnpm-lock.yaml", "lock-test\n");
  put(root, "contracts/trust-registry/src/trust-registry.compact", "contract-test\n");
  put(root, "contracts/trust-registry/dist/managed/trust-registry/contract/index.js", "generated-test\n");
  put(root, "contracts/trust-registry/package.json", JSON.stringify({
    name: "@midnight-ntwrk/trust-registry-contract", version: "0.1.0",
  }));
  put(root, "packages/trust-registry-domain/package.json", JSON.stringify({
    name: "@midnight-ntwrk/trust-registry-domain", version: "0.1.0",
  }));
  put(root, "artifacts/npm/midnight-ntwrk-trust-registry-contract-0.1.0.tgz", "contract-tarball");
  put(root, "artifacts/npm/midnight-ntwrk-trust-registry-domain-0.1.0.tgz", "domain-tarball");
  const input = {
    repoRoot: root, artifactDir: join(root, "artifacts/npm"), revision: "a".repeat(40),
    workspaces: ["contracts/trust-registry", "packages/trust-registry-domain"],
    publish: ["contracts/trust-registry"],
  };
  const manifest = buildReleaseCandidateManifest(input);
  assert.equal(manifest.sourceRevision, "a".repeat(40));
  assert.equal(manifest.compactCompilerVersion, "0.31.1");
  assert.equal(manifest.lockfileSha256, createHash("sha256").update("lock-test\n").digest("hex"));
  assert.deepEqual(manifest.identityDependencies, {
    "@midnight-ntwrk/credential-compact": "0.2.0",
    "@midnight-ntwrk/midnight-did": "0.7.0",
  });
  assert.deepEqual(manifest.packages.map(({ publication }) => publication), ["npm", "local-only"]);
  assert.equal(manifest.packages[0].sha256,
    createHash("sha256").update("contract-tarball").digest("hex"));
  assert.equal(verifyReleaseCandidateArtifacts(manifest, input.artifactDir, input.workspaces).length, 2);
  assert.throws(() => verifyReleaseCandidateArtifacts({
    ...manifest, packages: [manifest.packages[0], manifest.packages[0]],
  }, input.artifactDir, input.workspaces), /duplicated/u);
  put(root, "artifacts/npm/unlisted-0.1.0.tgz", "extra-tarball");
  assert.throws(() => verifyReleaseCandidateArtifacts(manifest, input.artifactDir, input.workspaces), /unlisted/u);
  rmSync(join(root, "artifacts/npm/unlisted-0.1.0.tgz"));
  put(root, "artifacts/npm/midnight-ntwrk-trust-registry-contract-0.1.0.tgz", "tampered-tarball");
  assert.throws(() => verifyReleaseCandidateArtifacts(manifest, input.artifactDir, input.workspaces), /hash or size mismatch/u);
  assert.throws(() => buildReleaseCandidateManifest({ ...input, revision: "short" }), /full Git commit SHA/u);
  rmSync(join(root, "artifacts/npm/midnight-ntwrk-trust-registry-domain-0.1.0.tgz"));
  assert.throws(() => buildReleaseCandidateManifest(input), /missing or empty/u);
});

test("packed Compact contract must contain every ZKIR and prover/verifier pair", () => {
  const prefix = "package/dist/managed/trust-registry";
  const paths = [
    `${prefix}/compiler/contract-info.json`,
    `${prefix}/zkir/proveA.zkir`,
    `${prefix}/keys/proveA.prover`,
    `${prefix}/keys/proveA.verifier`,
  ];
  const info = { circuits: [{ name: "proveA", proof: true }] };
  assert.doesNotThrow(() => assertFullPackedContract(paths, info));
  assert.throws(() => assertFullPackedContract(paths.slice(0, -1), info), /verification key for proveA/u);
  assert.throws(() => assertFullPackedContract(paths.slice(1), info), /contract-info/u);
});

test("manifest smoke mode refuses invalid evidence before package installation", () => {
  const root = mkdtempSync(join(tmpdir(), "tr-release-smoke-"));
  roots.push(root);
  put(root, "manifest.json", JSON.stringify({ format: "wrong-format", packages: [] }));
  const script = join(dirname(fileURLToPath(import.meta.url)), "smoke-packed-artifacts.mjs");
  const result = spawnSync("node", [script, "--manifest", join(root, "manifest.json"),
    "--artifacts-dir", root], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /manifest format or package count is invalid/u);
  assert.doesNotMatch(result.stderr, /npm install/u);
});
