import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  assertFullPackedContract,
  buildReleaseCandidateManifest,
  hashPackedTarEntry,
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

const packContract = (root, verifier = "verifier-a\n",
  source = "contract-test\n", generated = "generated-test\n") => {
  const prefix = "package/dist/managed/trust-registry";
  const info = JSON.stringify({ circuits: ["proveB", "proveA"].map((name) => ({ name, proof: true })) });
  put(root, "packed-contract/package/src/trust-registry.compact", source);
  put(root, `packed-contract/${prefix}/contract/index.js`, generated);
  put(root, "contracts/trust-registry/dist/managed/trust-registry/compiler/contract-info.json", info);
  put(root, `packed-contract/${prefix}/compiler/contract-info.json`, info);
  for (const name of ["proveB", "proveA"]) {
    put(root, `contracts/trust-registry/dist/managed/trust-registry/keys/${name}.verifier`, verifier);
    for (const [extension, content] of [["verifier", verifier], ["prover", "prover-a\n"]]) {
      put(root, `packed-contract/${prefix}/keys/${name}.${extension}`, content);
    }
    put(root, `packed-contract/${prefix}/zkir/${name}.zkir`, "zkir-a\n");
  }
  const tarball = join(root, "artifacts/npm/midnight-ntwrk-trust-registry-contract-0.1.0.tgz");
  mkdirSync(dirname(tarball), { recursive: true });
  const packed = spawnSync("tar", ["-czf", tarball, "package"], {
    cwd: join(root, "packed-contract"), encoding: "utf8",
  });
  assert.equal(packed.status, 0, packed.stderr);
  return tarball;
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
  const contractTarball = packContract(root);
  put(root, "artifacts/npm/midnight-ntwrk-trust-registry-domain-0.1.0.tgz", "domain-tarball");
  const input = {
    repoRoot: root, artifactDir: join(root, "artifacts/npm"), revision: "a".repeat(40),
    workspaces: ["contracts/trust-registry", "packages/trust-registry-domain"],
    publish: ["contracts/trust-registry"],
  };
  let manifest = buildReleaseCandidateManifest(input);
  assert.equal(manifest.sourceRevision, "a".repeat(40));
  assert.equal(manifest.compactCompilerVersion, "0.31.1");
  assert.equal(manifest.lockfileSha256, createHash("sha256").update("lock-test\n").digest("hex"));
  assert.deepEqual(manifest.identityDependencies, {
    "@midnight-ntwrk/credential-compact": "0.2.0",
    "@midnight-ntwrk/midnight-did": "0.7.0",
  });
  assert.deepEqual(manifest.packages.map(({ publication }) => publication), ["npm", "local-only"]);
  const verifierHash = createHash("sha256").update("verifier-a\n").digest("hex");
  assert.deepEqual(manifest.verifierKeySha256, { proveA: verifierHash, proveB: verifierHash });
  assert.deepEqual(Object.keys(manifest.verifierKeySha256), ["proveA", "proveB"]);
  assert.equal(manifest.packages[0].sha256,
    createHash("sha256").update(readFileSync(contractTarball)).digest("hex"));
  assert.equal(verifyReleaseCandidateArtifacts(manifest, input.artifactDir, input.workspaces).length, 2);
  for (const field of ["contractSourceSha256", "generatedContractSha256"]) {
    assert.throws(() => verifyReleaseCandidateArtifacts({ ...manifest, [field]: "0".repeat(64) },
      input.artifactDir, input.workspaces), /packed contract source or generated contract hash mismatch/u);
  }
  packContract(root, "verifier-a\n", "substituted-source\n");
  assert.throws(() => buildReleaseCandidateManifest(input), /Packed contract does not match the candidate tree/u);
  let repacked = { ...manifest.packages[0], sizeBytes: statSync(contractTarball).size,
    sha256: createHash("sha256").update(readFileSync(contractTarball)).digest("hex") };
  assert.throws(() => verifyReleaseCandidateArtifacts({ ...manifest,
    packages: [repacked, manifest.packages[1]],
  }, input.artifactDir, input.workspaces), /packed contract source or generated contract hash mismatch/u);
  packContract(root, "verifier-a\n", "contract-test\n", "substituted-generated\n");
  assert.throws(() => buildReleaseCandidateManifest(input), /Packed contract does not match the candidate tree/u);
  repacked = { ...manifest.packages[0], sizeBytes: statSync(contractTarball).size,
    sha256: createHash("sha256").update(readFileSync(contractTarball)).digest("hex") };
  assert.throws(() => verifyReleaseCandidateArtifacts({ ...manifest,
    packages: [repacked, manifest.packages[1]],
  }, input.artifactDir, input.workspaces), /packed contract source or generated contract hash mismatch/u);
  packContract(root);
  manifest = buildReleaseCandidateManifest(input);
  const extraSourceKey = "contracts/trust-registry/dist/managed/trust-registry/keys/extra.verifier";
  put(root, extraSourceKey, "extra\n");
  assert.throws(() => buildReleaseCandidateManifest(input), /Generated verifier keys do not match/u);
  rmSync(join(root, extraSourceKey));
  for (const verifierKeySha256 of [undefined, {}, { proveA: verifierHash },
    { proveA: verifierHash, renamed: verifierHash },
    { proveA: "0".repeat(64), proveB: verifierHash },
    { proveB: verifierHash, proveA: verifierHash },
    { proveA: verifierHash, proveB: verifierHash, extra: verifierHash }]) {
    assert.throws(() => verifyReleaseCandidateArtifacts({ ...manifest, verifierKeySha256 },
      input.artifactDir, input.workspaces), /verifier-key hashes are invalid or incomplete/u);
  }
  assert.throws(() => verifyReleaseCandidateArtifacts({
    ...manifest, packages: [manifest.packages[0], manifest.packages[0]],
  }, input.artifactDir, input.workspaces), /duplicated/u);
  assert.throws(() => verifyReleaseCandidateArtifacts({
    ...manifest, packages: manifest.packages.map((entry, index) => ({
      ...entry, workspace: manifest.packages[1 - index].workspace,
    })),
  }, input.artifactDir, input.workspaces), /invalid or duplicated/u);
  assert.throws(() => verifyReleaseCandidateArtifacts({
    ...manifest, packageVersion: "0.2.0",
  }, input.artifactDir, input.workspaces), /invalid or duplicated/u);
  put(root, "artifacts/npm/unlisted-0.1.0.tgz", "extra-tarball");
  assert.throws(() => buildReleaseCandidateManifest(input), /unlisted/u);
  assert.throws(() => verifyReleaseCandidateArtifacts(manifest, input.artifactDir, input.workspaces), /unlisted/u);
  rmSync(join(root, "artifacts/npm/unlisted-0.1.0.tgz"));
  put(root, "artifacts/npm/midnight-ntwrk-trust-registry-contract-0.1.0.tgz", "tampered-tarball");
  assert.throws(() => verifyReleaseCandidateArtifacts(manifest, input.artifactDir, input.workspaces), /hash or size mismatch/u);
  packContract(root, "changed-verifier\n");
  const changedPackage = { ...manifest.packages[0], sizeBytes: statSync(contractTarball).size,
    sha256: createHash("sha256").update(readFileSync(contractTarball)).digest("hex") };
  assert.throws(() => verifyReleaseCandidateArtifacts({ ...manifest,
    packages: [changedPackage, manifest.packages[1]],
  }, input.artifactDir, input.workspaces), /verifier-key hashes are invalid or incomplete/u);
  put(root, "contracts/trust-registry/dist/managed/trust-registry/keys/proveA.verifier", "verifier-a\n");
  assert.throws(() => buildReleaseCandidateManifest(input), /Packed verifier key does not match/u);
  assert.throws(() => buildReleaseCandidateManifest({ ...input, revision: "short" }), /full Git commit SHA/u);
  rmSync(join(root, "artifacts/npm/midnight-ntwrk-trust-registry-domain-0.1.0.tgz"));
  assert.throws(() => buildReleaseCandidateManifest(input), /missing or empty/u);
});

test("hashes packed contract entries larger than the subprocess default buffer", () => {
  const root = mkdtempSync(join(tmpdir(), "tr-release-large-entry-"));
  roots.push(root);
  const content = "generated-contract\n".repeat(130_000);
  put(root, "package/dist/managed/trust-registry/contract/index.js", content);
  const binaryVerifier = Buffer.from([0x00, 0xff, 0x80, 0x0a]);
  put(root, "package/dist/managed/trust-registry/keys/proveA.verifier", binaryVerifier);
  const tarball = join(root, "contract.tgz");
  const packed = spawnSync("tar", ["-czf", tarball, "package"], { cwd: root, encoding: "utf8" });
  assert.equal(packed.status, 0, packed.stderr);
  assert.equal(hashPackedTarEntry(tarball, "package/dist/managed/trust-registry/contract/index.js"),
    createHash("sha256").update(content).digest("hex"));
  assert.equal(hashPackedTarEntry(tarball, "package/dist/managed/trust-registry/keys/proveA.verifier"),
    createHash("sha256").update(binaryVerifier).digest("hex"));
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
  assert.throws(() => assertFullPackedContract([...paths, `${prefix}/keys/extra.verifier`], info),
    /unexpected proof artifacts for extra/u);
  assert.throws(() => assertFullPackedContract(paths.map((path) => path.replace("proveA.verifier", "renamed.verifier")), info),
    /verification key for proveA/u);
  assert.throws(() => assertFullPackedContract(paths.slice(1), info), /contract-info/u);
  assert.throws(() => assertFullPackedContract([...paths, paths.at(-1)], info), /duplicate archive paths/u);
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
