import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { STANDALONE_PROOF_PARAMETER_PATHS, verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const revision = "a".repeat(40);
const configBytes = JSON.stringify({ created: "fixture", architecture: "arm64" });
const configDigest = sha(configBytes);
const manifestBytes = JSON.stringify({ schemaVersion: 2,
  mediaType: "application/vnd.docker.distribution.manifest.v2+json",
  config: { digest: `sha256:${configDigest}` }, layers: [] });
const manifestDigest = sha(manifestBytes);
const reference = (role) => `example.test/${role}@sha256:${manifestDigest}`;

async function imageArchive(root, role, digest = manifestDigest, repoTags = null) {
  const source = join(root, `source-${role}`);
  await mkdir(join(source, "blobs/sha256"), { recursive: true });
  await writeFile(join(source, "blobs/sha256", digest), manifestBytes);
  await writeFile(join(source, "blobs/sha256", configDigest), configBytes);
  await writeFile(join(source, "index.json"), JSON.stringify({
    schemaVersion: 2, manifests: [{ digest: `sha256:${digest}` }],
  }));
  await writeFile(join(source, "manifest.json"), JSON.stringify([{
    Config: `blobs/sha256/${configDigest}`, RepoTags: repoTags, Layers: [],
  }]));
  const archive = join(root, "images", `${role}.tar`);
  execFileSync("tar", ["-cf", archive, "-C", source, "index.json", "manifest.json", "blobs"]);
  return sha(await readFile(archive));
}

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "tr-install-inventory-"));
  await mkdir(join(root, "artifacts"));
  await mkdir(join(root, "images"));
  await mkdir(join(root, "proof-params"));
  await writeFile(join(root, "release.json"), JSON.stringify({ sourceRevision: revision, packages: [] }));
  const images = [];
  for (const role of ["node", "indexer", "proof-server"]) {
    const archiveSha256 = await imageArchive(root, role);
    images.push({ role, reference: reference(role), archive: `images/${role}.tar`, archiveSha256 });
  }
  const proofFiles = [];
  for (const path of STANDALONE_PROOF_PARAMETER_PATHS) {
    const bytes = Buffer.from(`proof-parameter:${path}`);
    const target = join(root, "proof-params", path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes);
    proofFiles.push({ path, sha256: sha(bytes) });
  }
  const inventory = {
    format: "tr-standalone-install-v2", sourceRevision: revision,
    packageManifest: "release.json", artifactDirectory: "artifacts", images,
    proofParameters: { directory: "proof-params", files: proofFiles },
  };
  await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
  return { root, inventory };
}

test("verifies pinned packages, images, and all 18 proof parameters", async () => {
  const { root } = await fixture();
  try {
    let verified = false;
    const expectedArtifacts = join(await realpath(root), "artifacts");
    const result = await verifyStandaloneInstallBundle(root, (manifest, artifactDir) => {
      assert.equal(manifest.sourceRevision, revision);
      assert.equal(artifactDir, expectedArtifacts);
      verified = true;
    });
    assert.equal(verified, true);
    assert.deepEqual(result.imageRoles, ["indexer", "node", "proof-server"]);
    assert.equal(result.proofParameterCount, 18);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("v3 install pins complete runtime Compose bytes", async () => {
  const { root, inventory } = await fixture();
  try {
    const compose = Buffer.from(`name: \${TR_STACK_NAME:-tr-standalone-local-smoke}\nservices:\n  node:\n    image: ${reference("node")}\n  indexer:\n    image: ${reference("indexer")}\n  proof-server:\n    image: ${reference("proof-server")}\n`);
    const offlineCompose = Buffer.from("services:\n  node:\n    pull_policy: never\n  indexer:\n    pull_policy: never\n  proof-server:\n    pull_policy: never\n");
    inventory.format = "tr-standalone-install-v3";
    inventory.runtimeCompose = { path: "compose.yml", sha256: sha(compose),
      offlinePath: "compose.offline.yml", offlineSha256: sha(offlineCompose) };
    await writeFile(join(root, "compose.yml"), compose);
    await writeFile(join(root, "compose.offline.yml"), offlineCompose);
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    const result = await verifyStandaloneInstallBundle(root, () => {});
    assert.equal(result.runtimeComposeSha256, sha(compose));
    assert.equal(result.runtimeOfflineComposeSha256, sha(offlineCompose));
    inventory.images[0].reference = reference("indexer");
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /image inventory disagrees/u);
    inventory.images[0].reference = reference("node");
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await writeFile(join(root, "compose.offline.yml"), "services: {}\n");
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /Compose bytes disagree/u);
    await writeFile(join(root, "compose.offline.yml"), offlineCompose);
    await writeFile(join(root, "compose.yml"), "name: altered\n");
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /Compose bytes disagree/u);
    await rm(join(root, "compose.yml"));
    await symlink(join(root, "release.json"), join(root, "compose.yml"));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /not regular/u);
    await rm(join(root, "compose.yml"));
    inventory.runtimeCompose.path = "../outside.yml";
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /pin is missing/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects altered, missing, extra, and symlinked proof parameters", async () => {
  const { root, inventory } = await fixture();
  try {
    const first = STANDALONE_PROOF_PARAMETER_PATHS[0];
    const target = join(root, "proof-params", first);
    await writeFile(target, "altered");
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /Proof parameter hash mismatch/u);
    await rm(target);
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /incomplete/u);
    await symlink(join(root, "proof-params", STANDALONE_PROOF_PARAMETER_PATHS[1]), target);
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /non-regular/u);
    await rm(target);
    await writeFile(target, `proof-parameter:${first}`);
    await writeFile(join(root, "proof-params", "extra"), "extra");
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /extra files/u);
    await rm(join(root, "proof-params", "extra"));
    inventory.proofParameters.files.pop();
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /incomplete/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects altered archives, floating tags, missing roles, and source drift", async () => {
  const { root, inventory } = await fixture();
  try {
    const original = await readFile(join(root, "images/node.tar"));
    await writeFile(join(root, "images/node.tar"), "tampered");
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /archive hash mismatch/u);
    await writeFile(join(root, "images/node.tar"), original);
    inventory.images[0].reference = "example.test/node:latest";
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /Unpinned/u);
    inventory.images.pop();
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /required roles/u);
    inventory.images.push({ role: "proof-server", reference: reference("proof-server"),
      archive: "images/proof-server.tar", archiveSha256: await imageArchive(root, "proof-server") });
    inventory.images[0].reference = reference("node");
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await writeFile(join(root, "release.json"), JSON.stringify({ sourceRevision: "c".repeat(40), packages: [] }));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /source revision disagrees/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects an archive whose internal OCI digest disagrees with the pinned reference", async () => {
  const { root, inventory } = await fixture();
  try {
    const archive = join(root, "images/node.tar");
    inventory.images[0].archiveSha256 = await imageArchive(root, "node", "c".repeat(64));
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /OCI manifest digest disagrees/u);
    assert.ok((await readFile(archive)).length > 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects image archives that would import implicit tags", async () => {
  const { root, inventory } = await fixture();
  try {
    inventory.images[0].archiveSha256 = await imageArchive(root, "node", manifestDigest, ["example.test/node:latest"]);
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /implicit image tags/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects escaping paths and symlinked archives", async () => {
  const { root, inventory } = await fixture();
  try {
    inventory.images[0].archive = "../outside.tar";
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /Unsafe/u);
    inventory.images[0].archive = "images/node.tar";
    await rm(join(root, "images/node.tar"));
    await symlink(join(root, "images/indexer.tar"), join(root, "images/node.tar"));
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /not regular/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
