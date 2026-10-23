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

async function imageArchive(root, role, digest = manifestDigest, repoTags = null, imageName = null) {
  const source = join(root, `source-${role}`);
  await mkdir(join(source, "blobs/sha256"), { recursive: true });
  await writeFile(join(source, "blobs/sha256", digest), manifestBytes);
  await writeFile(join(source, "blobs/sha256", configDigest), configBytes);
  await writeFile(join(source, "index.json"), JSON.stringify({
    schemaVersion: 2, manifests: [{ digest: `sha256:${digest}`,
      ...(imageName ? { annotations: imageName === reference(role).split("@")[0]
        ? { "containerd.io/distribution.source.docker.io": imageName }
        : { "io.containerd.image.name": imageName } } : {}) }],
  }));
  await writeFile(join(source, "manifest.json"), JSON.stringify([{
    Config: `blobs/sha256/${configDigest}`, RepoTags: repoTags, Layers: [],
  }]));
  const archive = join(root, "images", `${role}.tar`);
  execFileSync("tar", ["-cf", archive, "-C", source, "index.json", "manifest.json", "blobs"]);
  return sha(await readFile(archive));
}

async function apiImageArchive(root, labelRevision = revision, repoTags = null, options = {}) {
  const source = join(root, "source-api");
  await mkdir(join(source, "blobs/sha256"), { recursive: true });
  const config = JSON.stringify({ os: "linux", architecture: "arm64", config: {
    Labels: { "org.opencontainers.image.revision": labelRevision }, User: "1000:1000",
    WorkingDir: "/app", Entrypoint: ["node", "/app/bin/trust-registry-api.mjs"],
    ...(options.env ? { Env: options.env } : {}),
  } });
  const configId = sha(config);
  const image = JSON.stringify({ schemaVersion: 2, config: { digest: `sha256:${configId}` }, layers: [] });
  const imageDigest = sha(image);
  const imageIndex = JSON.stringify({ schemaVersion: 2, manifests: [{ digest: `sha256:${imageDigest}`,
    platform: { os: "linux", architecture: "arm64" } },
  ...(options.extraPlatform ? [{ digest: `sha256:${"f".repeat(64)}`,
    platform: { os: "linux", architecture: "amd64" } }] : [])] });
  const imageId = `sha256:${sha(imageIndex)}`;
  await writeFile(join(source, "blobs/sha256", configId), config);
  await writeFile(join(source, "blobs/sha256", imageDigest), image);
  await writeFile(join(source, "blobs/sha256", imageId.slice(7)), imageIndex);
  await writeFile(join(source, "index.json"), JSON.stringify({ schemaVersion: 2,
    manifests: [{ digest: imageId,
      ...(options.outerName ? { annotations: { "io.containerd.image.name": options.outerName } } : {}) }] }));
  await writeFile(join(source, "manifest.json"), JSON.stringify([{ Config: `blobs/sha256/${configId}`,
    RepoTags: repoTags, Layers: [] }]));
  const archive = join(root, "images/api.image.tar");
  execFileSync("tar", ["-cf", archive, "-C", source, "index.json", "manifest.json", "blobs"]);
  const archiveSha256 = sha(await readFile(archive));
  const manifest = { format: "tr-api-runtime-image-v1", sourceRevision: revision,
    approvedSignerFingerprint: "A".repeat(40), platform: "linux/arm64",
    baseImage: `example.test/base@sha256:${"b".repeat(64)}`,
    lockfileSha256: "c".repeat(64), dockerfileSha256: "d".repeat(64),
    payload: { fileCount: 1, sha256: "e".repeat(64) }, imageId,
    archiveName: "api.image.tar", archiveSha256 };
  const manifestBytes = JSON.stringify(manifest);
  await writeFile(join(root, "images/api.manifest.json"), manifestBytes);
  return { manifest: "images/api.manifest.json", manifestSha256: sha(manifestBytes),
    archive: "images/api.image.tar", archiveSha256, imageId };
}

async function staticImageArchive(root, role, options = {}) {
  const source = join(root, `source-static-${role}`);
  await mkdir(join(source, "blobs/sha256"), { recursive: true });
  const config = JSON.stringify({ os: "linux", architecture: "arm64", config: {
    Labels: { "org.opencontainers.image.revision": options.labelRevision ?? revision },
    User: "1000:1000", WorkingDir: "/app",
    Env: options.env ?? [`TR_STATIC_ROLE=${role}`],
    Cmd: ["node", "/app/entrypoint.mjs", "--host", "0.0.0.0", "--port", "4173"],
  } });
  const configId = sha(config);
  const image = JSON.stringify({ schemaVersion: 2, config: { digest: `sha256:${configId}` }, layers: [] });
  const imageDigest = sha(image);
  const imageIndex = JSON.stringify({ schemaVersion: 2, manifests: [{
    digest: `sha256:${imageDigest}`, platform: { os: "linux", architecture: "arm64" },
  }, ...(options.extraPlatform ? [{ digest: `sha256:${imageDigest}`,
    platform: { os: "linux", architecture: "amd64" } }] : [])] });
  const imageId = `sha256:${sha(imageIndex)}`;
  await writeFile(join(source, "blobs/sha256", configId), config);
  await writeFile(join(source, "blobs/sha256", imageDigest), image);
  await writeFile(join(source, "blobs/sha256", imageId.slice(7)), imageIndex);
  await writeFile(join(source, "index.json"), JSON.stringify({ schemaVersion: 2,
    manifests: [{ digest: imageId,
      ...(options.outerName ? { annotations: { "io.containerd.image.name": options.outerName } } : {}) }] }));
  await writeFile(join(source, "manifest.json"), JSON.stringify([{ Config: `blobs/sha256/${configId}`,
    RepoTags: options.repoTags ?? null, Layers: [] }]));
  const archive = join(root, `images/${role}.image.tar`);
  execFileSync("tar", ["-cf", archive, "-C", source, "index.json", "manifest.json", "blobs"]);
  const archiveSha256 = sha(await readFile(archive));
  const assets = [{ path: "index.html", size: 1, sha256: "f".repeat(64) }];
  const manifest = { format: "tr-static-runtime-image-v1", role, sourceRevision: revision,
    approvedSignerFingerprint: "A".repeat(40), platform: "linux/arm64",
    baseImage: `example.test/base@sha256:${"b".repeat(64)}`,
    assetsSha256: sha(JSON.stringify(assets)), imageId,
    archiveName: `${role}.image.tar`, archiveSha256, assets };
  const bytes = JSON.stringify(manifest);
  await writeFile(join(root, `images/${role}.manifest.json`), bytes);
  return { manifest: `images/${role}.manifest.json`, manifestSha256: sha(bytes),
    archive: `images/${role}.image.tar`, archiveSha256, imageId };
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
    packageManifest: "release.json", packageManifestSha256: sha(await readFile(join(root, "release.json"))),
    artifactDirectory: "artifacts", images,
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
    assert.equal(result.packageManifestSha256, sha(await readFile(join(root, "release.json"))));
    assert.deepEqual(result.imageRoles, ["indexer", "node", "proof-server"]);
    assert.equal(result.images.length, 3);
    assert.ok(result.images.every((image) => image.configId === `sha256:${configDigest}`));
    assert.ok(result.images.every((image) => image.acceptedIds.includes(
      `sha256:${image.reference.split("@sha256:")[1]}`)));
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
    const originalManifest = await readFile(join(root, "release.json"));
    await writeFile(join(root, "release.json"), JSON.stringify({ sourceRevision: revision, packages: [], changed: true }));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /release manifest bytes disagree/u);
    await writeFile(join(root, "release.json"), originalManifest);
    delete inventory.packageManifestSha256;
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /release manifest bytes disagree/u);
    inventory.packageManifestSha256 = sha(originalManifest);
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
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

test("v4 binds an API archive to the exact install source and runtime config", async () => {
  const { root, inventory } = await fixture();
  try {
    const compose = Buffer.from(`name: \${TR_STACK_NAME:-tr-standalone-local-smoke}\nservices:\n  node:\n    image: ${reference("node")}\n  indexer:\n    image: ${reference("indexer")}\n  proof-server:\n    image: ${reference("proof-server")}\n`);
    const offlineCompose = Buffer.from("services: {}\n");
    await writeFile(join(root, "compose.yml"), compose);
    await writeFile(join(root, "compose.offline.yml"), offlineCompose);
    inventory.format = "tr-standalone-install-v4";
    inventory.runtimeCompose = { path: "compose.yml", sha256: sha(compose),
      offlinePath: "compose.offline.yml", offlineSha256: sha(offlineCompose) };
    inventory.apiRuntime = await apiImageArchive(root);
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    const verified = await verifyStandaloneInstallBundle(root, () => {});
    assert.equal(verified.apiRuntime.imageId, inventory.apiRuntime.imageId);
    assert.equal(verified.apiRuntime.platform, "linux/arm64");

    const apiManifestPath = join(root, "images/api.manifest.json");
    const original = await readFile(apiManifestPath);
    await writeFile(apiManifestPath, "{}\n");
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /API image bytes disagree/u);
    await writeFile(apiManifestPath, original);
    const altered = JSON.parse(original);
    altered.sourceRevision = "b".repeat(40);
    const alteredBytes = JSON.stringify(altered);
    await writeFile(apiManifestPath, alteredBytes);
    inventory.apiRuntime.manifestSha256 = sha(alteredBytes);
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /manifest is malformed or disagrees/u);
    await writeFile(apiManifestPath, original);
    inventory.apiRuntime.manifestSha256 = sha(original);
    const wrongRuntime = await apiImageArchive(root, "b".repeat(40));
    inventory.apiRuntime.archiveSha256 = sha(await readFile(join(root, "images/api.image.tar")));
    altered.archiveSha256 = inventory.apiRuntime.archiveSha256;
    altered.sourceRevision = revision;
    altered.imageId = wrongRuntime.imageId;
    const mismatchedBytes = JSON.stringify(altered);
    await writeFile(apiManifestPath, mismatchedBytes);
    inventory.apiRuntime.manifestSha256 = sha(mismatchedBytes);
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /runtime config disagrees/u);
    const tagged = await apiImageArchive(root, revision, ["example.test/api:latest"]);
    const taggedManifest = JSON.parse(await readFile(apiManifestPath));
    taggedManifest.imageId = tagged.imageId;
    taggedManifest.archiveSha256 = tagged.archiveSha256;
    const taggedBytes = JSON.stringify(taggedManifest);
    await writeFile(apiManifestPath, taggedBytes);
    inventory.apiRuntime.manifestSha256 = sha(taggedBytes);
    inventory.apiRuntime.archiveSha256 = tagged.archiveSha256;
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /imports a tag/u);
    for (const options of [
      { outerName: "tr-standalone/node:sha-fake" },
      { extraPlatform: true },
      { env: ["NODE_OPTIONS=--import=data:text/javascript,throw%20Error('injected')"] },
    ]) {
      const changed = await apiImageArchive(root, revision, null, options);
      const changedManifest = JSON.parse(await readFile(apiManifestPath));
      changedManifest.imageId = changed.imageId;
      changedManifest.archiveSha256 = changed.archiveSha256;
      const bytes = JSON.stringify(changedManifest);
      await writeFile(apiManifestPath, bytes);
      inventory.apiRuntime.manifestSha256 = sha(bytes);
      inventory.apiRuntime.archiveSha256 = changed.archiveSha256;
      await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
      await assert.rejects(verifyStandaloneInstallBundle(root, () => {}),
        options.outerName ? /OCI index disagrees/u
          : options.extraPlatform ? /exactly one image/u : /runtime config disagrees/u);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("v5 binds both portal OCI archives to the exact install source and roles", async () => {
  const { root, inventory } = await fixture();
  try {
    const compose = Buffer.from(`name: \${TR_STACK_NAME:-tr-standalone-local-smoke}\nservices:\n  node:\n    image: ${reference("node")}\n  indexer:\n    image: ${reference("indexer")}\n  proof-server:\n    image: ${reference("proof-server")}\n`);
    const offlineCompose = Buffer.from("services: {}\n");
    await writeFile(join(root, "compose.yml"), compose);
    await writeFile(join(root, "compose.offline.yml"), offlineCompose);
    inventory.format = "tr-standalone-install-v5";
    inventory.runtimeCompose = { path: "compose.yml", sha256: sha(compose),
      offlinePath: "compose.offline.yml", offlineSha256: sha(offlineCompose) };
    inventory.apiRuntime = await apiImageArchive(root);
    inventory.portalRuntimes = {
      admin: await staticImageArchive(root, "admin"),
      applicant: await staticImageArchive(root, "applicant"),
    };
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    const verified = await verifyStandaloneInstallBundle(root, () => {});
    assert.equal(verified.portalRuntimes.admin.imageId, inventory.portalRuntimes.admin.imageId);
    assert.equal(verified.portalRuntimes.applicant.imageId, inventory.portalRuntimes.applicant.imageId);
    delete inventory.portalRuntimes.applicant;
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /both portal/u);
    inventory.portalRuntimes.applicant = await staticImageArchive(root, "applicant");
    const wrongRole = await staticImageArchive(root, "admin", { labelRevision: "b".repeat(40) });
    inventory.portalRuntimes.admin = wrongRole;
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /runtime/u);
    inventory.portalRuntimes.admin = await staticImageArchive(root, "admin", {
      outerName: "tr-static-admin:latest",
    });
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /OCI index is malformed/u);
    for (const options of [
      { env: ["TR_STATIC_ROLE=admin", "TR_STATIC_ROLE=applicant"] },
      { env: ["TR_STATIC_ROLE=admin", "NODE_OPTIONS=--import=/tmp/evil.mjs"] },
      { extraPlatform: true },
    ]) {
      inventory.portalRuntimes.admin = await staticImageArchive(root, "admin", options);
      await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
      await assert.rejects(verifyStandaloneInstallBundle(root, () => {}),
        options.extraPlatform ? /OCI index/u : /runtime/u);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("v6 pins the installation relay script beside the complete runtime", async () => {
  const { root, inventory } = await fixture();
  try {
    const compose = Buffer.from(`name: \${TR_STACK_NAME:-tr-standalone-local-smoke}\nservices:\n  node:\n    image: ${reference("node")}\n  indexer:\n    image: ${reference("indexer")}\n  proof-server:\n    image: ${reference("proof-server")}\n`);
    const offlineCompose = Buffer.from("services: {}\n");
    await writeFile(join(root, "compose.yml"), compose);
    await writeFile(join(root, "compose.offline.yml"), offlineCompose);
    inventory.format = "tr-standalone-install-v6";
    inventory.runtimeCompose = { path: "compose.yml", sha256: sha(compose),
      offlinePath: "compose.offline.yml", offlineSha256: sha(offlineCompose) };
    inventory.apiRuntime = await apiImageArchive(root);
    inventory.portalRuntimes = {
      admin: await staticImageArchive(root, "admin"),
      applicant: await staticImageArchive(root, "applicant"),
    };
    const relay = Buffer.from("# fixed destination installation relay\n");
    await writeFile(join(root, "install-relay.py"), relay);
    inventory.installRelay = { path: "install-relay.py", sha256: sha(relay), imageRole: "node" };
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    const verified = await verifyStandaloneInstallBundle(root, () => {});
    assert.equal(verified.installRelay.sha256, sha(relay));
    assert.equal(verified.installRelay.image.reference, reference("node"));
    await writeFile(join(root, "install-relay.py"), "changed\n");
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /relay bytes disagree/u);
    await writeFile(join(root, "install-relay.py"), relay);
    inventory.installRelay.imageRole = "indexer";
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /relay pin is missing/u);
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

test("rejects a ledger image name hidden in OCI index annotations", async () => {
  const { root, inventory } = await fixture();
  try {
    inventory.images[0].archiveSha256 = await imageArchive(root, "node", manifestDigest, null,
      "tr-standalone/proof-server:sha-unapproved");
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /OCI manifest digest disagrees/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("accepts only the pinned repository as a ledger distribution-source annotation", async () => {
  const { root, inventory } = await fixture();
  try {
    inventory.images[0].archiveSha256 = await imageArchive(root, "node", manifestDigest, null,
      reference("node").split("@")[0]);
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await verifyStandaloneInstallBundle(root, () => {});
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
