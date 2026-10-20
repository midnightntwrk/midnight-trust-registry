import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { approvedMappingSigner, staticImageIdsFromArchive, verifyHelmImageMapping,
  verifyMappingSignature } from "./check-helm-image-mapping.mjs";

const revision = "a".repeat(40);
const inventorySha256 = "b".repeat(64);
const valuesSha256 = "7".repeat(64);
const archiveSha256 = "c".repeat(64);
const imageId = `sha256:${"d".repeat(64)}`;
const roles = ["node", "indexer", "proofServer", "api", "admin", "applicant"];
const images = roles.map((role) => ({ role,
  reference: `registry.example.test/tr/${role.toLowerCase()}@sha256:${"e".repeat(64)}`,
  archiveSha256, imageId, configId: imageId }));
const bundle = {
  sourceRevision: revision,
  inventorySha256,
  images: ["node", "indexer", "proof-server"].map((role) => ({ role, acceptedIds: [imageId] })),
  apiRuntime: { imageId, configId: imageId },
};
const inventory = {
  format: "tr-standalone-install-v4",
  images: ["node", "indexer", "proof-server"].map((role) => ({ role, archiveSha256 })),
  apiRuntime: { archiveSha256 },
};
const portals = {
  admin: { archiveSha256, acceptedIds: [imageId], configId: imageId },
  applicant: { archiveSha256, acceptedIds: [imageId], configId: imageId },
};
const values = { deploymentPhase: "runtime", imagePullPolicy: "Never",
  images: Object.fromEntries(images.map(({ role, reference }) => [role, reference])) };
const receipt = { format: "tr-helm-image-mapping-v1", sourceRevision: revision,
  inventorySha256, valuesSha256, images };

test("accepts an exact six-role image mapping", () => {
  assert.deepEqual(verifyHelmImageMapping(bundle, inventory, portals, values, receipt, valuesSha256), {
    sourceRevision: revision, inventorySha256, mappedRoles: roles, deploymentPhase: "runtime",
  });
});

test("rejects changed registry references and archive identities", () => {
  const changed = structuredClone(receipt);
  changed.images[0].reference = `registry.example.test/tr/other@sha256:${"e".repeat(64)}`;
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values, changed, valuesSha256), /node/u);
  changed.images[0].reference = receipt.images[0].reference;
  changed.images[0].archiveSha256 = "f".repeat(64);
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values, changed, valuesSha256), /node/u);
  changed.images[0].archiveSha256 = archiveSha256;
  changed.images[0].imageId = `sha256:${"f".repeat(64)}`;
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values, changed, valuesSha256), /node/u);
  changed.images[0].imageId = imageId;
  changed.images[0].configId = `sha256:${"f".repeat(64)}`;
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values, changed, valuesSha256), /node/u);
});

test("rejects missing roles, tag references, unpinned inventory, and pulls", () => {
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values,
    { ...receipt, images: images.slice(1) }, valuesSha256), /roles/u);
  const tagged = structuredClone(receipt);
  tagged.images[0].reference = "registry.example.test/tr/node:latest";
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values, tagged, valuesSha256), /node/u);
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals,
    { ...values, imagePullPolicy: "Always" }, receipt, valuesSha256), /disagree/u);
  assert.throws(() => verifyHelmImageMapping(bundle,
    { ...inventory, format: "tr-standalone-install-v3" }, portals, values, receipt, valuesSha256), /disagree/u);
});

test("rejects stale source, inventory, and portal identities", () => {
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values,
    { ...receipt, sourceRevision: "f".repeat(40) }, valuesSha256), /disagree/u);
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values,
    { ...receipt, inventorySha256: "f".repeat(64) }, valuesSha256), /disagree/u);
  assert.throws(() => verifyHelmImageMapping(bundle, inventory,
    { ...portals, admin: { archiveSha256, acceptedIds: [], configId: imageId } }, values,
    receipt, valuesSha256), /admin/u);
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values,
    { ...receipt, valuesSha256: "f".repeat(64) }, valuesSha256), /disagree/u);
});

test("static archive config ID is checked against runtime revision and role", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-static-archive-test-"));
  try {
    const config = Buffer.from(JSON.stringify({ os: "linux", architecture: "arm64",
      config: { Labels: { "org.opencontainers.image.revision": revision },
        User: "1000:1000", WorkingDir: "/app", Env: ["TR_STATIC_ROLE=admin"],
        Cmd: ["node", "/app/entrypoint.mjs", "--host", "0.0.0.0", "--port", "4173"] } }));
    const digest = createHash("sha256").update(config).digest("hex");
    await mkdir(join(root, "blobs", "sha256"), { recursive: true });
    await writeFile(join(root, "blobs", "sha256", digest), config);
    await writeFile(join(root, "manifest.json"), JSON.stringify([{
      Config: `blobs/sha256/${digest}`, RepoTags: null,
    }]));
    const archive = join(root, "image.tar");
    execFileSync("tar", ["-cf", archive, "-C", root, "manifest.json", `blobs/sha256/${digest}`]);
    assert.deepEqual(staticImageIdsFromArchive(archive, "admin", revision), [`sha256:${digest}`]);
    assert.throws(() => staticImageIdsFromArchive(archive, "applicant", revision), /runtime/u);
    assert.throws(() => staticImageIdsFromArchive(archive, "admin", "f".repeat(40)), /runtime/u);
    const imageManifest = Buffer.from(JSON.stringify({ schemaVersion: 2,
      config: { digest: `sha256:${digest}` }, layers: [] }));
    const imageDigest = createHash("sha256").update(imageManifest).digest("hex");
    const imageIndex = Buffer.from(JSON.stringify({ schemaVersion: 2,
      manifests: [{ digest: `sha256:${imageDigest}`, platform: { os: "linux", architecture: "arm64" } }] }));
    const indexDigest = createHash("sha256").update(imageIndex).digest("hex");
    await writeFile(join(root, "blobs", "sha256", imageDigest), imageManifest);
    await writeFile(join(root, "blobs", "sha256", indexDigest), imageIndex);
    await writeFile(join(root, "index.json"), JSON.stringify({ schemaVersion: 2,
      manifests: [{ digest: `sha256:${indexDigest}` }] }));
    const ociArchive = join(root, "oci.tar");
    execFileSync("tar", ["-cf", ociArchive, "-C", root, "index.json", "manifest.json",
      `blobs/sha256/${digest}`, `blobs/sha256/${imageDigest}`, `blobs/sha256/${indexDigest}`]);
    assert.deepEqual(staticImageIdsFromArchive(ociArchive, "admin", revision),
      [`sha256:${digest}`, `sha256:${imageDigest}`, `sha256:${indexDigest}`]);
    await writeFile(join(root, "index.json"), "{invalid-json");
    const invalidArchive = join(root, "invalid.tar");
    execFileSync("tar", ["-cf", invalidArchive, "-C", root, "index.json", "manifest.json",
      `blobs/sha256/${digest}`]);
    assert.throws(() => staticImageIdsFromArchive(invalidArchive, "admin", revision));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("detached mapping signature covers the exact bytes and approved signer", async (t) => {
  if (spawnSync("gpg", ["--version"], { stdio: "ignore" }).status !== 0
    || spawnSync("gpgv", ["--version"], { stdio: "ignore" }).status !== 0) {
    t.skip("gpg and gpgv are required");
    return;
  }
  const root = await mkdtemp(join(tmpdir(), "tr-helm-signature-test-"));
  try {
    const home = join(root, "signer");
    await mkdir(home, { mode: 0o700 });
    try {
      execFileSync("gpg", ["--homedir", home, "--batch", "--pinentry-mode", "loopback",
        "--passphrase", "", "--quick-generate-key", "Helm Reviewer <reviewer@example.test>",
        "ed25519", "sign", "0"], { stdio: "pipe", timeout: 30_000 });
    } catch (error) {
      if (/No agent running|can't connect to the gpg-agent/u.test(String(error.stderr))) {
        t.skip("temporary-home gpg-agent is unavailable on this host");
        return;
      }
      throw error;
    }
    const listing = execFileSync("gpg", ["--homedir", home, "--batch", "--with-colons",
      "--list-secret-keys"], { encoding: "utf8" });
    const fingerprint = listing.split("\n").find((line) => line.startsWith("fpr:"))?.split(":")[9];
    assert.match(fingerprint, /^[0-9A-F]{40}$/u);
    const keyring = join(root, "reviewer.gpg");
    await writeFile(keyring, execFileSync("gpg", ["--homedir", home, "--batch", "--export", fingerprint]));
    const bytes = Buffer.from('{"format":"tr-helm-image-mapping-v1"}\n');
    const signature = join(root, "mapping.sig");
    execFileSync("gpg", ["--homedir", home, "--batch", "--yes", "--detach-sign",
      "--output", signature], { input: bytes, stdio: ["pipe", "pipe", "pipe"] });
    assert.equal(verifyMappingSignature(bytes, signature, keyring, fingerprint), fingerprint);
    assert.throws(() => verifyMappingSignature(Buffer.from("changed"), signature, keyring,
      fingerprint), /valid detached signature/u);
    assert.throws(() => verifyMappingSignature(bytes, signature, keyring,
      "B".repeat(40)), /approved signer/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("GPG status accepts a primary fingerprint for a signing subkey but rejects revoked keys", () => {
  const signer = "A".repeat(40);
  const primary = "B".repeat(40);
  const status = `[GNUPG:] VALIDSIG ${signer} 2026-10-20 0 0 4 0 22 8 00 ${primary}\n`;
  assert.equal(approvedMappingSigner(status, signer), signer);
  assert.equal(approvedMappingSigner(status, primary), primary);
  assert.throws(() => approvedMappingSigner(status, "C".repeat(40)), /approved signer/u);
  assert.throws(() => approvedMappingSigner(`${status}[GNUPG:] REVKEYSIG ${signer}\n`, primary), /revoked/u);
  assert.throws(() => approvedMappingSigner(`${status}[GNUPG:] EXPKEYSIG ${signer}\n`, primary), /expired/u);
});
