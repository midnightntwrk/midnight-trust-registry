import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { staticImageIdFromArchive, verifyHelmImageMapping } from "./check-helm-image-mapping.mjs";

const revision = "a".repeat(40);
const inventorySha256 = "b".repeat(64);
const archiveSha256 = "c".repeat(64);
const imageId = `sha256:${"d".repeat(64)}`;
const roles = ["node", "indexer", "proofServer", "api", "admin", "applicant"];
const images = roles.map((role) => ({ role,
  reference: `registry.example.test/tr/${role.toLowerCase()}@sha256:${"e".repeat(64)}`,
  archiveSha256, imageId }));
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
  admin: { archiveSha256, acceptedIds: [imageId] },
  applicant: { archiveSha256, acceptedIds: [imageId] },
};
const values = { deploymentPhase: "runtime", imagePullPolicy: "Never",
  images: Object.fromEntries(images.map(({ role, reference }) => [role, reference])) };
const receipt = { format: "tr-helm-image-mapping-v1", sourceRevision: revision,
  inventorySha256, images };

test("accepts an exact six-role image mapping", () => {
  assert.deepEqual(verifyHelmImageMapping(bundle, inventory, portals, values, receipt), {
    sourceRevision: revision, inventorySha256, mappedRoles: roles, deploymentPhase: "runtime",
  });
});

test("rejects changed registry references and archive identities", () => {
  const changed = structuredClone(receipt);
  changed.images[0].reference = `registry.example.test/tr/other@sha256:${"e".repeat(64)}`;
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values, changed), /node/u);
  changed.images[0].reference = receipt.images[0].reference;
  changed.images[0].archiveSha256 = "f".repeat(64);
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values, changed), /node/u);
  changed.images[0].archiveSha256 = archiveSha256;
  changed.images[0].imageId = `sha256:${"f".repeat(64)}`;
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values, changed), /node/u);
});

test("rejects missing roles, tag references, unpinned inventory, and pulls", () => {
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values,
    { ...receipt, images: images.slice(1) }), /roles/u);
  const tagged = structuredClone(receipt);
  tagged.images[0].reference = "registry.example.test/tr/node:latest";
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values, tagged), /node/u);
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals,
    { ...values, imagePullPolicy: "Always" }, receipt), /disagree/u);
  assert.throws(() => verifyHelmImageMapping(bundle,
    { ...inventory, format: "tr-standalone-install-v3" }, portals, values, receipt), /disagree/u);
});

test("rejects stale source, inventory, and portal identities", () => {
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values,
    { ...receipt, sourceRevision: "f".repeat(40) }), /disagree/u);
  assert.throws(() => verifyHelmImageMapping(bundle, inventory, portals, values,
    { ...receipt, inventorySha256: "f".repeat(64) }), /disagree/u);
  assert.throws(() => verifyHelmImageMapping(bundle, inventory,
    { ...portals, admin: { archiveSha256, acceptedIds: [] } }, values, receipt), /admin/u);
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
    assert.equal(staticImageIdFromArchive(archive, "admin", revision), `sha256:${digest}`);
    assert.throws(() => staticImageIdFromArchive(archive, "applicant", revision), /runtime/u);
    assert.throws(() => staticImageIdFromArchive(archive, "admin", "f".repeat(40)), /runtime/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
