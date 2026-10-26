import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { collectHelmCriImageReceipt } from "./collect-helm-cri-images.mjs";
import { checkHelmCriFleet, checkSignedHelmCriFleet,
  validateApprovedNodeScope } from "./check-helm-cri-fleet.mjs";

const roles = ["node", "indexer", "proofServer", "api", "admin", "applicant"];
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const endpoint = "unix:///run/containerd/containerd.sock";
const configId = (index) => `sha256:${String(index + 1).repeat(64)}`;
const reference = (role) => `registry.example.test/tr/${role.toLowerCase()}@sha256:${"a".repeat(64)}`;
const mapping = { format: "tr-helm-image-mapping-v1", sourceRevision: "b".repeat(40),
  inventorySha256: "c".repeat(64), valuesSha256: "d".repeat(64),
  images: roles.map((role, index) => ({ role, reference: reference(role),
    imageId: configId(index), configId: configId(index), archiveSha256: "f".repeat(64) })) };
const mappingBytes = Buffer.from(`${JSON.stringify(mapping)}\n`);
const preflight = { sourceRevision: mapping.sourceRevision,
  inventorySha256: mapping.inventorySha256, mappingSha256: sha256(mappingBytes) };
const scope = { format: "tr-helm-approved-node-scope-v1", sourceRevision: mapping.sourceRevision,
  mappingSha256: sha256(mappingBytes), namespace: "trust-registry", releaseName: "tr-rc",
  eligibleNodeSelection: "kubernetes.io/arch=arm64", clusterReference: "local-cluster-01",
  approvedAt: "2026-10-20T00:00:00Z", reviewedReference: "review-record-01",
  nodes: [{ name: "worker-1", collectorHost: "worker-1", imageEndpoint: endpoint },
    { name: "worker-2", collectorHost: "worker-2", imageEndpoint: endpoint }] };
const scopeBytes = Buffer.from(`${JSON.stringify(scope)}\n`);

async function receipt(node) {
  const value = await collectHelmCriImageReceipt(mappingBytes, node.name, node.imageEndpoint,
    async (_command, args) => {
      const index = roles.findIndex((role) => reference(role) === args.at(-1));
      return { stdout: JSON.stringify({ status: { id: configId(index),
        repoDigests: [args.at(-1)], size: "12345" } }) };
    }, node.collectorHost);
  return Buffer.from(`${JSON.stringify(value)}\n`);
}

async function receipts() {
  return new Map(await Promise.all(scope.nodes.map(async (node) => [node.name, await receipt(node)])));
}

test("covers every approved node with one matching CRI receipt", async () => {
  const observed = await receipts();
  const result = checkHelmCriFleet(mappingBytes, preflight, scopeBytes, observed);
  assert.equal(result.coveredApprovedScope, true);
  assert.equal(result.scopeSha256, sha256(scopeBytes));
  assert.deepEqual(result.receipts.map((entry) => entry.nodeName), ["worker-1", "worker-2"]);
});

test("rejects missing, extra, duplicate, or mismatched node observations", async () => {
  const observed = await receipts();
  observed.delete("worker-2");
  assert.throws(() => checkHelmCriFleet(mappingBytes, preflight, scopeBytes, observed), /receipt count/u);
  observed.set("unexpected", await receipt(scope.nodes[1]));
  assert.throws(() => checkHelmCriFleet(mappingBytes, preflight, scopeBytes, observed), /Missing CRI receipt/u);
  observed.set("worker-2", await receipt(scope.nodes[1]));
  assert.throws(() => checkHelmCriFleet(mappingBytes, preflight, scopeBytes, observed), /receipt count/u);
  observed.delete("unexpected");
  const duplicate = { ...scope, nodes: [scope.nodes[0], scope.nodes[0]] };
  assert.throws(() => validateApprovedNodeScope(duplicate, mappingBytes), /duplicate/u);
  assert.throws(() => validateApprovedNodeScope({ ...scope,
    nodes: [scope.nodes[0], { ...scope.nodes[1], collectorHost: "worker-1" }] }, mappingBytes), /duplicate/u);
  const forged = JSON.parse(observed.get("worker-2"));
  forged.collectorHost = "other-host";
  observed.set("worker-2", Buffer.from(JSON.stringify(forged)));
  assert.throws(() => checkHelmCriFleet(mappingBytes, preflight, scopeBytes, observed), /node identity/u);
  forged.collectorHost = "worker-2";
  forged.nodeName = "worker-1";
  observed.set("worker-2", Buffer.from(JSON.stringify(forged)));
  assert.throws(() => checkHelmCriFleet(mappingBytes, preflight, scopeBytes, observed), /node identity/u);
  forged.nodeName = "worker-2";
  forged.imageEndpoint = "unix:///var/run/other.sock";
  observed.set("worker-2", Buffer.from(JSON.stringify(forged)));
  assert.throws(() => checkHelmCriFleet(mappingBytes, preflight, scopeBytes, observed), /node identity/u);
  forged.imageEndpoint = endpoint;
  forged.images[0].inspecti.status.id = configId(1);
  observed.set("worker-2", Buffer.from(JSON.stringify(forged)));
  assert.throws(() => checkHelmCriFleet(mappingBytes, preflight, scopeBytes, observed), /exact reviewed/u);
  forged.images[0].inspecti.status.id = configId(0);
  forged.collectedAt = "2025-10-20T00:00:00Z";
  observed.set("worker-2", Buffer.from(JSON.stringify(forged)));
  assert.throws(() => checkHelmCriFleet(mappingBytes, preflight, scopeBytes, observed), /predates/u);
  forged.collectedAt = "2026";
  observed.set("worker-2", Buffer.from(JSON.stringify(forged)));
  assert.throws(() => checkHelmCriFleet(mappingBytes, preflight, scopeBytes, observed), /ISO-8601/u);
});

test("rejects altered scope, mapping, preflight, and invalid node selectors", async () => {
  const observed = await receipts();
  assert.throws(() => checkHelmCriFleet(mappingBytes, { ...preflight,
    mappingSha256: "0".repeat(64) }, scopeBytes, observed), /preflight/u);
  assert.throws(() => checkHelmCriFleet(mappingBytes, preflight,
    Buffer.from(JSON.stringify({ ...scope, mappingSha256: "0".repeat(64) })), observed), /scope/u);
  assert.throws(() => validateApprovedNodeScope({ ...scope,
    eligibleNodeSelection: "kubernetes.io/arch=amd64" }, mappingBytes), /scope/u);
  assert.throws(() => validateApprovedNodeScope({ ...scope,
    approvedAt: "2026" }, mappingBytes), /ISO-8601/u);
  assert.throws(() => validateApprovedNodeScope({ ...scope,
    approvedAt: "2026-02-30T00:00:00Z" }, mappingBytes), /real UTC/u);
  assert.throws(() => validateApprovedNodeScope({ ...scope,
    nodes: [{ ...scope.nodes[0], imageEndpoint: "tcp://host:9000" }] }, mappingBytes), /Unix/u);
});

test("signed checker requires exactly one regular file per scoped node", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-helm-fleet-test-"));
  try {
    const receiptsDirectory = join(root, "receipts");
    await mkdir(receiptsDirectory);
    const mappingPath = join(root, "mapping.json");
    const scopePath = join(root, "scope.json");
    await writeFile(mappingPath, mappingBytes);
    await writeFile(scopePath, scopeBytes);
    const observed = await receipts();
    for (const [name, bytes] of observed) {
      await writeFile(join(receiptsDirectory, `node-${name}.json`), bytes);
    }
    const paths = { preflightPaths: { receiptPath: mappingPath }, scopePath,
      scopeSignaturePath: "scope.sig", scopeKeyringPath: "reviewer.gpg",
      scopeSignerFingerprint: "A".repeat(40), receiptsDirectory };
    const dependencies = { checkPreflight: async () => preflight,
      verifySignature: () => {} };
    assert.equal((await checkSignedHelmCriFleet(paths, dependencies)).receipts.length, 2);
    await assert.rejects(checkSignedHelmCriFleet(paths, { ...dependencies,
      verifySignature: () => { throw new Error("invalid signature"); } }), /invalid signature/u);
    await writeFile(join(receiptsDirectory, "extra.json"), "{}");
    await assert.rejects(checkSignedHelmCriFleet(paths, dependencies), /exactly one/u);
    await rm(join(receiptsDirectory, "extra.json"));
    await rm(join(receiptsDirectory, "node-worker-2.json"));
    await symlink(join(receiptsDirectory, "node-worker-1.json"),
      join(receiptsDirectory, "node-worker-2.json"));
    await assert.rejects(checkSignedHelmCriFleet(paths, dependencies), /regular file/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
