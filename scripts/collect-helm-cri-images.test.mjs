import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { collectHelmCriImageReceipt, validateCriEndpoint, validateSignedImageMapping,
  verifyCriImageStatus, verifyHelmCriImageReceipt } from "./collect-helm-cri-images.mjs";

const roles = ["node", "indexer", "proofServer", "api", "admin", "applicant"];
const reference = (role) => `registry.example.test/tr/${role.toLowerCase()}@sha256:${"a".repeat(64)}`;
const mapping = { format: "tr-helm-image-mapping-v1", sourceRevision: "b".repeat(40),
  inventorySha256: "c".repeat(64), valuesSha256: "d".repeat(64),
  images: roles.map((role) => ({ role, reference: reference(role),
    imageId: `sha256:${"e".repeat(64)}`, archiveSha256: "f".repeat(64) })) };
const bytes = Buffer.from(`${JSON.stringify(mapping)}\n`);
const endpoint = "unix:///run/containerd/containerd.sock";
const inspecti = (role) => ({ status: { id: `sha256:${"e".repeat(64)}`,
  repoDigests: [reference(role)], size: "12345" } });

test("collects one exact CRI observation for each signed role without pulling", async () => {
  const calls = [];
  const run = async (command, args) => {
    calls.push([command, args]);
    const role = roles.find((entry) => reference(entry) === args.at(-1));
    return { stdout: JSON.stringify(inspecti(role)) };
  };
  const receipt = await collectHelmCriImageReceipt(bytes, "worker-1", endpoint, run, "node-host");
  assert.equal(receipt.mappingSha256, createHash("sha256").update(bytes).digest("hex"));
  assert.equal(receipt.nodeName, "worker-1");
  assert.equal(receipt.collectorHost, "node-host");
  assert.deepEqual(calls.map(([, args]) => args), roles.map((role) => [
    "--image-endpoint", endpoint, "inspecti", "--quiet", "--output", "json", reference(role),
  ]));
  assert.deepEqual(verifyHelmCriImageReceipt(bytes, receipt).observedRoles, roles);
});

test("rejects an absent digest, empty image, or fabricated node observation", async () => {
  assert.throws(() => verifyCriImageStatus({ status: { ...inspecti("node").status,
    repoDigests: [reference("indexer")] } }, reference("node")), /exact reviewed/u);
  assert.throws(() => verifyCriImageStatus({ status: { ...inspecti("node").status,
    size: "0" } }, reference("node")), /exact reviewed/u);
  const receipt = await collectHelmCriImageReceipt(bytes, "worker-1", endpoint,
    async (_command, args) => ({ stdout: JSON.stringify(inspecti(roles.find((role) =>
      reference(role) === args.at(-1)))) }), "node-host");
  receipt.images[0].inspecti.status.repoDigests = [];
  assert.throws(() => verifyHelmCriImageReceipt(bytes, receipt), /exact reviewed/u);
  receipt.images[0].inspecti.status.repoDigests = [reference("node")];
  receipt.images.pop();
  assert.throws(() => verifyHelmCriImageReceipt(bytes, receipt), /does not match/u);
});

test("requires a complete signed mapping, explicit Unix endpoint, and node identity", async () => {
  assert.throws(() => validateSignedImageMapping({ ...mapping,
    images: mapping.images.slice(1) }), /malformed/u);
  assert.throws(() => validateCriEndpoint("tcp://127.0.0.1:9000"), /Unix/u);
  assert.throws(() => validateCriEndpoint("unix:///run/../private.sock"), /Unix/u);
  await assert.rejects(collectHelmCriImageReceipt(bytes, "worker..one", endpoint,
    async () => { throw new Error("must not run"); }), /node name/u);
});
