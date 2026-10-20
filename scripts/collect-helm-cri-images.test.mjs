import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { collectHelmCriImageReceipt, collectSignedHelmCriImages,
  validateCriEndpoint, validateSignedImageMapping,
  verifyCriImageStatus, checkHelmCriReceiptConsistency } from "./collect-helm-cri-images.mjs";

const roles = ["node", "indexer", "proofServer", "api", "admin", "applicant"];
const reference = (role) => `registry.example.test/tr/${role.toLowerCase()}@sha256:${"a".repeat(64)}`;
const configId = (role) => `sha256:${String(roles.indexOf(role) + 1).repeat(64)}`;
const mapping = { format: "tr-helm-image-mapping-v1", sourceRevision: "b".repeat(40),
  inventorySha256: "c".repeat(64), valuesSha256: "d".repeat(64),
  images: roles.map((role) => ({ role, reference: reference(role),
    imageId: configId(role), configId: configId(role), archiveSha256: "f".repeat(64) })) };
const bytes = Buffer.from(`${JSON.stringify(mapping)}\n`);
const endpoint = "unix:///run/containerd/containerd.sock";
const inspecti = (role) => ({ status: { id: configId(role),
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
  assert.deepEqual(checkHelmCriReceiptConsistency(bytes, receipt).observedRoles, roles);
});

test("rejects an absent digest, wrong config ID, empty image, or incomplete record", async () => {
  assert.throws(() => verifyCriImageStatus({ status: { ...inspecti("node").status,
    repoDigests: [reference("indexer")] } }, reference("node"), configId("node")), /exact reviewed/u);
  assert.throws(() => verifyCriImageStatus({ status: { ...inspecti("node").status,
    size: "0" } }, reference("node"), configId("node")), /exact reviewed/u);
  assert.throws(() => verifyCriImageStatus(inspecti("indexer"), reference("node"),
    configId("node")), /exact reviewed/u);
  const receipt = await collectHelmCriImageReceipt(bytes, "worker-1", endpoint,
    async (_command, args) => ({ stdout: JSON.stringify(inspecti(roles.find((role) =>
      reference(role) === args.at(-1)))) }), "node-host");
  receipt.images[0].inspecti.status.repoDigests = [];
  assert.throws(() => checkHelmCriReceiptConsistency(bytes, receipt), /exact reviewed/u);
  receipt.images[0].inspecti.status.repoDigests = [reference("node")];
  receipt.images.pop();
  assert.throws(() => checkHelmCriReceiptConsistency(bytes, receipt), /does not match/u);
  receipt.images.push({ role: "applicant", reference: reference("applicant"),
    inspecti: inspecti("applicant") });
  receipt.mappingSha256 = "0".repeat(64);
  assert.throws(() => checkHelmCriReceiptConsistency(bytes, receipt), /does not match/u);
});

test("requires a complete signed mapping, explicit Unix endpoint, and node identity", async () => {
  assert.throws(() => validateSignedImageMapping({ ...mapping,
    images: mapping.images.slice(1) }), /malformed/u);
  const short = structuredClone(mapping);
  short.images[0].reference = `midnightntwrk/node@sha256:${"a".repeat(64)}`;
  assert.throws(() => validateSignedImageMapping(short), /pinned node/u);
  assert.throws(() => validateCriEndpoint("tcp://127.0.0.1:9000"), /Unix/u);
  assert.throws(() => validateCriEndpoint("unix:///run/../private.sock"), /Unix/u);
  await assert.rejects(collectHelmCriImageReceipt(bytes, "worker..one", endpoint,
    async () => { throw new Error("must not run"); }), /node name/u);
});

test("signed collector rejects invalid approval before CRI and writes one private receipt", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-helm-cri-test-"));
  try {
    const mappingPath = join(root, "mapping.json");
    const outputPath = join(root, "node-receipt.json");
    await writeFile(mappingPath, bytes);
    const paths = { mappingPath, outputPath, signaturePath: join(root, "mapping.sig"),
      keyringPath: join(root, "reviewer.gpg"), signerFingerprint: "A".repeat(40),
      nodeName: "worker-1", imageEndpoint: endpoint };
    let calls = 0;
    const run = async (_command, args) => {
      calls += 1;
      return { stdout: JSON.stringify(inspecti(roles.find((role) =>
        reference(role) === args.at(-1)))) };
    };
    assert.throws(() => verifyCriImageStatus(inspecti("node"), reference("node"),
      configId("api")), /exact reviewed/u);
    await assert.rejects(collectSignedHelmCriImages(paths, run, () => {
      throw new Error("bad signature");
    }), /bad signature/u);
    assert.equal(calls, 0);
    assert.equal((await readFile(mappingPath)).toString(), bytes.toString());
    const result = await collectSignedHelmCriImages(paths, run, () => {}, "node-host");
    assert.deepEqual(result.observedRoles, roles);
    assert.equal(calls, roles.length);
    assert.equal((await stat(outputPath)).mode & 0o777, 0o600);
    assert.equal(JSON.parse(await readFile(outputPath, "utf8")).collectorHost, "node-host");
    await assert.rejects(collectSignedHelmCriImages(paths, run, () => {}, "node-host"),
      { code: "EEXIST" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
