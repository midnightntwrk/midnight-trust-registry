#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { open, readFile } from "node:fs/promises";
import { hostname } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { verifyMappingSignature } from "./verify-helm-mapping-signature.mjs";

const execFileAsync = promisify(execFile);
const SHA256 = /^[0-9a-f]{64}$/u;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;
const REFERENCE = /^[a-z0-9][a-z0-9.:-]*(\/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}$/u;
const NODE = /^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/u;
const ROLES = ["node", "indexer", "proofServer", "api", "admin", "applicant"];
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function validateCriEndpoint(endpoint) {
  if (typeof endpoint !== "string" || !endpoint.startsWith("unix:///")
    || !/^unix:\/\/\/[A-Za-z0-9_./-]+$/u.test(endpoint)
    || endpoint.slice(8).split("/").some((part) => part === ".." || part === "." || part === "")) {
    throw new Error("An explicit absolute Unix CRI image endpoint is required");
  }
  return endpoint;
}

export function validateSignedImageMapping(mapping) {
  if (mapping?.format !== "tr-helm-image-mapping-v1"
    || !/^[0-9a-f]{40}$/u.test(mapping.sourceRevision)
    || !SHA256.test(mapping.inventorySha256)
    || !SHA256.test(mapping.valuesSha256)
    || !Array.isArray(mapping.images) || mapping.images.length !== ROLES.length
    || new Set(mapping.images.map((entry) => entry?.role)).size !== ROLES.length) {
    throw new Error("Signed Helm image mapping is malformed");
  }
  for (const role of ROLES) {
    const entry = mapping.images.find((image) => image.role === role);
    if (!REFERENCE.test(entry?.reference) || !IMAGE_ID.test(entry?.imageId)
      || !IMAGE_ID.test(entry?.configId)
      || !SHA256.test(entry?.archiveSha256)) {
      throw new Error(`Signed Helm image mapping lacks a pinned ${role} image`);
    }
  }
  return mapping;
}

export function verifyCriImageStatus(inspecti, reference, approvedConfigId) {
  const status = inspecti?.status;
  if (!IMAGE_ID.test(approvedConfigId) || status?.id !== approvedConfigId
    || !Array.isArray(status.repoDigests)
    || !status.repoDigests.includes(reference)
    || !/^[1-9][0-9]*$/u.test(String(status.size))) {
    throw new Error(`CRI image store does not report the exact reviewed reference: ${reference}`);
  }
  return status.id;
}

export async function collectHelmCriImageReceipt(mappingBytes, nodeName, imageEndpoint,
  run = execFileAsync, host = hostname()) {
  const mapping = validateSignedImageMapping(JSON.parse(mappingBytes));
  if (typeof nodeName !== "string" || nodeName.length > 253 || !NODE.test(nodeName)
    || nodeName.split(".").some((part) => part.length === 0 || part.length > 63)) {
    throw new Error("Kubernetes node name must be an explicit DNS name");
  }
  validateCriEndpoint(imageEndpoint);
  const images = [];
  for (const role of ROLES) {
    const { reference, configId } = mapping.images.find((image) => image.role === role);
    const { stdout } = await run("crictl", ["--image-endpoint", imageEndpoint,
      "inspecti", "--quiet", "--output", "json", reference], {
      timeout: 30_000, maxBuffer: 4 * 1024 * 1024,
    });
    const inspecti = JSON.parse(stdout);
    verifyCriImageStatus(inspecti, reference, configId);
    images.push({ role, reference, inspecti });
  }
  return { format: "tr-helm-cri-node-images-v1", nodeName, collectorHost: host,
    imageEndpoint, collectedAt: new Date().toISOString(), mappingSha256: sha256(mappingBytes),
    sourceRevision: mapping.sourceRevision, images };
}

/** Checks record consistency, not node identity or authenticity of the JSON. */
export function checkHelmCriReceiptConsistency(mappingBytes, receipt) {
  const mapping = validateSignedImageMapping(JSON.parse(mappingBytes));
  if (receipt?.format !== "tr-helm-cri-node-images-v1"
    || receipt.mappingSha256 !== sha256(mappingBytes)
    || receipt.sourceRevision !== mapping.sourceRevision
    || typeof receipt.nodeName !== "string" || !NODE.test(receipt.nodeName)
    || !Array.isArray(receipt.images) || receipt.images.length !== ROLES.length
    || new Set(receipt.images.map((image) => image?.role)).size !== ROLES.length) {
    throw new Error("Node CRI receipt does not match the approved image mapping");
  }
  validateCriEndpoint(receipt.imageEndpoint);
  for (const role of ROLES) {
    const { reference, configId } = mapping.images.find((image) => image.role === role);
    const image = receipt.images.find((entry) => entry.role === role);
    if (image.reference !== reference) {
      throw new Error(`Node CRI receipt uses an unexpected ${role} reference`);
    }
    verifyCriImageStatus(image.inspecti, reference, configId);
  }
  return { nodeName: receipt.nodeName, sourceRevision: mapping.sourceRevision,
    mappingSha256: receipt.mappingSha256, observedRoles: [...ROLES] };
}

export async function collectSignedHelmCriImages(paths, run = execFileAsync,
  verifySignature = verifyMappingSignature, host = hostname()) {
  const mappingBytes = await readFile(paths.mappingPath);
  verifySignature(mappingBytes, paths.signaturePath, paths.keyringPath,
    paths.signerFingerprint);
  const receipt = await collectHelmCriImageReceipt(mappingBytes, paths.nodeName,
    paths.imageEndpoint, run, host);
  const output = await open(paths.outputPath, "wx", 0o600);
  try {
    await output.writeFile(`${JSON.stringify(receipt, null, 2)}\n`);
    await output.sync();
  } finally {
    await output.close();
  }
  return checkHelmCriReceiptConsistency(mappingBytes, receipt);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 9) {
    throw new Error("Usage: node scripts/collect-helm-cri-images.mjs <mapping.json> <mapping.sig> <reviewer-keyring> <reviewer-fingerprint> <kubernetes-node-name> <unix:///cri-image-socket> <new-output.json>");
  }
  const [mappingPath, signaturePath, keyringPath, signerFingerprint,
    nodeName, imageEndpoint, outputPath] = process.argv.slice(2);
  console.log(JSON.stringify(await collectSignedHelmCriImages({ mappingPath, signaturePath,
    keyringPath, signerFingerprint, nodeName, imageEndpoint, outputPath })));
}
