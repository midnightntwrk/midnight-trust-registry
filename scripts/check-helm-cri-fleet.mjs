#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { checkHelmImageMapping } from "./check-helm-image-mapping.mjs";
import { checkHelmCriReceiptConsistency, validateCriEndpoint,
  validateSignedImageMapping } from "./collect-helm-cri-images.mjs";
import { verifyMappingSignature } from "./verify-helm-mapping-signature.mjs";

const DNS_LABEL = /^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/u;
const RELEASE = /^[a-z](?:[-a-z0-9]*[a-z0-9])?$/u;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function validDnsName(value, maxLength = 253) {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength
    && value.split(".").every((part) => part.length <= 63 && DNS_LABEL.test(part));
}

export function validateApprovedNodeScope(scope, mappingBytes) {
  const mapping = validateSignedImageMapping(JSON.parse(mappingBytes));
  if (scope?.format !== "tr-helm-approved-node-scope-v1"
    || scope.sourceRevision !== mapping.sourceRevision
    || scope.mappingSha256 !== sha256(mappingBytes)
    || typeof scope.namespace !== "string" || scope.namespace.length > 63
    || !DNS_LABEL.test(scope.namespace)
    || typeof scope.releaseName !== "string" || scope.releaseName.length > 47
    || !RELEASE.test(scope.releaseName)
    || scope.eligibleNodeSelection !== "kubernetes.io/arch=arm64"
    || typeof scope.clusterReference !== "string" || scope.clusterReference.length < 8
    || typeof scope.approvedAt !== "string" || !Number.isFinite(Date.parse(scope.approvedAt))
    || typeof scope.reviewedReference !== "string" || scope.reviewedReference.length < 8
    || !Array.isArray(scope.nodes) || scope.nodes.length === 0 || scope.nodes.length > 256
    || new Set(scope.nodes.map((node) => node?.name)).size !== scope.nodes.length) {
    throw new Error("Approved Kubernetes node scope is missing, duplicate, or mismatched");
  }
  for (const node of scope.nodes) {
    if (!validDnsName(node?.name) || !validDnsName(node.collectorHost)) {
      throw new Error("Approved node identity is malformed");
    }
    validateCriEndpoint(node.imageEndpoint);
  }
  return scope;
}

/** Checks records against a signed scope; it cannot authenticate the machines or the scope's completeness. */
export function checkHelmCriFleet(mappingBytes, preflight, scopeBytes, receiptBytesByNode) {
  const mapping = validateSignedImageMapping(JSON.parse(mappingBytes));
  const scope = validateApprovedNodeScope(JSON.parse(scopeBytes), mappingBytes);
  if (preflight?.mappingSha256 !== sha256(mappingBytes)
    || preflight.sourceRevision !== mapping.sourceRevision
    || preflight.inventorySha256 !== mapping.inventorySha256
    || !(receiptBytesByNode instanceof Map)
    || receiptBytesByNode.size !== scope.nodes.length) {
    throw new Error("Fleet evidence is not paired with a passing install mapping preflight");
  }
  const receipts = [];
  for (const node of scope.nodes) {
    const bytes = receiptBytesByNode.get(node.name);
    if (!Buffer.isBuffer(bytes)) throw new Error(`Missing CRI receipt for approved node: ${node.name}`);
    const receipt = JSON.parse(bytes);
    const checked = checkHelmCriReceiptConsistency(mappingBytes, receipt);
    if (checked.nodeName !== node.name
      || receipt.collectorHost !== node.collectorHost
      || receipt.imageEndpoint !== node.imageEndpoint) {
      throw new Error(`CRI receipt does not match approved node identity: ${node.name}`);
    }
    receipts.push({ nodeName: node.name, sha256: sha256(bytes) });
  }
  return { format: "tr-helm-cri-fleet-consistency-v1", sourceRevision: mapping.sourceRevision,
    mappingSha256: sha256(mappingBytes), scopeSha256: sha256(scopeBytes),
    namespace: scope.namespace, releaseName: scope.releaseName,
    coveredApprovedScope: true, receipts: receipts.sort((a, b) => a.nodeName.localeCompare(b.nodeName)) };
}

async function boundedReceipt(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size === 0 || stat.size > 2 * 1024 * 1024) {
    throw new Error("Node receipt must be a bounded regular file");
  }
  return readFile(path);
}

export async function checkSignedHelmCriFleet(paths, dependencies = {}) {
  const mappingBytes = await readFile(paths.preflightPaths.receiptPath);
  const preflight = await (dependencies.checkPreflight ?? checkHelmImageMapping)(paths.preflightPaths);
  if (preflight.mappingSha256 !== sha256(mappingBytes)) {
    throw new Error("Signed image mapping changed during fleet verification");
  }
  const scopeBytes = await readFile(paths.scopePath);
  (dependencies.verifySignature ?? verifyMappingSignature)(scopeBytes, paths.scopeSignaturePath, paths.scopeKeyringPath,
    paths.scopeSignerFingerprint);
  const scope = validateApprovedNodeScope(JSON.parse(scopeBytes), mappingBytes);
  const directory = await realpath(resolve(paths.receiptsDirectory));
  const entries = await readdir(directory, { withFileTypes: true });
  const expected = scope.nodes.map((node) => `node-${node.name}.json`).sort();
  if (entries.some((entry) => !entry.isFile())
    || entries.map((entry) => entry.name).sort().join("\0") !== expected.join("\0")) {
    throw new Error("Receipt directory must contain exactly one regular file per approved node");
  }
  const receipts = new Map();
  for (const node of scope.nodes) {
    receipts.set(node.name, await boundedReceipt(join(directory, `node-${node.name}.json`)));
  }
  return checkHelmCriFleet(mappingBytes, preflight, scopeBytes, receipts);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 8) {
    throw new Error("Usage: node scripts/check-helm-cri-fleet.mjs <preflight-paths.json> <approved-node-scope.json> <scope.sig> <scope-keyring> <scope-signer-fingerprint> <receipts-directory>");
  }
  const [preflightPathsFile, scopePath, scopeSignaturePath, scopeKeyringPath,
    scopeSignerFingerprint, receiptsDirectory] = process.argv.slice(2);
  const preflightPaths = JSON.parse(await readFile(preflightPathsFile, "utf8"));
  console.log(JSON.stringify(await checkSignedHelmCriFleet({ preflightPaths, scopePath,
    scopeSignaturePath, scopeKeyringPath, scopeSignerFingerprint, receiptsDirectory }), null, 2));
}
