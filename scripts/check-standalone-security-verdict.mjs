#!/usr/bin/env node

import { lstat } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  checkStandaloneAcceptanceEvidence,
  readAcceptanceManifest,
  readPrivateObservation,
} from "./check-standalone-acceptance-evidence.mjs";
import { verifyDetachedReviewerSignature } from "./standalone-setup-wizard.mjs";

const FINGERPRINT = /^[0-9A-F]{40}$/u;

/**
 * Verify only the signature and candidate binding. Identity, independence,
 * findings, and the truth of deployment evidence remain human review gates.
 * @param {string} root
 * @param {string} sourceRevision
 * @param {string} verdictPath
 * @param {string} signaturePath
 * @param {string} publicKeyPath
 * @param {string} expectedFingerprint Pinned by the release owner outside the verdict bundle.
 * @param {typeof verifyDetachedReviewerSignature} [verifySignature]
 */
export async function checkStandaloneSecurityVerdict(
  root, sourceRevision, verdictPath, signaturePath, publicKeyPath, expectedFingerprint,
  verifySignature = verifyDetachedReviewerSignature,
) {
  if (!FINGERPRINT.test(expectedFingerprint)) throw new Error("Expected reviewer fingerprint must be canonical");
  const stat = await lstat(root);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0) {
    throw new Error("Evidence root must be a private real directory");
  }
  const manifest = await readAcceptanceManifest(root);
  await checkStandaloneAcceptanceEvidence(root, manifest, sourceRevision);
  const paths = new Set(manifest.cases.S01.evidence.map((item) => item.path));
  if (verdictPath === signaturePath || !paths.has(verdictPath) || !paths.has(signaturePath)
    || verdictPath.toLowerCase().startsWith("decisions/")
    || signaturePath.toLowerCase().startsWith("decisions/")) {
    throw new Error("Verdict and detached signature must be distinct raw S01 attachments");
  }
  const verdict = await readPrivateObservation(root, verdictPath);
  const expectedKeys = ["format", "sourceRevision", "installInventorySha256", "signedPlanSha256",
    "genesisHash", "contractAddress", "reviewerFingerprint", "reviewedAt", "scope", "outcome"];
  if (!verdict || typeof verdict !== "object" || Array.isArray(verdict)
    || Object.keys(verdict).sort().join("|") !== expectedKeys.sort().join("|")
    || verdict.format !== "tr-local-security-verdict-v1"
    || verdict.sourceRevision !== manifest.sourceRevision
    || verdict.installInventorySha256 !== manifest.installInventorySha256
    || verdict.signedPlanSha256 !== manifest.signedPlanSha256
    || verdict.genesisHash !== manifest.genesisHash
    || verdict.contractAddress !== manifest.contractAddress
    || verdict.reviewerFingerprint !== expectedFingerprint
    || verdict.scope !== "self-hosted-local-0.1.0"
    || !["approve", "reject"].includes(verdict.outcome)
    || typeof verdict.reviewedAt !== "string" || !Number.isFinite(Date.parse(verdict.reviewedAt))) {
    throw new Error("Security verdict does not bind the selected standalone candidate");
  }
  await verifySignature(resolve(root, verdictPath), resolve(root, signaturePath),
    publicKeyPath, expectedFingerprint, verdict.reviewedAt);
  return {
    format: "tr-local-security-verdict-check-v1",
    sourceRevision: manifest.sourceRevision,
    outcome: verdict.outcome,
    signatureValidForPinnedKey: true,
    reviewerIndependence: "not-verified",
    findingsDisposition: "not-verified",
    deploymentEvidence: "not-verified",
    releaseQualified: false,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 8 || !isAbsolute(process.argv[2]) || !isAbsolute(process.argv[5])) {
      throw new Error("Usage: check-standalone-security-verdict.mjs <absolute-private-evidence-dir> <source-sha> <relative-verdict-json> <absolute-public-key-or-keyring> <relative-detached-signature> <trusted-reviewer-fingerprint>");
    }
    const report = await checkStandaloneSecurityVerdict(
      resolve(process.argv[2]), process.argv[3], process.argv[4], process.argv[6],
      resolve(process.argv[5]), process.argv[7],
    );
    console.log(JSON.stringify(report, null, 2));
    if (report.outcome !== "approve") process.exitCode = 2;
  } catch (error) {
    console.error(`Standalone security verdict check failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
