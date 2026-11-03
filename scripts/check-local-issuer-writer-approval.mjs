#!/usr/bin/env node

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadApprovedLocalLedgerRuntimePlanWithDigest } from "../packages/trust-registry-api/dist/local-ledger-runtime.js";
import { loadApprovedLocalIssuerWriterApproval } from "../packages/trust-registry-api/dist/local-issuer-writer-approval.js";
import { verifyInstalledProviderRuntime } from "./verify-installed-provider-runtime.mjs";

/** @typedef {{planPath: string, planSignaturePath: string, writerApprovalPath: string,
 * writerSignaturePath: string, keyringDirectory: string, reviewerFingerprint: string}} WriterPreflightInput */
/** @typedef {{loadPlan?: typeof loadApprovedLocalLedgerRuntimePlanWithDigest,
 * loadWriter?: typeof loadApprovedLocalIssuerWriterApproval,
 * verifyProvider?: typeof verifyInstalledProviderRuntime}} WriterPreflightDependencies */

/** Verifies a signed handoff; it never constructs a writer or asserts ledger finality.
 * @param {WriterPreflightInput} input
 * @param {WriterPreflightDependencies} [dependencies]
 */
export async function checkLocalIssuerWriterApproval(input, dependencies = {}) {
  const approved = await (dependencies.loadPlan ?? loadApprovedLocalLedgerRuntimePlanWithDigest)({
    planPath: input.planPath,
    signaturePath: input.planSignaturePath,
    keyringDirectory: input.keyringDirectory,
    reviewerFingerprint: input.reviewerFingerprint,
    requireApprovalChain: true,
  });
  if (approved.plan.format !== "tr-local-api-runtime-v3"
    || approved.reviewerFingerprint !== input.reviewerFingerprint) {
    throw new Error("Issuer writer preflight requires the verified v3 API plan reviewer");
  }
  const writer = await (dependencies.loadWriter ?? loadApprovedLocalIssuerWriterApproval)({
    approvalPath: input.writerApprovalPath,
    signaturePath: input.writerSignaturePath,
    keyringDirectory: input.keyringDirectory,
    plan: approved.plan,
    planSha256: approved.planSha256,
    approvedPlanReviewerFingerprint: approved.reviewerFingerprint,
  });
  const annex = writer.approval;
  if (annex.apiPlanSha256 !== approved.planSha256
    || annex.reviewerFingerprint !== approved.reviewerFingerprint
    || annex.sourceRevision !== approved.plan.sourceRevision
    || annex.installInventorySha256 !== approved.plan.installInventorySha256
    || annex.networkId !== approved.plan.networkId
    || annex.expectedGenesisHash !== approved.plan.expectedGenesisHash
    || annex.contractAddress !== approved.plan.contractAddress) {
    throw new Error("Signed issuer writer annex differs from the approved API plan");
  }
  const report = await (dependencies.verifyProvider ?? verifyInstalledProviderRuntime)(annex.providerRoot, {
    sourceRevision: approved.plan.sourceRevision,
    inventorySha256: approved.plan.installInventorySha256,
    contentSha256: annex.providerContentSha256,
  });
  if (report.format !== "tr-installed-provider-runtime-verification-v1"
    || report.sourceRevision !== approved.plan.sourceRevision
    || report.installInventorySha256 !== approved.plan.installInventorySha256
    || report.contentSha256 !== annex.providerContentSha256
    || report.ownership !== "trusted-tree-check-passed" || report.releaseQualified !== false) {
    throw new Error("Installed issuer provider differs from the signed writer annex");
  }
  return {
    format: "tr-local-issuer-writer-preflight-v1",
    sourceRevision: approved.plan.sourceRevision,
    planSha256: approved.planSha256,
    writerApprovalSha256: writer.approvalSha256,
    reviewerFingerprint: approved.reviewerFingerprint,
    providerContentSha256: report.contentSha256,
    submissionJournalPath: annex.submissionJournalPath,
    signedWriterApprovalVerified: true,
    installedProviderVerified: true,
    actorJourney: "not-run",
    independentFinality: "not-verified",
    releaseQualified: false,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 8) {
    throw new Error("Usage: node scripts/check-local-issuer-writer-approval.mjs <signed-plan> <plan-signature> <writer-approval> <writer-signature> <private-reviewer-keyring> <reviewer-fingerprint>");
  }
  const [planPath, planSignaturePath, writerApprovalPath, writerSignaturePath,
    keyringDirectory, reviewerFingerprint] = process.argv.slice(2);
  try {
    console.log(JSON.stringify(await checkLocalIssuerWriterApproval({
      planPath, planSignaturePath, writerApprovalPath, writerSignaturePath,
      keyringDirectory, reviewerFingerprint,
    }), null, 2));
  } catch (error) {
    console.error(`Local issuer writer preflight failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
