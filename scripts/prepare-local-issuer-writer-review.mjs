#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import { lstat, link, open, realpath, unlink } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { loadApprovedLocalLedgerRuntimePlanWithDigest } from "../packages/trust-registry-api/dist/local-ledger-runtime.js";
import { validateLocalIssuerWriterApproval } from "../packages/trust-registry-api/dist/local-issuer-writer-approval.js";
import { verifyInstalledProviderRuntime } from "./verify-installed-provider-runtime.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const within = (parent, path) => {
  const child = relative(parent, path);
  return child === "" || (child !== ".." && !child.startsWith(`..${sep}`));
};

/** Writes review bytes only. Approval, signing, and deployment are separate human actions. */
export async function prepareLocalIssuerWriterReview(input, dependencies = {}) {
  const { outputDirectory, providerRoot, submissionJournalPath } = input;
  if (![outputDirectory, providerRoot, submissionJournalPath].every((path) =>
    typeof path === "string" && isAbsolute(path) && resolve(path) === path)
    || typeof input.reviewedContentSha256 !== "string" || !SHA256.test(input.reviewedContentSha256)
    || /^0{64}$/u.test(input.reviewedContentSha256)
    || within(providerRoot, outputDirectory) || within(providerRoot, submissionJournalPath)) {
    throw new Error("Writer review requires canonical paths outside the provider tree and a reviewed content digest");
  }
  const directory = await lstat(outputDirectory);
  if (!directory.isDirectory() || (directory.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && directory.uid !== process.getuid())
    || await realpath(outputDirectory) !== outputDirectory) {
    throw new Error("Writer review output requires an owned, private, nonsymlink directory");
  }
  const approved = await (dependencies.loadPlan ?? loadApprovedLocalLedgerRuntimePlanWithDigest)({
    planPath: input.planPath, signaturePath: input.signaturePath,
    keyringDirectory: input.keyringDirectory, reviewerFingerprint: input.reviewerFingerprint,
    requireApprovalChain: true,
  });
  if (approved.reviewerFingerprint !== input.reviewerFingerprint) {
    throw new Error("Writer review signer differs from the verified API plan reviewer fingerprint");
  }
  if (approved.plan.format !== "tr-local-api-runtime-v3") {
    throw new Error("Writer review requires an approval-chain-bound v3 API plan");
  }
  const report = await (dependencies.verifyProvider ?? verifyInstalledProviderRuntime)(providerRoot, {
    sourceRevision: approved.plan.sourceRevision,
    inventorySha256: approved.plan.installInventorySha256,
    contentSha256: input.reviewedContentSha256,
  });
  if (report.format !== "tr-installed-provider-runtime-verification-v1"
    || report.sourceRevision !== approved.plan.sourceRevision
    || report.installInventorySha256 !== approved.plan.installInventorySha256
    || report.contentSha256 !== input.reviewedContentSha256
    || report.ownership !== "trusted-tree-check-passed" || report.releaseQualified !== false) {
    throw new Error("Installed provider report differs from the reviewed source and content pins");
  }
  const draft = validateLocalIssuerWriterApproval({
    format: "tr-local-issuer-writer-approval-v1",
    apiPlanSha256: approved.planSha256,
    reviewerFingerprint: approved.reviewerFingerprint,
    sourceRevision: approved.plan.sourceRevision,
    installInventorySha256: approved.plan.installInventorySha256,
    networkId: approved.plan.networkId,
    expectedGenesisHash: approved.plan.expectedGenesisHash,
    contractAddress: approved.plan.contractAddress,
    providerRoot,
    providerContentSha256: input.reviewedContentSha256,
    submissionJournalPath,
    notBefore: approved.plan.notBefore,
    notAfter: approved.plan.notAfter,
  }, { plan: approved.plan, planSha256: approved.planSha256,
    approvedPlanReviewerFingerprint: approved.reviewerFingerprint });
  const bytes = Buffer.from(`${JSON.stringify(draft, null, 2)}\n`);
  const output = join(outputDirectory, "issuer-writer-approval.unsigned.json");
  const temporary = `${output}.${randomUUID()}.tmp`;
  try {
    const file = await open(temporary, "wx", 0o600);
    try {
      await file.writeFile(bytes);
      await file.sync();
    } finally {
      await file.close();
    }
    await link(temporary, output);
  } finally {
    await unlink(temporary).catch(() => {});
  }
  return {
    format: "tr-local-issuer-writer-review-packet-v1",
    path: output,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    sourceRevision: approved.plan.sourceRevision,
    status: "unsigned-human-review-required",
    releaseQualified: false,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 10) {
    throw new Error("Usage: node scripts/prepare-local-issuer-writer-review.mjs <private-output-dir> <signed-plan> <plan-signature> <private-reviewer-keyring> <reviewer-fingerprint> <installed-provider-root> <independently-reviewed-content-sha256> <absolute-journal-path>");
  }
  const [outputDirectory, planPath, signaturePath, keyringDirectory, reviewerFingerprint,
    providerRoot, reviewedContentSha256, submissionJournalPath] = process.argv.slice(2);
  console.log(JSON.stringify(await prepareLocalIssuerWriterReview({
    outputDirectory, planPath, signaturePath, keyringDirectory, reviewerFingerprint,
    providerRoot, reviewedContentSha256, submissionJournalPath,
  })));
}
