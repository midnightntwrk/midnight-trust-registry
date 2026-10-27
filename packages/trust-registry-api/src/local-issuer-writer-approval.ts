import { createHash } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";

import type { LocalLedgerRuntimePlan } from "./local-ledger-runtime.js";
import { readBoundedLocalApprovalFile, verifyDetachedLocalReviewerSignature } from "./local-reviewer-signature.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;

export type LocalIssuerWriterApproval = Readonly<{
  format: "tr-local-issuer-writer-approval-v1";
  apiPlanSha256: string;
  sourceRevision: string;
  installInventorySha256: string;
  networkId: string;
  expectedGenesisHash: string;
  contractAddress: string;
  providerRoot: string;
  providerContentSha256: string;
  submissionJournalPath: string;
  notBefore: string;
  notAfter: string;
}>;

type Binding = {
  plan: Pick<LocalLedgerRuntimePlan, "sourceRevision" | "installInventorySha256" | "networkId"
    | "expectedGenesisHash" | "contractAddress" | "notBefore" | "notAfter">;
  planSha256: string;
};

const canonicalTime = (value: unknown): number => {
  const parsed = typeof value === "string" ? Date.parse(value) : Number.NaN;
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : Number.NaN;
};

/** Checks a separately signed writer annex; it never authenticates the provider, ledger, or journal. */
export function validateLocalIssuerWriterApproval(
  value: unknown, binding: Binding, now = Date.now(),
): LocalIssuerWriterApproval {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Local issuer writer approval must be an object");
  }
  const approval = value as Record<string, unknown>;
  const keys = ["format", "apiPlanSha256", "sourceRevision", "installInventorySha256",
    "networkId", "expectedGenesisHash", "contractAddress", "providerRoot",
    "providerContentSha256", "submissionJournalPath", "notBefore", "notAfter"];
  const root = approval.providerRoot;
  const journal = approval.submissionJournalPath;
  if (Object.keys(approval).length !== keys.length || keys.some((key) => !Object.hasOwn(approval, key))
    || approval.format !== "tr-local-issuer-writer-approval-v1"
    || typeof binding.planSha256 !== "string" || !SHA256.test(binding.planSha256)
    || approval.apiPlanSha256 !== binding.planSha256
    || typeof approval.sourceRevision !== "string" || !REVISION.test(approval.sourceRevision)
    || approval.sourceRevision !== binding.plan.sourceRevision
    || approval.installInventorySha256 !== binding.plan.installInventorySha256
    || approval.networkId !== binding.plan.networkId
    || typeof approval.expectedGenesisHash !== "string" || !HASH.test(approval.expectedGenesisHash)
    || approval.expectedGenesisHash !== binding.plan.expectedGenesisHash
    || typeof approval.contractAddress !== "string" || !HASH.test(approval.contractAddress)
    || approval.contractAddress !== binding.plan.contractAddress
    || typeof approval.providerContentSha256 !== "string" || !SHA256.test(approval.providerContentSha256)
    || /^0{64}$/u.test(approval.providerContentSha256)
    || typeof root !== "string" || !isAbsolute(root) || resolve(root) !== root
    || typeof journal !== "string" || !isAbsolute(journal) || resolve(journal) !== journal
    || root === journal || (relative(root, journal) !== ".."
      && !relative(root, journal).startsWith(`..${sep}`))
    || !Number.isFinite(canonicalTime(approval.notBefore))
    || !Number.isFinite(canonicalTime(approval.notAfter))
    || canonicalTime(approval.notBefore) < canonicalTime(binding.plan.notBefore)
    || canonicalTime(approval.notAfter) > canonicalTime(binding.plan.notAfter)
    || canonicalTime(approval.notAfter) <= canonicalTime(approval.notBefore)
    || now < canonicalTime(approval.notBefore) || now > canonicalTime(approval.notAfter)) {
    throw new Error("Local issuer writer approval differs from the signed API plan or reviewed install pins");
  }
  return Object.freeze(approval as LocalIssuerWriterApproval);
}

export async function loadApprovedLocalIssuerWriterApproval(input: Binding & {
  approvalPath: string;
  signaturePath: string;
  keyringDirectory: string;
  reviewerFingerprint: string;
}): Promise<{ approval: LocalIssuerWriterApproval; approvalSha256: string }> {
  const bytes = await readBoundedLocalApprovalFile(input.approvalPath, 64 * 1024);
  await verifyDetachedLocalReviewerSignature({
    documentBytes: bytes, signaturePath: input.signaturePath,
    keyringDirectory: input.keyringDirectory, reviewerFingerprint: input.reviewerFingerprint,
    description: "Local issuer writer approval",
  });
  const raw = bytes.toString("utf8");
  const parsed: unknown = JSON.parse(raw);
  if (!Buffer.from(raw, "utf8").equals(bytes)
    || ![JSON.stringify(parsed), `${JSON.stringify(parsed)}\n`, `${JSON.stringify(parsed, null, 2)}\n`].includes(raw)) {
    throw new Error("Local issuer writer approval must use canonical signed JSON");
  }
  return {
    approval: validateLocalIssuerWriterApproval(parsed, input),
    approvalSha256: createHash("sha256").update(bytes).digest("hex"),
  };
}
