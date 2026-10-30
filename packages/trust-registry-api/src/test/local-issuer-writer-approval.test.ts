import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it } from "vitest";

import {
  loadApprovedLocalIssuerWriterApproval,
  validateLocalIssuerWriterApproval,
} from "../local-issuer-writer-approval.js";

const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");

const fixture = () => {
  const plan = {
    sourceRevision: "a".repeat(40), installInventorySha256: "b".repeat(64),
    networkId: "undeployed" as const, expectedGenesisHash: `0x${"c".repeat(64)}`,
    contractAddress: `0x${"d".repeat(64)}`,
    notBefore: new Date(Date.now() - 60_000).toISOString(),
    notAfter: new Date(Date.now() + 3_600_000).toISOString(),
  };
  const planSha256 = "e".repeat(64);
  const approvedPlanReviewerFingerprint = "A".repeat(40);
  const approval = {
    format: "tr-local-issuer-writer-approval-v1", apiPlanSha256: planSha256,
    reviewerFingerprint: approvedPlanReviewerFingerprint,
    sourceRevision: plan.sourceRevision, installInventorySha256: plan.installInventorySha256,
    networkId: plan.networkId, expectedGenesisHash: plan.expectedGenesisHash,
    contractAddress: plan.contractAddress,
    providerRoot: "/opt/trust-registry/provider",
    providerContentSha256: "f".repeat(64),
    submissionJournalPath: "/var/lib/trust-registry/issuer-journal.json",
    notBefore: plan.notBefore, notAfter: plan.notAfter,
  };
  return { plan, planSha256, approvedPlanReviewerFingerprint, approval };
};

it("binds the writer annex to one signed plan, reviewed tree, and outside journal", () => {
  const { plan, planSha256, approvedPlanReviewerFingerprint, approval } = fixture();
  const binding = { plan, planSha256, approvedPlanReviewerFingerprint };
  expect(validateLocalIssuerWriterApproval(approval, binding)).toEqual(approval);
  for (const changed of [
    { apiPlanSha256: "1".repeat(64) },
    { reviewerFingerprint: "B".repeat(40) },
    { sourceRevision: "1".repeat(40) },
    { installInventorySha256: "1".repeat(64) },
    { networkId: "preview" },
    { expectedGenesisHash: `0x${"1".repeat(64)}` },
    { contractAddress: `0x${"1".repeat(64)}` },
    { providerContentSha256: "0".repeat(64) },
    { providerRoot: "relative/provider" },
    { providerRoot: "/opt/trust-registry/../provider" },
    { submissionJournalPath: "/opt/trust-registry/provider/journal.json" },
    { submissionJournalPath: "relative/journal.json" },
    { notAfter: new Date(Date.parse(plan.notAfter) + 1).toISOString() },
    { extra: true },
  ]) {
    expect(() => validateLocalIssuerWriterApproval({ ...approval, ...changed }, binding))
      .toThrow(/differs from the signed API plan/u);
  }
  expect(() => validateLocalIssuerWriterApproval(approval, binding,
    Date.parse(plan.notAfter) + 1)).toThrow(/differs from the signed API plan/u);
});

it("loads only the exact detached-signed writer annex", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-iw-"));
  try {
    const signer = join(root, "signer");
    const verifier = join(root, "verifier");
    await mkdir(signer, { mode: 0o700 });
    await mkdir(verifier, { mode: 0o700 });
    execFileSync("gpg", ["--homedir", signer, "--batch", "--pinentry-mode", "loopback",
      "--passphrase", "", "--quick-generate-key", "Writer Reviewer <reviewer@example.test>",
      "ed25519", "sign", "0"], { stdio: "pipe", timeout: 30_000 });
    const listing = execFileSync("gpg", ["--homedir", signer, "--batch", "--with-colons",
      "--list-secret-keys"], { encoding: "utf8" });
    const fingerprint = listing.split("\n").find((line) => line.startsWith("fpr:"))?.split(":")[9];
    expect(fingerprint).toMatch(/^[A-F0-9]{40}$/u);
    const publicKey = execFileSync("gpg", ["--homedir", signer, "--batch", "--export", fingerprint!]);
    execFileSync("gpg", ["--homedir", verifier, "--batch", "--import"],
      { input: publicKey, stdio: ["pipe", "pipe", "pipe"] });
    const { plan, planSha256, approval } = fixture();
    approval.reviewerFingerprint = fingerprint!;
    const approvalPath = join(root, "writer.json");
    const signaturePath = join(root, "writer.sig");
    const bytes = `${JSON.stringify(approval, null, 2)}\n`;
    await writeFile(approvalPath, bytes, { mode: 0o600 });
    execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
      "--output", signaturePath, approvalPath]);
    const input = { approvalPath, signaturePath, keyringDirectory: verifier,
      approvedPlanReviewerFingerprint: fingerprint!, plan, planSha256 };
    const loaded = await loadApprovedLocalIssuerWriterApproval(input);
    expect(loaded.approval).toEqual(approval);
    expect(loaded.approvalSha256).toBe(sha256(bytes));
    await expect(loadApprovedLocalIssuerWriterApproval({ ...input,
      approvedPlanReviewerFingerprint: "B".repeat(40) }))
      .rejects.toThrow(/approved detached reviewer signature/u);
    await writeFile(approvalPath, `${JSON.stringify({ ...approval,
      providerContentSha256: "1".repeat(64) }, null, 2)}\n`);
    await expect(loadApprovedLocalIssuerWriterApproval(input))
      .rejects.toThrow(/approved detached reviewer signature/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}, 30_000);
