import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { canonicalizeJson } from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it } from "vitest";

import { draftProposalRecoveryDecision, loadApprovedProposalRecoveryDecision,
  proposalRecoveryCandidateDigest } from "../proposal-recovery-decision.js";

const hash = (value: string): string => createHash("sha256").update(value).digest("hex");
const candidate = {
  format: "tr-local-proposal-recovery-candidate-v2",
  networkId: "undeployed",
  registryId: "registry:test",
  contractAddress: `0x${"1".repeat(64)}`,
  planExpectedGenesisHash: `0x${"2".repeat(64)}`,
  planSourceRevision: "3".repeat(40),
  approvedPlanSha256: "4".repeat(64),
  journalBindingDigest: `0x${"5".repeat(64)}`,
  finalizedBlockHash: `0x${"6".repeat(64)}`,
  role: "issuer",
  authorizationId: "issuer-grant-1",
  evidenceCommitment: `0x${"7".repeat(64)}`,
  attemptDigest: `0x${"8".repeat(64)}`,
  reservationState: "reserved",
  reservationActionSequence: "3",
  reservationActionKind: `0x${"9".repeat(64)}`,
  reservationActionPayloadHash: `0x${"a".repeat(64)}`,
  finalizedGovernanceActionCount: "4",
  observedEventHash: null,
  reason: "sequence-invalidated-record-absent",
  reviewCandidate: true,
  retryPermitted: false,
  releaseQualified: false,
} as const;

describe("signed local proposal recovery decision", () => {
  it("binds the candidate, finality evidence, reviewer and exact signed bytes without releasing the journal", async () => {
    const root = await mkdtemp("/tmp/tr-recovery-");
    const signer = join(root, "signer");
    const verifier = join(root, "verifier");
    try {
      await mkdir(signer, { mode: 0o700 });
      await mkdir(verifier, { mode: 0o700 });
      execFileSync("gpg", ["--homedir", signer, "--batch", "--pinentry-mode", "loopback",
        "--passphrase", "", "--quick-generate-key", "Recovery Reviewer <reviewer@example.test>",
        "ed25519", "sign", "0"], { stdio: "pipe", timeout: 30_000 });
      const listing = execFileSync("gpg", ["--homedir", signer, "--batch", "--with-colons",
        "--list-secret-keys"], { encoding: "utf8" });
      const fingerprint = listing.split("\n").find((line) => line.startsWith("fpr:"))?.split(":")[9];
      expect(fingerprint).toMatch(/^[A-F0-9]{40}$/u);
      const publicKey = execFileSync("gpg", ["--homedir", signer, "--batch", "--export", fingerprint!]);
      execFileSync("gpg", ["--homedir", verifier, "--batch", "--import"],
        { input: publicKey, stdio: ["pipe", "pipe", "pipe"] });
      const decisionPath = join(root, "recovery-decision.json");
      const signaturePath = join(root, "recovery-decision.sig");
      const finalityEvidencePath = join(root, "finality-evidence.json");
      const evidence = '{"independentReview":"test-only"}\n';
      await writeFile(finalityEvidencePath, evidence);
      const decision = {
        format: "tr-local-proposal-recovery-decision-v1",
        decision: "abandon-invalidated-action",
        candidateSha256: proposalRecoveryCandidateDigest(candidate),
        finalityEvidenceSha256: hash(evidence),
        evidenceReference: "private-review-bundle-1",
        draftedAt: new Date().toISOString(),
        reviewerFingerprint: fingerprint!,
        registryId: candidate.registryId,
        contractAddress: candidate.contractAddress,
        role: candidate.role,
        authorizationId: candidate.authorizationId,
        evidenceCommitment: candidate.evidenceCommitment,
        attemptDigest: candidate.attemptDigest,
        journalBindingDigest: candidate.journalBindingDigest,
        reservationActionSequence: candidate.reservationActionSequence,
        finalizedGovernanceActionCount: candidate.finalizedGovernanceActionCount,
        finalizedBlockHash: candidate.finalizedBlockHash,
        approvedPlanSha256: candidate.approvedPlanSha256,
      } as const;
      const sign = async (value: unknown): Promise<void> => {
        await writeFile(decisionPath, `${canonicalizeJson(value)}\n`);
        execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
          "--output", signaturePath, decisionPath]);
      };
      const input = { decisionPath, signaturePath, finalityEvidencePath,
        keyringDirectory: verifier, reviewerFingerprint: fingerprint!, candidate };
      await expect(draftProposalRecoveryDecision({ candidate, finalityEvidencePath,
        evidenceReference: decision.evidenceReference, reviewerFingerprint: fingerprint!,
        now: Date.parse(decision.draftedAt) })).resolves.toBe(`${canonicalizeJson(decision)}\n`);
      await expect(draftProposalRecoveryDecision({ candidate: { ...candidate,
        reason: "sequence-still-live" }, finalityEvidencePath,
      evidenceReference: decision.evidenceReference, reviewerFingerprint: fingerprint! }))
        .rejects.toThrow(/invalidated/u);
      await expect(draftProposalRecoveryDecision({ candidate, finalityEvidencePath,
        evidenceReference: "demo:unsafe", reviewerFingerprint: fingerprint! }))
        .rejects.toThrow();
      await sign(decision);
      await expect(loadApprovedProposalRecoveryDecision(input)).resolves.toEqual({
        decision, decisionSha256: hash(`${canonicalizeJson(decision)}\n`),
        finalityAuthenticated: false, releaseQualified: false, retryPermitted: false,
      });
      const untrustedParent = join(root, "untrusted-parent");
      const untrustedKeyring = join(untrustedParent, "verifier");
      await mkdir(untrustedParent);
      await chmod(untrustedParent, 0o777);
      await mkdir(untrustedKeyring, { mode: 0o700 });
      await writeFile(join(untrustedKeyring, "pubring.kbx"),
        await readFile(join(verifier, "pubring.kbx")));
      await expect(loadApprovedProposalRecoveryDecision({ ...input, keyringDirectory: untrustedKeyring }))
        .rejects.toThrow(/untrusted ancestor/u);
      await writeFile(finalityEvidencePath, `${evidence}changed`);
      await expect(loadApprovedProposalRecoveryDecision(input))
        .rejects.toThrow(/Finality evidence bytes differ/u);
      await writeFile(finalityEvidencePath, evidence);
      await expect(loadApprovedProposalRecoveryDecision({ ...input,
        reviewerFingerprint: "F".repeat(40) }))
        .rejects.toThrow(/detached reviewer signature/u);
      await expect(loadApprovedProposalRecoveryDecision({ ...input,
        candidate: { ...candidate, authorizationId: "other" } }))
        .rejects.toThrow(/exact candidate/u);
      await expect(loadApprovedProposalRecoveryDecision({ ...input,
        candidate: { ...candidate, finalizedGovernanceActionCount: "3" } }))
        .rejects.toThrow(/invalidated/u);
      await writeFile(decisionPath, `${JSON.stringify(decision)}\nchanged`);
      await expect(loadApprovedProposalRecoveryDecision(input))
        .rejects.toThrow(/detached reviewer signature/u);
      await sign({ ...decision, authorizationId: "other" });
      await expect(loadApprovedProposalRecoveryDecision(input))
        .rejects.toThrow(/exact candidate/u);
      await sign({ ...decision, draftedAt: new Date(Date.now() + 3600_000).toISOString() });
      await expect(loadApprovedProposalRecoveryDecision(input))
        .rejects.toThrow(/exact candidate/u);
      await sign({ ...decision, draftedAt: new Date(Date.now() - 25 * 3600_000).toISOString() });
      await expect(loadApprovedProposalRecoveryDecision(input))
        .rejects.toThrow(/exact candidate/u);
      await sign({ ...decision, draftedAt: decision.draftedAt.replace("Z", "+00:00") });
      await expect(loadApprovedProposalRecoveryDecision(input))
        .rejects.toThrow(/exact candidate/u);
      await sign({ ...decision, evidenceReference: "demo:unsafe" });
      await expect(loadApprovedProposalRecoveryDecision(input)).rejects.toThrow();
      await sign(decision);
      await writeFile(decisionPath, `${JSON.stringify(decision)}\n`);
      execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
        "--output", signaturePath, decisionPath]);
      await expect(loadApprovedProposalRecoveryDecision(input))
        .rejects.toThrow(/canonical signed JSON/u);
      await writeFile(decisionPath, `${JSON.stringify(decision).replace('"role":"issuer"',
        '"role":"verifier","role":"issuer"')}\n`);
      execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
        "--output", signaturePath, decisionPath]);
      await expect(loadApprovedProposalRecoveryDecision(input))
        .rejects.toThrow(/canonical signed JSON/u);
    } finally {
      spawnSync("gpgconf", ["--homedir", signer, "--kill", "gpg-agent"], { stdio: "ignore" });
      await rm(root, { recursive: true, force: true });
    }
  });
});
