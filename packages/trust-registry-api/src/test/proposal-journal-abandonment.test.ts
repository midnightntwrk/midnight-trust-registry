import { Buffer } from "node:buffer";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { encodeCompactActionKind } from "@midnight-ntwrk/trust-registry-contract";
import { createMaintainerScenarioFixture, LocalTrustRegistryIntegrationHarness,
  type FinalizedRegistryLedgerView } from "@midnight-ntwrk/trust-registry-integration";
import { describe, expect, it } from "vitest";

import { assessProposalRecoveryCandidate } from "../proposal-recovery-candidate.js";
import { draftProposalRecoveryDecision } from "../proposal-recovery-decision.js";
import { FileProposalSubmissionJournal, proposalJournalBindingDigest,
  ProposalSubmissionAlreadyPendingError, ProposalSubmissionOutcomeUnknownError,
  type ProposalReservationContext } from "../proposal-submission-journal.js";

const hash = (byte: string) => `0x${byte.repeat(64)}`;
const digest = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

describe("audited proposal reservation abandonment", () => {
  it("keeps a signed invalidation tombstone across rotation and restart without replay", async () => {
    const root = await mkdtemp("/tmp/tr-abandonment-");
    const signer = join(root, "signer");
    const keyring = join(root, "keyring");
    try {
      await mkdir(signer, { mode: 0o700 });
      await mkdir(keyring, { mode: 0o700 });
      execFileSync("gpg", ["--homedir", signer, "--batch", "--pinentry-mode", "loopback",
        "--passphrase", "", "--quick-generate-key", "Recovery Reviewer <reviewer@example.test>",
        "ed25519", "sign", "0"], { stdio: "pipe", timeout: 30_000 });
      const fingerprint = execFileSync("gpg", ["--homedir", signer, "--batch", "--with-colons",
        "--list-secret-keys"], { encoding: "utf8" }).split("\n")
        .find((line) => line.startsWith("fpr:"))?.split(":")[9];
      expect(fingerprint).toMatch(/^[A-F0-9]{40}$/u);
      execFileSync("gpg", ["--homedir", keyring, "--batch", "--import"], {
        input: execFileSync("gpg", ["--homedir", signer, "--batch", "--export", fingerprint!]),
        stdio: ["pipe", "pipe", "pipe"],
      });
      const harness = new LocalTrustRegistryIntegrationHarness("abandonment-fixture");
      const contractAddress = `0x${harness.simulator.contractAddress}`;
      const genesisHash = hash("e");
      const journalPath = join(root, "proposal-journal.json");
      const journal = new FileProposalSubmissionJournal(journalPath);
      await journal.bindDeployment(harness.registryId, contractAddress, genesisHash);
      const sequence = harness.simulator.getLedger().governanceActionCount;
      const context: ProposalReservationContext = {
        actionSequence: sequence.toString(),
        actionKind: `0x${Buffer.from(encodeCompactActionKind("tr:issuer:propose")).toString("hex")}`,
        actionPayloadHash: hash("c"),
      };
      const authorizationId = "issuer:unobserved";
      const evidenceCommitment = hash("a");
      await expect(journal.executeOnce("issuer", authorizationId, evidenceCommitment,
        async () => { throw new Error("provider response lost"); }, context))
        .rejects.toBeInstanceOf(ProposalSubmissionOutcomeUnknownError);
      const finalityEvidencePath = join(root, "finality-evidence.json");
      const decisionPath = join(root, "decision.json");
      const signaturePath = join(root, "decision.sig");
      const evidence = Buffer.from('{"testOnly":"injected finalized view"}\n');
      await writeFile(finalityEvidencePath, evidence);
      const view = () => ({
        networkId: "undeployed", finalizedBlockHash: hash("d"), contractAddress,
        ledger: harness.simulator.getLedger(),
      }) as unknown as FinalizedRegistryLedgerView;
      const input = {
        registryId: harness.registryId, contractAddress, expectedGenesisHash: genesisHash,
        planSourceRevision: "f".repeat(40), approvedPlanSha256: "7".repeat(64),
        planReviewerFingerprint: "A".repeat(40), role: "issuer" as const, authorizationId,
        decisionPath, signaturePath, finalityEvidencePath, keyringDirectory: keyring,
        reviewerFingerprint: fingerprint!,
        authenticateFinality: async (bytes: Buffer) => ({
          evidenceSha256: digest(bytes), genesisHash,
          planSourceRevision: "f".repeat(40), approvedPlanSha256: "7".repeat(64),
          view: view(), originalActionRejected: true as const,
        }),
      };
      await expect(journal.abandonInvalidatedReservation(input))
        .rejects.toThrow();
      expect((await journal.read("issuer", authorizationId))?.state).toBe("reserved");

      harness.proposeMaintainer(createMaintainerScenarioFixture("abandonment-sequence-advancer"));
      const bound = await journal.readBoundAttempt(harness.registryId, contractAddress,
        genesisHash, "issuer", authorizationId);
      const candidate = await assessProposalRecoveryCandidate({
        attempt: bound.attempt!, view: view(), registryId: harness.registryId,
        contractAddress, planExpectedGenesisHash: genesisHash,
        planSourceRevision: input.planSourceRevision, approvedPlanSha256: input.approvedPlanSha256,
        journalBindingDigest: bound.bindingDigest,
      });
      expect(candidate.reviewCandidate).toBe(true);
      expect(bound.bindingDigest).toBe(proposalJournalBindingDigest({
        format: "tr-proposal-journal-binding-v1", registryId: harness.registryId,
        networkId: "undeployed", expectedGenesisHash: genesisHash, contractAddress,
      }));
      await writeFile(decisionPath, await draftProposalRecoveryDecision({
        candidate, finalityEvidencePath, evidenceReference: "test:review-bundle",
        reviewerFingerprint: fingerprint!, planReviewerFingerprint: input.planReviewerFingerprint,
      }));
      execFileSync("gpg", ["--homedir", signer, "--batch", "--detach-sign", "--output",
        signaturePath, decisionPath]);
      await expect(journal.abandonInvalidatedReservation({ ...input,
        authenticateFinality: async () => ({ evidenceSha256: "0".repeat(64), genesisHash,
          planSourceRevision: input.planSourceRevision, approvedPlanSha256: input.approvedPlanSha256,
          view: view(), originalActionRejected: true as const }),
      })).rejects.toThrow();
      await expect(journal.abandonInvalidatedReservation({ ...input,
        authenticateFinality: async () => { throw new Error("finality reader unavailable"); },
      })).rejects.toThrow(/finality reader unavailable/u);
      await expect(journal.abandonInvalidatedReservation({ ...input,
        authenticateFinality: async (bytes: Buffer) => ({ evidenceSha256: digest(bytes),
          genesisHash, planSourceRevision: input.planSourceRevision,
          approvedPlanSha256: input.approvedPlanSha256,
          view: view(), originalActionRejected: false as unknown as true }),
      })).rejects.toThrow();
      expect((await journal.read("issuer", authorizationId))?.state).toBe("reserved");
      const abandoned = await journal.abandonInvalidatedReservation(input);
      expect(abandoned).toMatchObject({ state: "abandoned", eventHash: null,
        recovery: { reservedAttemptDigest: candidate.attemptDigest,
          finalityEvidenceSha256: digest(evidence), reviewerFingerprint: fingerprint!,
          evidenceReference: "test:review-bundle", finalizedBlockHash: hash("d"),
          decisionDraftedAt: expect.any(String), recordedAt: expect.any(String) } });
      expect((await journal.inspectCapacity()).pendingEntries).toBe(0);
      expect(await journal.rotateObserved(async () => null)).toEqual({ archived: 1, pending: 0 });
      const reopened = new FileProposalSubmissionJournal(journalPath);
      await reopened.assertDeploymentBinding(harness.registryId, contractAddress, genesisHash);
      expect((await reopened.read("issuer", authorizationId))?.state).toBe("abandoned");
      await expect(reopened.reconcile("issuer", authorizationId,
        async () => ({ eventHash: hash("f"), evidenceCommitment })))
        .rejects.toThrow();
      expect((await reopened.read("issuer", authorizationId))?.state).toBe("abandoned");
      await expect(reopened.executeOnce("issuer", authorizationId, evidenceCommitment,
        async () => { throw new Error("must not execute"); }, context))
        .rejects.toBeInstanceOf(ProposalSubmissionAlreadyPendingError);
      await expect(reopened.executeOnce("issuer", "issuer:new-intent", evidenceCommitment,
        async () => ({ eventHash: hash("f") }), {
          ...context, actionSequence: harness.simulator.getLedger().governanceActionCount.toString(),
        })).resolves.toEqual({ eventHash: hash("f") });
      await expect(reopened.reconcile("issuer", "issuer:new-intent",
        async () => ({ eventHash: hash("f"), evidenceCommitment })))
        .resolves.toMatchObject({ state: "observed" });
      expect(await reopened.rotateObserved(async () => ({ eventHash: hash("f"), evidenceCommitment })))
        .toEqual({ archived: 1, pending: 0 });
      expect(await reopened.compactObservedArchives(async () => ({ eventHash: hash("f"), evidenceCommitment })))
        .toEqual({ before: 2, after: 1, archivedEntries: 2 });
      const compacted = new FileProposalSubmissionJournal(journalPath);
      await compacted.assertDeploymentBinding(harness.registryId, contractAddress, genesisHash);
      expect((await compacted.read("issuer", authorizationId))?.state).toBe("abandoned");
      await expect(compacted.executeOnce("issuer", authorizationId, evidenceCommitment,
        async () => { throw new Error("must not execute after compaction"); }, context))
        .rejects.toBeInstanceOf(ProposalSubmissionAlreadyPendingError);
    } finally {
      spawnSync("gpgconf", ["--homedir", signer, "--kill", "gpg-agent"], { stdio: "ignore" });
      await rm(root, { recursive: true, force: true });
    }
  });
});
