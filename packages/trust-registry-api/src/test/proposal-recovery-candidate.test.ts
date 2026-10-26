import { describe, expect, it } from "vitest";

import {
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "@midnight-ntwrk/trust-registry-integration";

import { resolveCompactProposalObservation } from "../compact-proposal-observation.js";
import { assessProposalRecoveryCandidate } from "../proposal-recovery-candidate.js";
import type { ProposalSubmissionAttempt } from "../proposal-submission-journal.js";

const hash = (byte: string) => `0x${byte.repeat(64)}`;

const attempt = (authorizationId: string, sequence?: bigint): ProposalSubmissionAttempt => ({
  role: "issuer",
  authorizationId,
  evidenceCommitment: hash("a"),
  state: "reserved",
  eventHash: null,
  ...(sequence === undefined ? {} : { reservationContext: {
    actionSequence: sequence.toString(), actionKind: hash("b"), actionPayloadHash: hash("c"),
  } }),
});

const input = (harness: LocalTrustRegistryIntegrationHarness, recorded: ProposalSubmissionAttempt) => ({
  attempt: recorded,
  registryId: harness.registryId,
  contractAddress: `0x${harness.simulator.contractAddress}`,
  planExpectedGenesisHash: hash("e"),
  planSourceRevision: "f".repeat(40),
  journalBindingDigest: hash("8"),
  view: {
    networkId: "undeployed",
    finalizedBlockHash: hash("d"),
    contractAddress: `0x${harness.simulator.contractAddress}`,
    ledger: harness.simulator.getLedger(),
  },
});

describe("read-only proposal recovery candidates", () => {
  it("requires a later finalized governance sequence and an absent proposal record", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("recovery-candidate-absent");
    const sequence = harness.simulator.getLedger().governanceActionCount;
    const recorded = attempt("issuer:never-submitted", sequence);
    const live = await assessProposalRecoveryCandidate(input(harness, recorded));
    expect(live.reason).toBe("sequence-still-live");
    expect(live.reviewCandidate).toBe(false);

    harness.authorizeMaintainer(createMaintainerScenarioFixture("recovery-candidate-advancer"));
    const candidate = await assessProposalRecoveryCandidate(input(harness, recorded));
    expect(candidate).toMatchObject({
      reason: "sequence-invalidated-record-absent", reviewCandidate: true,
      reservationActionSequence: sequence.toString(),
      reservationActionKind: hash("b"), reservationActionPayloadHash: hash("c"),
      planExpectedGenesisHash: hash("e"), planSourceRevision: "f".repeat(40),
      journalBindingDigest: hash("8"),
      finalizedGovernanceActionCount: harness.simulator.getLedger().governanceActionCount.toString(),
      retryPermitted: false, releaseQualified: false,
    });
    expect(candidate.attemptDigest).toMatch(/^0x[0-9a-f]{64}$/u);
    expect((await assessProposalRecoveryCandidate(input(harness, { ...recorded,
      evidenceCommitment: hash("9"),
    }))).attemptDigest).not.toBe(candidate.attemptDigest);
  });

  it("blocks matching and conflicting finalized proposal records", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("recovery-candidate-present");
    const issuer = createIssuerScenarioFixture("recovery-candidate-issuer");
    const sequence = harness.simulator.getLedger().governanceActionCount;
    harness.proposeIssuer(issuer);
    const observation = await resolveCompactProposalObservation(
      async () => harness.simulator.getLedger(), harness.registryId, "issuer", issuer.authorizationId,
    );
    expect(observation).not.toBeNull();
    const recorded = attempt(issuer.authorizationId, sequence);
    const matching = await assessProposalRecoveryCandidate(input(harness, {
      ...recorded, evidenceCommitment: observation!.evidenceCommitment,
    }));
    expect(matching.reason).toBe("matching-record");
    expect(matching.observedEventHash).toBe(observation!.eventHash);
    expect(matching.reviewCandidate).toBe(false);
    const conflicting = await assessProposalRecoveryCandidate(input(harness, recorded));
    expect(conflicting.reason).toBe("conflicting-record");
    expect(conflicting.reviewCandidate).toBe(false);
    const eventConflict = await assessProposalRecoveryCandidate(input(harness, {
      ...recorded, evidenceCommitment: observation!.evidenceCommitment,
      state: "submitted", eventHash: hash("9"),
    }));
    expect(eventConflict.reason).toBe("conflicting-record");
    harness.approveIssuer(issuer);
    harness.activateIssuer(issuer);
    const afterApproval = await assessProposalRecoveryCandidate(input(harness, {
      ...recorded, evidenceCommitment: observation!.evidenceCommitment,
    }));
    expect(afterApproval.reason).toBe("matching-record");
    expect(afterApproval.reviewCandidate).toBe(false);
  });

  it("keeps legacy and already-submitted entries blocked even after sequence advancement", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("recovery-candidate-legacy");
    const sequence = harness.simulator.getLedger().governanceActionCount;
    harness.authorizeMaintainer(createMaintainerScenarioFixture("recovery-candidate-next"));
    expect((await assessProposalRecoveryCandidate(input(harness, attempt("issuer:legacy")))).reason)
      .toBe("legacy-reservation");
    const reserved = attempt("issuer:submitted", sequence);
    const submitted: ProposalSubmissionAttempt = { ...reserved, state: "submitted", eventHash: hash("e") };
    const report = await assessProposalRecoveryCandidate(input(harness, submitted));
    expect(report.reason).toBe("non-reserved-attempt");
    expect(report.retryPermitted).toBe(false);
  });

  it("fails closed on a substituted deployment or registry", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("recovery-candidate-binding");
    const recorded = attempt("issuer:binding", harness.simulator.getLedger().governanceActionCount);
    const valid = input(harness, recorded);
    await expect(assessProposalRecoveryCandidate({ ...valid, contractAddress: hash("f") }))
      .rejects.toThrow(/pinned finalized local ledger view/u);
    await expect(assessProposalRecoveryCandidate({ ...valid, registryId: "other-registry" }))
      .rejects.toThrow(/different trust registry/u);
    await expect(assessProposalRecoveryCandidate({ ...valid,
      view: { ...valid.view, networkId: "preprod" },
    })).rejects.toThrow(/pinned finalized local ledger view/u);
    await expect(assessProposalRecoveryCandidate({ ...valid, journalBindingDigest: "bad" }))
      .rejects.toThrow(/pinned finalized local ledger view/u);
    await expect(assessProposalRecoveryCandidate({ ...valid,
      planExpectedGenesisHash: hash("0"),
    })).rejects.toThrow(/pinned finalized local ledger view/u);
  });

  it("distinguishes a sequence ahead of finality from a still-live sequence", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("recovery-candidate-ahead");
    const recorded = attempt("issuer:ahead", harness.simulator.getLedger().governanceActionCount + 1n);
    const report = await assessProposalRecoveryCandidate(input(harness, recorded));
    expect(report.reason).toBe("sequence-ahead-of-finality");
    expect(report.reviewCandidate).toBe(false);
  });

  it("rejects malformed reservation context instead of reporting a candidate", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("recovery-candidate-malformed");
    const valid = attempt("issuer:malformed", 0n);
    const invalid = [
      { ...valid.reservationContext!, actionSequence: "01" },
      { ...valid.reservationContext!, actionSequence: (1n << 64n).toString() },
      { ...valid.reservationContext!, actionKind: "bad" },
      { ...valid.reservationContext!, actionPayloadHash: "bad" },
    ];
    for (const reservationContext of invalid) {
      await expect(assessProposalRecoveryCandidate(input(harness, {
        ...valid, reservationContext,
      }))).rejects.toThrow(/invalid/u);
    }
  });
});
