import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  signMaintainerProposalEvidenceFromSeed,
  signPolicyBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import type { MaintainerCoAuthorizer } from "@midnight-ntwrk/trust-registry-contract/testing";
import { AuthorizationStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import {
  createIssuerScenarioFixture,
  createMaintainerAuthorizationScopeFixture,
  createMaintainerScenarioFixture,
  type MaintainerScenarioFixture,
} from "../fixtures.js";
import {
  LocalTrustRegistryIntegrationHarness,
  type PreparedMaintainerAction,
} from "../local-simulator-harness.js";

const signPrepared = (
  maintainer: MaintainerScenarioFixture,
  action: Pick<PreparedMaintainerAction,
    "registryId" | "policyCommitment" | "actionKind" | "actionPayloadHash" | "actionSequence">,
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    action.registryId,
    action.policyCommitment,
    action.actionKind,
    action.actionPayloadHash,
    action.actionSequence,
  ),
});

describe("externally signed Compact maintainer onboarding", () => {
  it("rejects candidate self-voting and requires two existing maintainers at every transition", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-maintainer");
    const second = createMaintainerScenarioFixture("maintainer-second");
    const third = createMaintainerScenarioFixture("maintainer-third");
    const candidate = createMaintainerScenarioFixture("maintainer-candidate");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const evidence = harness.createApplicationEvidence({
      applicationId: candidate.maintainerId,
      subjectDid: candidate.subjectDid,
      role: "maintainer",
      scope: createMaintainerAuthorizationScopeFixture(harness.registryId),
    });
    const proposal = harness.prepareMaintainerProposalAction(candidate, evidence);
    const verifierSignature = harness.signMaintainerProposalEvidence(proposal);
    const beforeProposal = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.prepareMaintainerProposalAction(candidate, evidence, {
      scope: createMaintainerAuthorizationScopeFixture(harness.registryId),
      challengeHash: evidence.envelope.challengeHash,
      governedResource: { type: "registry", id: "another-registry" },
    })).toThrow(/scope does not match/u);
    expect(() => harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(second, proposal),
    ], verifierSignature)).toThrow();
    expect(() => harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(second, proposal), signPrepared(second, proposal),
    ], verifierSignature)).toThrow();
    expect(() => harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(second, proposal), signPrepared(candidate, proposal),
    ], verifierSignature)).toThrow();
    expect(() => harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(second, proposal), signPrepared(third, proposal),
    ], signMaintainerProposalEvidenceFromSeed(
      candidate.seed, proposal.registryId,
      proposal.evidenceVerifierKeyIdCommitment, proposal.actionPayloadHash,
    ))).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeProposal);
    harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(second, proposal), signPrepared(third, proposal),
    ], verifierSignature);
    const proposalEvidence = harness.simulator.getMaintainerProposalEvidence(candidate.maintainerIdCommitment);
    expect(proposalEvidence.evidenceCommitment).toEqual(proposal.evidenceHash);
    expect(proposalEvidence.activePolicyVersion).toBe(proposal.policyVersion);

    const approval = harness.prepareMaintainerDecisionAction(candidate, "approve");
    expect(() => harness.prepareMaintainerDecisionAction(candidate, "unsupported" as "approve"))
      .toThrow(/Unsupported maintainer decision action/u);
    const beforeApproval = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeMaintainerDecisionWithSignatures(candidate, "approve", [
      signPrepared(second, approval), signPrepared(candidate, approval),
    ])).toThrow();
    expect(() => harness.executeMaintainerDecisionWithSignatures(candidate, "approve", [
      signPrepared(second, { ...approval, policyCommitment: new Uint8Array(32) }),
      signPrepared(third, approval),
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeApproval);
    harness.executeMaintainerDecisionWithSignatures(candidate, "approve", [
      signPrepared(second, approval), signPrepared(third, approval),
    ]);

    const activation = harness.prepareMaintainerDecisionAction(candidate, "activate");
    const beforeActivation = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeMaintainerDecisionWithSignatures(candidate, "activate", [
      signPrepared(second, approval), signPrepared(third, approval),
    ])).toThrow();
    expect(() => harness.executeMaintainerDecisionWithSignatures(candidate, "activate", [
      signPrepared(second, activation), signPrepared(candidate, activation),
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeActivation);
    harness.executeMaintainerDecisionWithSignatures(candidate, "activate", [
      signPrepared(second, activation), signPrepared(third, activation),
    ]);
    expect(harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment).status)
      .toBe(AuthorizationStatus.active);

    const issuer = createIssuerScenarioFixture("candidate-coauthorizer-issuer");
    expect(() => harness.proposeIssuer(issuer, [candidate])).not.toThrow();
  });
});
