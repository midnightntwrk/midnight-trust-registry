import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  signMaintainerProposalEvidenceFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
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
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: MaintainerScenarioFixture,
  action: Pick<PreparedMaintainerAction,
    "registryId" | "policyCommitment" | "actionKind" | "actionPayloadHash" | "actionSequence">,
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed,
    action.registryId,
    harness.simulator.getLedger().deploymentNetworkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"),
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
      signPrepared(harness, second, proposal),
    ], verifierSignature)).toThrow();
    expect(() => harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, second, proposal),
    ], verifierSignature)).toThrow();
    expect(() => harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, candidate, proposal),
    ], verifierSignature)).toThrow();
    expect(() => harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, third, proposal),
    ], signMaintainerProposalEvidenceFromSeed(
      candidate.seed, proposal.registryId,
      proposal.evidenceVerifierKeyIdCommitment, proposal.actionPayloadHash,
    ))).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeProposal);
    harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, third, proposal),
    ], verifierSignature);
    const proposalEvidence = harness.simulator.getMaintainerProposalEvidence(candidate.maintainerIdCommitment);
    expect(proposalEvidence.evidenceCommitment).toEqual(proposal.evidenceHash);
    expect(proposalEvidence.activePolicyVersion).toBe(proposal.policyVersion);

    const approval = harness.prepareMaintainerDecisionAction(candidate, "approve");
    expect(() => harness.prepareMaintainerDecisionAction(candidate, "unsupported" as "approve"))
      .toThrow(/Unsupported maintainer decision action/u);
    const beforeApproval = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeMaintainerDecisionWithSignatures(candidate, "approve", [
      signPrepared(harness, second, approval), signPrepared(harness, candidate, approval),
    ])).toThrow();
    expect(() => harness.executeMaintainerDecisionWithSignatures(candidate, "approve", [
      signPrepared(harness, second, { ...approval, policyCommitment: new Uint8Array(32) }),
      signPrepared(harness, third, approval),
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeApproval);
    harness.executeMaintainerDecisionWithSignatures(candidate, "approve", [
      signPrepared(harness, second, approval), signPrepared(harness, third, approval),
    ]);

    const activation = harness.prepareMaintainerDecisionAction(candidate, "activate");
    const beforeActivation = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeMaintainerDecisionWithSignatures(candidate, "activate", [
      signPrepared(harness, second, approval), signPrepared(harness, third, approval),
    ])).toThrow();
    expect(() => harness.executeMaintainerDecisionWithSignatures(candidate, "activate", [
      signPrepared(harness, second, activation), signPrepared(harness, candidate, activation),
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeActivation);
    harness.executeMaintainerDecisionWithSignatures(candidate, "activate", [
      signPrepared(harness, second, activation), signPrepared(harness, third, activation),
    ]);
    expect(harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment).status)
      .toBe(AuthorizationStatus.active);

    const issuer = createIssuerScenarioFixture("candidate-coauthorizer-issuer");
    expect(() => harness.proposeIssuer(issuer, [candidate])).not.toThrow();

    const priorPolicyVersion = harness.simulator.getLedger().governancePolicyVersion;
    harness.updateMaintainerThresholdPolicy(3n, 1n, 2n, [second]);
    expect(harness.simulator.getLedger().governancePolicyVersion).toBe(priorPolicyVersion + 1n);
    const afterRevision = createIssuerScenarioFixture("three-of-four-issuer");
    const beforeRejectedProposal = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.proposeIssuer(afterRevision, [second])).toThrow(/action threshold/i);
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeRejectedProposal);
    expect(() => harness.proposeIssuer(afterRevision, [second, third])).not.toThrow();

    // Lower the ordinary threshold before removal so the remaining three
    // maintainers retain a quorum that can exclude a future target.
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n, [second, third]);
    harness.suspendMaintainer(candidate);
    expect(harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment).status)
      .toBe(AuthorizationStatus.suspended);
    expect(harness.simulator.getLedger().activeMaintainerCount).toBe(3n);
    const afterSuspension = createIssuerScenarioFixture("suspended-maintainer-issuer");
    const beforeSuspendedVote = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.proposeIssuer(afterSuspension, [candidate, second]))
      .toThrow(/Maintainer must be active/i);
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeSuspendedVote);
    expect(() => harness.proposeIssuer(afterSuspension, [second, third])).not.toThrow();
  }, 15_000);
});
