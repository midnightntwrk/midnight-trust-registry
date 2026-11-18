import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  signMaintainerProposalEvidenceFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnightntwrk/trust-registry-contract";
import type { MaintainerCoAuthorizer } from "@midnightntwrk/trust-registry-contract/testing";
import { AuthorizationStatus } from "@midnightntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

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
    "registryId" | "networkIdCommitment" | "policyCommitment" | "actionKind" | "actionPayloadHash" | "actionSequence">,
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed,
    action.registryId,
    action.networkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"),
    action.policyCommitment,
    action.actionKind,
    action.actionPayloadHash,
    action.actionSequence,
  ),
});

describe("externally signed Compact maintainer onboarding", () => {
  it("rejects candidate self-voting and requires two existing maintainers at every transition", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-maintainer");
    const second = createMaintainerScenarioFixture("maintainer-second");
    const third = createMaintainerScenarioFixture("maintainer-third");
    const candidate = createMaintainerScenarioFixture("maintainer-candidate");
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(third);
    await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const evidence = await harness.createApplicationEvidence({
      applicationId: candidate.maintainerId,
      subjectDid: candidate.subjectDid,
      role: "maintainer",
      scope: createMaintainerAuthorizationScopeFixture(harness.registryId),
    });
    const proposal = await harness.prepareMaintainerProposalAction(candidate, evidence);
    const verifierSignature = harness.signMaintainerProposalEvidence(proposal);
    const beforeProposal = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.prepareMaintainerProposalAction(candidate, evidence, {
      scope: createMaintainerAuthorizationScopeFixture(harness.registryId),
      challengeHash: evidence.envelope.challengeHash,
      governedResource: { type: "registry", id: "another-registry" },
    })).rejects.toThrow(/scope does not match/u);
    await expect(harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(harness, second, proposal),
    ], verifierSignature)).rejects.toThrow();
    await expect(harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, second, proposal),
    ], verifierSignature)).rejects.toThrow();
    await expect(harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, candidate, proposal),
    ], verifierSignature)).rejects.toThrow();
    await expect(harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, third, proposal),
    ], signMaintainerProposalEvidenceFromSeed(
      candidate.seed, proposal.registryId,
      proposal.networkIdCommitment, proposal.contractAddress,
      proposal.evidenceVerifierKeyIdCommitment, proposal.actionPayloadHash,
    ))).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeProposal);
    await harness.executeMaintainerProposalWithSignatures(candidate, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, third, proposal),
    ], verifierSignature);
    const proposalEvidence = await harness.simulator.getMaintainerProposalEvidence(candidate.maintainerIdCommitment);
    expect(proposalEvidence.evidenceCommitment).toEqual(proposal.evidenceHash);
    expect(proposalEvidence.activePolicyVersion).toBe(proposal.policyVersion);

    const approval = await harness.prepareMaintainerDecisionAction(candidate, "approve");
    await expect(harness.prepareMaintainerDecisionAction(candidate, "unsupported" as "approve"))
      .rejects.toThrow(/Unsupported maintainer decision action/u);
    const beforeApproval = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.executeMaintainerDecisionWithSignatures(candidate, "approve", [
      signPrepared(harness, second, approval), signPrepared(harness, candidate, approval),
    ])).rejects.toThrow();
    await expect(harness.executeMaintainerDecisionWithSignatures(candidate, "approve", [
      signPrepared(harness, second, { ...approval, policyCommitment: new Uint8Array(32).fill(1) }),
      signPrepared(harness, third, approval),
    ])).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeApproval);
    await harness.executeMaintainerDecisionWithSignatures(candidate, "approve", [
      signPrepared(harness, second, approval), signPrepared(harness, third, approval),
    ]);

    const activation = await harness.prepareMaintainerDecisionAction(candidate, "activate");
    const beforeActivation = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.executeMaintainerDecisionWithSignatures(candidate, "activate", [
      signPrepared(harness, second, approval), signPrepared(harness, third, approval),
    ])).rejects.toThrow();
    await expect(harness.executeMaintainerDecisionWithSignatures(candidate, "activate", [
      signPrepared(harness, second, activation), signPrepared(harness, candidate, activation),
    ])).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeActivation);
    await harness.executeMaintainerDecisionWithSignatures(candidate, "activate", [
      signPrepared(harness, second, activation), signPrepared(harness, third, activation),
    ]);
    expect((await harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment)).status)
      .toBe(AuthorizationStatus.active);

    const issuer = createIssuerScenarioFixture("candidate-coauthorizer-issuer");
    await expect(harness.proposeIssuer(issuer, [candidate])).resolves.toBeDefined();

    const priorPolicyVersion = (await harness.simulator.getLedger()).governancePolicyVersion;
    await harness.updateMaintainerThresholdPolicy(3n, 1n, 2n, [second]);
    expect((await harness.simulator.getLedger()).governancePolicyVersion).toBe(priorPolicyVersion + 1n);
    const afterRevision = createIssuerScenarioFixture("three-of-four-issuer");
    const beforeRejectedProposal = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.proposeIssuer(afterRevision, [second])).rejects.toThrow(/action threshold/i);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeRejectedProposal);
    await expect(harness.proposeIssuer(afterRevision, [second, third])).resolves.toBeDefined();

    // Lower the ordinary threshold before removal so the remaining three
    // maintainers retain a quorum that can exclude a future target.
    await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n, [second, third]);
    await harness.suspendMaintainer(candidate);
    expect((await harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment)).status)
      .toBe(AuthorizationStatus.suspended);
    expect((await harness.simulator.getLedger()).activeMaintainerCount).toBe(3n);
    const afterSuspension = createIssuerScenarioFixture("suspended-maintainer-issuer");
    const beforeSuspendedVote = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.proposeIssuer(afterSuspension, [candidate, second]))
      .rejects.toThrow(/Maintainer must be active/i);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeSuspendedVote);
    await expect(harness.proposeIssuer(afterSuspension, [second, third])).resolves.toBeDefined();
  }, 15_000);
});
