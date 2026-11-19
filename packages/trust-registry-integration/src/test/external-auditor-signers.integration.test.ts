import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  signAuditorProposalEvidenceFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnightntwrk/trust-registry-contract";
import type { MaintainerCoAuthorizer } from "@midnightntwrk/trust-registry-contract/testing";
import { TrustRegistrySimulatorClient } from "@midnightntwrk/trust-registry-client/simulator";

import {
  createAuditorAuthorizationScopeFixture,
  createAuditorScenarioFixture,
  createMaintainerScenarioFixture,
  type MaintainerScenarioFixture,
} from "../fixtures.js";
import {
  LocalTrustRegistryIntegrationHarness,
  type PreparedAuditorProposalAction,
} from "../local-simulator-harness.js";

const signPrepared = (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: MaintainerScenarioFixture,
  action: Pick<PreparedAuditorProposalAction,
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

describe("externally signed Compact auditor governance", () => {
  it("requires an exact mandate scope and 2-of-3 proposal, approval, and activation", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-auditor");
    const second = createMaintainerScenarioFixture("auditor-second");
    const third = createMaintainerScenarioFixture("auditor-third");
    const outsider = createMaintainerScenarioFixture("auditor-outsider");
    const auditor = createAuditorScenarioFixture("external-auditor-applicant");
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(third);
    await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const scope = createAuditorAuthorizationScopeFixture(auditor);
    const evidence = await harness.createApplicationEvidence({
      applicationId: auditor.authorizationId,
      subjectDid: auditor.subjectDid,
      role: "auditor",
      scope,
    });
    const proposal = await harness.prepareAuditorProposalAction(auditor, evidence);
    const verifierSignature = harness.signAuditorProposalEvidence(proposal);
    const initialCount = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.prepareAuditorProposalAction(auditor, evidence, {
      scope,
      challengeHash: evidence.envelope.challengeHash,
      governedResource: { type: "requestProfile", id: "another-mandate" },
    })).rejects.toThrow(/scope does not match/u);
    await expect(harness.executeAuditorProposalWithSignatures(auditor, evidence, [
      signPrepared(harness, second, proposal),
    ], verifierSignature)).rejects.toThrow();
    await expect(harness.executeAuditorProposalWithSignatures(auditor, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, second, proposal),
    ], verifierSignature)).rejects.toThrow();
    await expect(harness.executeAuditorProposalWithSignatures(auditor, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, outsider, proposal),
    ], verifierSignature)).rejects.toThrow();
    await expect(harness.executeAuditorProposalWithSignatures(auditor, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, third, proposal),
    ], signAuditorProposalEvidenceFromSeed(
      outsider.seed, proposal.registryId,
      proposal.networkIdCommitment, proposal.contractAddress,
      proposal.evidenceVerifierKeyIdCommitment, proposal.actionPayloadHash,
    ))).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(initialCount);
    await harness.executeAuditorProposalWithSignatures(auditor, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, third, proposal),
    ], verifierSignature);
    const proposalEvidence = await harness.simulator.getAuditorProposalEvidence(auditor.authorizationIdCommitment);
    expect(proposalEvidence.evidenceCommitment).toEqual(proposal.evidenceHash);
    expect(proposalEvidence.activePolicyVersion).toBe(proposal.policyVersion);

    const approval = await harness.prepareAuditorDecisionAction(auditor, "approve");
    await expect(harness.prepareAuditorDecisionAction(auditor, "unsupported" as "approve"))
      .rejects.toThrow(/Unsupported auditor decision action/u);
    const beforeApproval = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.executeAuditorDecisionWithSignatures(auditor, "approve", [
      signPrepared(harness, second, { ...approval, policyCommitment: new Uint8Array(32).fill(1) }),
      signPrepared(harness, third, approval),
    ])).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeApproval);
    await harness.executeAuditorDecisionWithSignatures(auditor, "approve", [
      signPrepared(harness, second, approval), signPrepared(harness, third, approval),
    ]);

    const activation = await harness.prepareAuditorDecisionAction(auditor, "activate");
    const beforeActivation = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.executeAuditorDecisionWithSignatures(auditor, "activate", [
      signPrepared(harness, second, approval), signPrepared(harness, third, approval),
    ])).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeActivation);
    await harness.executeAuditorDecisionWithSignatures(auditor, "activate", [
      signPrepared(harness, second, activation), signPrepared(harness, third, activation),
    ]);

    const bundle = await harness.evaluateCurrentAuditorDecision(auditor, {
      expectedRegistryId: harness.registryId,
    });
    expect(bundle.authorization?.status).toBe("active");
    expect(bundle.authorization?.role).toBe("auditor");
    expect(bundle.authorization?.resourceId).toBe(auditor.scopeResourceId);
    await expect(new TrustRegistrySimulatorClient(harness.simulator)
      .verifyAuditorAuthorizationBundle(bundle, {})).resolves.toBeDefined();
  });
});
