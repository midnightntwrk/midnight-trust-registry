import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  signAuditorProposalEvidenceFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import type { MaintainerCoAuthorizer } from "@midnight-ntwrk/trust-registry-contract/testing";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";

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

describe("externally signed Compact auditor governance", () => {
  it("requires an exact mandate scope and 2-of-3 proposal, approval, and activation", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-auditor");
    const second = createMaintainerScenarioFixture("auditor-second");
    const third = createMaintainerScenarioFixture("auditor-third");
    const outsider = createMaintainerScenarioFixture("auditor-outsider");
    const auditor = createAuditorScenarioFixture("external-auditor-applicant");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const scope = createAuditorAuthorizationScopeFixture(auditor);
    const evidence = harness.createApplicationEvidence({
      applicationId: auditor.authorizationId,
      subjectDid: auditor.subjectDid,
      role: "auditor",
      scope,
    });
    const proposal = harness.prepareAuditorProposalAction(auditor, evidence);
    const verifierSignature = harness.signAuditorProposalEvidence(proposal);
    const initialCount = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.prepareAuditorProposalAction(auditor, evidence, {
      scope,
      challengeHash: evidence.envelope.challengeHash,
      governedResource: { type: "requestProfile", id: "another-mandate" },
    })).toThrow(/scope does not match/u);
    expect(() => harness.executeAuditorProposalWithSignatures(auditor, evidence, [
      signPrepared(harness, second, proposal),
    ], verifierSignature)).toThrow();
    expect(() => harness.executeAuditorProposalWithSignatures(auditor, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, second, proposal),
    ], verifierSignature)).toThrow();
    expect(() => harness.executeAuditorProposalWithSignatures(auditor, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, outsider, proposal),
    ], verifierSignature)).toThrow();
    expect(() => harness.executeAuditorProposalWithSignatures(auditor, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, third, proposal),
    ], signAuditorProposalEvidenceFromSeed(
      outsider.seed, proposal.registryId,
      proposal.networkIdCommitment, proposal.contractAddress,
      proposal.evidenceVerifierKeyIdCommitment, proposal.actionPayloadHash,
    ))).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(initialCount);
    harness.executeAuditorProposalWithSignatures(auditor, evidence, [
      signPrepared(harness, second, proposal), signPrepared(harness, third, proposal),
    ], verifierSignature);
    const proposalEvidence = harness.simulator.getAuditorProposalEvidence(auditor.authorizationIdCommitment);
    expect(proposalEvidence.evidenceCommitment).toEqual(proposal.evidenceHash);
    expect(proposalEvidence.activePolicyVersion).toBe(proposal.policyVersion);

    const approval = harness.prepareAuditorDecisionAction(auditor, "approve");
    expect(() => harness.prepareAuditorDecisionAction(auditor, "unsupported" as "approve"))
      .toThrow(/Unsupported auditor decision action/u);
    const beforeApproval = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeAuditorDecisionWithSignatures(auditor, "approve", [
      signPrepared(harness, second, { ...approval, policyCommitment: new Uint8Array(32) }),
      signPrepared(harness, third, approval),
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeApproval);
    harness.executeAuditorDecisionWithSignatures(auditor, "approve", [
      signPrepared(harness, second, approval), signPrepared(harness, third, approval),
    ]);

    const activation = harness.prepareAuditorDecisionAction(auditor, "activate");
    const beforeActivation = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeAuditorDecisionWithSignatures(auditor, "activate", [
      signPrepared(harness, second, approval), signPrepared(harness, third, approval),
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeActivation);
    harness.executeAuditorDecisionWithSignatures(auditor, "activate", [
      signPrepared(harness, second, activation), signPrepared(harness, third, activation),
    ]);

    const bundle = harness.evaluateCurrentAuditorDecision(auditor, {
      expectedRegistryId: harness.registryId,
    });
    expect(bundle.authorization?.status).toBe("active");
    expect(bundle.authorization?.role).toBe("auditor");
    expect(bundle.authorization?.resourceId).toBe(auditor.scopeResourceId);
    expect(() => new TrustRegistrySimulatorClient(harness.simulator)
      .verifyAuditorAuthorizationBundle(bundle, {})).not.toThrow();
  });
});
