import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
  signVerifierProposalEvidenceFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";
import type { MaintainerCoAuthorizer } from "@midnight-ntwrk/trust-registry-contract/testing";

import {
  createMaintainerScenarioFixture,
  createVerifierAuthorizationScopeFixture,
  createVerifierScenarioFixture,
  type MaintainerScenarioFixture,
} from "../fixtures.js";
import {
  LocalTrustRegistryIntegrationHarness,
  type PreparedVerifierProposalAction,
} from "../local-simulator-harness.js";

const signPrepared = (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: MaintainerScenarioFixture,
  action: Pick<PreparedVerifierProposalAction,
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

describe("externally signed Compact verifier governance", () => {
  it("requires distinct active maintainers for proposal, approval, and activation", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-verifier");
    const second = createMaintainerScenarioFixture("verifier-second");
    const third = createMaintainerScenarioFixture("verifier-third");
    const outsider = createMaintainerScenarioFixture("verifier-outsider");
    const verifier = createVerifierScenarioFixture("external-verifier-applicant");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const evidence = harness.createApplicationEvidence({
      applicationId: verifier.authorizationId,
      subjectDid: verifier.subjectDid,
      role: "verifier",
      scope: createVerifierAuthorizationScopeFixture(verifier),
    });
    const proposal = harness.prepareVerifierProposalAction(verifier, evidence);
    const verifierSignature = harness.signVerifierProposalEvidence(proposal);
    const firstProposalSigner = signPrepared(harness, second, proposal);
    const secondProposalSigner = signPrepared(harness, third, proposal);
    const beforeProposal = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.prepareVerifierProposalAction(verifier, evidence, {
      scope: createVerifierAuthorizationScopeFixture(verifier),
      challengeHash: evidence.envelope.challengeHash,
      governedResource: { type: "requestProfile", id: "wrong-request-profile" },
    })).toThrow(/scope does not match/u);
    expect(() => harness.executeVerifierProposalWithSignatures(
      verifier, evidence, [firstProposalSigner], verifierSignature,
    )).toThrow();
    expect(() => harness.executeVerifierProposalWithSignatures(
      verifier, evidence, [firstProposalSigner, firstProposalSigner], verifierSignature,
    )).toThrow();
    expect(() => harness.executeVerifierProposalWithSignatures(
      verifier, evidence, [firstProposalSigner, signPrepared(harness, outsider, proposal)], verifierSignature,
    )).toThrow();
    expect(() => harness.executeVerifierProposalWithSignatures(
      verifier, evidence, [firstProposalSigner, secondProposalSigner],
      signVerifierProposalEvidenceFromSeed(
        outsider.seed, proposal.registryId,
        proposal.networkIdCommitment, proposal.contractAddress,
        proposal.evidenceVerifierKeyIdCommitment, proposal.actionPayloadHash,
      ),
    )).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeProposal);
    harness.executeVerifierProposalWithSignatures(
      verifier, evidence, [firstProposalSigner, secondProposalSigner], verifierSignature,
    );
    const proposalEvidence = harness.simulator.getVerifierProposalEvidence(verifier.authorizationIdCommitment);
    expect(proposalEvidence.evidenceCommitment).toEqual(proposal.evidenceHash);
    expect(proposalEvidence.evidenceVerifierKeyIdCommitment).toEqual(proposal.evidenceVerifierKeyIdCommitment);
    expect(proposalEvidence.activePolicyVersion).toBe(proposal.policyVersion);

    const approval = harness.prepareVerifierDecisionAction(verifier, "approve");
    expect(() => harness.prepareVerifierDecisionAction(verifier, "unsupported" as "approve"))
      .toThrow(/Unsupported verifier decision action/u);
    const beforeApproval = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeVerifierDecisionWithSignatures(
      verifier, "approve", [signPrepared(harness, second, approval)],
    )).toThrow();
    expect(() => harness.executeVerifierDecisionWithSignatures(
      verifier, "approve", [
        signPrepared(harness, second, { ...approval, policyCommitment: new Uint8Array(32) }),
        signPrepared(harness, third, approval),
      ],
    )).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeApproval);
    harness.executeVerifierDecisionWithSignatures(verifier, "approve", [
      signPrepared(harness, second, approval), signPrepared(harness, third, approval),
    ]);

    const activation = harness.prepareVerifierDecisionAction(verifier, "activate");
    const beforeActivation = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeVerifierDecisionWithSignatures(verifier, "activate", [
      signPrepared(harness, second, approval), signPrepared(harness, third, approval),
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeActivation);
    harness.executeVerifierDecisionWithSignatures(verifier, "activate", [
      signPrepared(harness, second, activation), signPrepared(harness, third, activation),
    ]);

    const bundle = harness.evaluateCurrentVerifierDecision(verifier, {
      expectedRegistryId: harness.registryId,
    });
    expect(bundle.authorization?.status).toBe("active");
    expect(bundle.authorization?.resourceId).toBe(verifier.scopeResourceId);
    expect(() => new TrustRegistrySimulatorClient(harness.simulator)
      .verifyVerifierAuthorizationBundle(bundle, {})).not.toThrow();
  });
});
