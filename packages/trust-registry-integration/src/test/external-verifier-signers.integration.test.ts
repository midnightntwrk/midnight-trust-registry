import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  signPolicyBoundMaintainerActionFromSeed,
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
  maintainer: MaintainerScenarioFixture,
  action: Pick<PreparedVerifierProposalAction,
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
    const firstProposalSigner = signPrepared(second, proposal);
    const secondProposalSigner = signPrepared(third, proposal);
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
      verifier, evidence, [firstProposalSigner, signPrepared(outsider, proposal)], verifierSignature,
    )).toThrow();
    expect(() => harness.executeVerifierProposalWithSignatures(
      verifier, evidence, [firstProposalSigner, secondProposalSigner],
      signVerifierProposalEvidenceFromSeed(
        outsider.seed, proposal.registryId,
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
      verifier, "approve", [signPrepared(second, approval)],
    )).toThrow();
    expect(() => harness.executeVerifierDecisionWithSignatures(
      verifier, "approve", [
        signPrepared(second, { ...approval, policyCommitment: new Uint8Array(32) }),
        signPrepared(third, approval),
      ],
    )).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeApproval);
    harness.executeVerifierDecisionWithSignatures(verifier, "approve", [
      signPrepared(second, approval), signPrepared(third, approval),
    ]);

    const activation = harness.prepareVerifierDecisionAction(verifier, "activate");
    const beforeActivation = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeVerifierDecisionWithSignatures(verifier, "activate", [
      signPrepared(second, approval), signPrepared(third, approval),
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeActivation);
    harness.executeVerifierDecisionWithSignatures(verifier, "activate", [
      signPrepared(second, activation), signPrepared(third, activation),
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
