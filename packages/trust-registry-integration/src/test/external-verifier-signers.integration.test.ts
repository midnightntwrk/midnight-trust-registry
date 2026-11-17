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

describe("externally signed Compact verifier governance", () => {
  it("requires distinct active maintainers for proposal, approval, and activation", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-verifier");
    const second = createMaintainerScenarioFixture("verifier-second");
    const third = createMaintainerScenarioFixture("verifier-third");
    const outsider = createMaintainerScenarioFixture("verifier-outsider");
    const verifier = createVerifierScenarioFixture("external-verifier-applicant");
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(third);
    await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const evidence = await harness.createApplicationEvidence({
      applicationId: verifier.authorizationId,
      subjectDid: verifier.subjectDid,
      role: "verifier",
      scope: createVerifierAuthorizationScopeFixture(verifier),
    });
    const proposal = await harness.prepareVerifierProposalAction(verifier, evidence);
    const verifierSignature = harness.signVerifierProposalEvidence(proposal);
    const firstProposalSigner = signPrepared(harness, second, proposal);
    const secondProposalSigner = signPrepared(harness, third, proposal);
    const beforeProposal = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.prepareVerifierProposalAction(verifier, evidence, {
      scope: createVerifierAuthorizationScopeFixture(verifier),
      challengeHash: evidence.envelope.challengeHash,
      governedResource: { type: "requestProfile", id: "wrong-request-profile" },
    })).rejects.toThrow(/scope does not match/u);
    await expect(harness.executeVerifierProposalWithSignatures(
      verifier, evidence, [firstProposalSigner], verifierSignature,
    )).rejects.toThrow();
    await expect(harness.executeVerifierProposalWithSignatures(
      verifier, evidence, [firstProposalSigner, firstProposalSigner], verifierSignature,
    )).rejects.toThrow();
    await expect(harness.executeVerifierProposalWithSignatures(
      verifier, evidence, [firstProposalSigner, signPrepared(harness, outsider, proposal)], verifierSignature,
    )).rejects.toThrow();
    await expect(harness.executeVerifierProposalWithSignatures(
      verifier, evidence, [firstProposalSigner, secondProposalSigner],
      signVerifierProposalEvidenceFromSeed(
        outsider.seed, proposal.registryId,
        proposal.networkIdCommitment, proposal.contractAddress,
        proposal.evidenceVerifierKeyIdCommitment, proposal.actionPayloadHash,
      ),
    )).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeProposal);
    await harness.executeVerifierProposalWithSignatures(
      verifier, evidence, [firstProposalSigner, secondProposalSigner], verifierSignature,
    );
    const proposalEvidence = await harness.simulator.getVerifierProposalEvidence(verifier.authorizationIdCommitment);
    expect(proposalEvidence.evidenceCommitment).toEqual(proposal.evidenceHash);
    expect(proposalEvidence.evidenceVerifierKeyIdCommitment).toEqual(proposal.evidenceVerifierKeyIdCommitment);
    expect(proposalEvidence.activePolicyVersion).toBe(proposal.policyVersion);

    const approval = await harness.prepareVerifierDecisionAction(verifier, "approve");
    await expect(harness.prepareVerifierDecisionAction(verifier, "unsupported" as "approve"))
      .rejects.toThrow(/Unsupported verifier decision action/u);
    const beforeApproval = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.executeVerifierDecisionWithSignatures(
      verifier, "approve", [signPrepared(harness, second, approval)],
    )).rejects.toThrow();
    await expect(harness.executeVerifierDecisionWithSignatures(
      verifier, "approve", [
        signPrepared(harness, second, { ...approval, policyCommitment: new Uint8Array(32).fill(1) }),
        signPrepared(harness, third, approval),
      ],
    )).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeApproval);
    await harness.executeVerifierDecisionWithSignatures(verifier, "approve", [
      signPrepared(harness, second, approval), signPrepared(harness, third, approval),
    ]);

    const activation = await harness.prepareVerifierDecisionAction(verifier, "activate");
    const beforeActivation = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.executeVerifierDecisionWithSignatures(verifier, "activate", [
      signPrepared(harness, second, approval), signPrepared(harness, third, approval),
    ])).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeActivation);
    await harness.executeVerifierDecisionWithSignatures(verifier, "activate", [
      signPrepared(harness, second, activation), signPrepared(harness, third, activation),
    ]);

    const bundle = await harness.evaluateCurrentVerifierDecision(verifier, {
      expectedRegistryId: harness.registryId,
    });
    expect(bundle.authorization?.status).toBe("active");
    expect(bundle.authorization?.resourceId).toBe(verifier.scopeResourceId);
    await expect(new TrustRegistrySimulatorClient(harness.simulator)
      .verifyVerifierAuthorizationBundle(bundle, {})).resolves.toBeDefined();
  });
});
