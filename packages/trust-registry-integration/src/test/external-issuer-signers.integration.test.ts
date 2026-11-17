import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  computeUpdateIssuerAuthorizationPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  signIssuerProposalEvidenceFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  createMaintainerFixture,
  type MaintainerCoAuthorizer,
} from "@midnight-ntwrk/trust-registry-contract/testing";

import {
  createIssuerScenarioFixture,
  createIssuerAuthorizationScopeFixture,
  createMaintainerScenarioFixture,
  type MaintainerScenarioFixture,
} from "../fixtures.js";
import {
  LocalTrustRegistryIntegrationHarness,
  type PreparedIssuerDecisionAction,
} from "../local-simulator-harness.js";

const signPreparedAction = (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: MaintainerScenarioFixture,
  prepared: Pick<PreparedIssuerDecisionAction,
    "registryId" | "networkIdCommitment" | "policyCommitment" | "actionKind" | "actionPayloadHash" | "actionSequence">,
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed,
    prepared.registryId,
    prepared.networkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"),
    prepared.policyCommitment,
    prepared.actionKind,
    prepared.actionPayloadHash,
    prepared.actionSequence,
  ),
});

describe("externally signed Compact issuer governance", () => {
  it("requires two distinct active maintainers for proposal, approval, and activation", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-signers");
    const second = createMaintainerScenarioFixture("external-second");
    const third = createMaintainerScenarioFixture("external-third");
    const issuer = createIssuerScenarioFixture("external-issuer");

    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(third);
    await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const evidence = await harness.createApplicationEvidence({
      applicationId: issuer.authorizationId,
      subjectDid: issuer.subjectDid,
      role: "issuer",
      scope: createIssuerAuthorizationScopeFixture(issuer),
      governedResource: { type: "credentialFamily", id: issuer.resourceId },
    });
    const proposal = await harness.prepareIssuerProposalAction(issuer, evidence);
    const verifierSeed = createMaintainerFixture("evidence-verifier", 41).seed;
    const verifierSignature = signIssuerProposalEvidenceFromSeed(
      verifierSeed,
      proposal.registryId,
      proposal.networkIdCommitment,
      proposal.contractAddress,
      proposal.evidenceVerifierKeyIdCommitment,
      proposal.actionPayloadHash,
    );
    const proposalSigners = [signPreparedAction(harness, second, proposal), signPreparedAction(harness, third, proposal)];
    const beforeProposal = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.executeIssuerProposalWithSignatures(
      issuer, evidence, [proposalSigners[0]!], verifierSignature,
    )).rejects.toThrow();
    await expect(harness.executeIssuerProposalWithSignatures(
      issuer, evidence, proposalSigners,
      signIssuerProposalEvidenceFromSeed(
        new Uint8Array(32).fill(99), proposal.registryId,
        proposal.networkIdCommitment, proposal.contractAddress,
        proposal.evidenceVerifierKeyIdCommitment, proposal.actionPayloadHash,
      ),
    )).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeProposal);
    await harness.executeIssuerProposalWithSignatures(issuer, evidence, proposalSigners, verifierSignature);
    await expect(harness.executeIssuerProposalWithSignatures(
      issuer, evidence, proposalSigners, verifierSignature,
    )).rejects.toThrow();

    const approval = await harness.prepareIssuerDecisionAction(issuer, "approve");
    expect(approval.actionPayloadHash).toEqual(computeUpdateIssuerAuthorizationPayloadHash(
      approval.authorizationId,
      approval.previousLifecycleEventHash,
      approval.evidenceHash,
    ));
    const firstSignature = signPreparedAction(harness, second, approval);
    const secondSignature = signPreparedAction(harness, third, approval);
    const beforeApproval = (await harness.simulator.getLedger()).governanceActionCount;

    await expect(harness.executeIssuerDecisionWithSignatures(
      issuer, "approve", [firstSignature],
    )).rejects.toThrow();
    await expect(harness.executeIssuerDecisionWithSignatures(
      issuer, "approve", [firstSignature, firstSignature],
    )).rejects.toThrow();
    await expect(harness.executeIssuerDecisionWithSignatures(
      issuer, "approve", [
        firstSignature,
        signPreparedAction(harness, createMaintainerScenarioFixture("unknown-signer"), approval),
      ],
    )).rejects.toThrow();
    await expect(harness.prepareIssuerDecisionAction(issuer, "unknown" as "approve")).rejects.toThrow(
      /Unsupported issuer decision action/,
    );
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeApproval);

    await harness.executeIssuerDecisionWithSignatures(issuer, "approve", [firstSignature, secondSignature]);
    const activation = await harness.prepareIssuerDecisionAction(issuer, "activate");
    const beforeActivation = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.executeIssuerDecisionWithSignatures(
      issuer, "activate", [firstSignature, secondSignature],
    )).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeActivation);

    await harness.executeIssuerDecisionWithSignatures(issuer, "activate", [
      signPreparedAction(harness, second, activation),
      signPreparedAction(harness, third, activation),
    ]);
    expect((await harness.evaluateCurrentIssuerDecision(issuer)).authorization?.status).toBe("active");
  });

  it("rejects a policy-substituted signature without changing the proposal", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-policy");
    const issuer = createIssuerScenarioFixture("external-policy-issuer");
    const second = createMaintainerScenarioFixture("external-policy-second");
    const third = createMaintainerScenarioFixture("external-policy-third");
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(third);
    await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    await harness.proposeIssuer(issuer, [second]);

    const prepared = await harness.prepareIssuerDecisionAction(issuer, "approve");
    const altered = { ...prepared, policyCommitment: new Uint8Array(32).fill(1) };
    const before = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.executeIssuerDecisionWithSignatures(issuer, "approve", [
      signPreparedAction(harness, second, altered),
      signPreparedAction(harness, third, prepared),
    ])).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before);
  });
});
