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
    "registryId" | "policyCommitment" | "actionKind" | "actionPayloadHash" | "actionSequence">,
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed,
    prepared.registryId,
    harness.simulator.getLedger().deploymentNetworkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"),
    prepared.policyCommitment,
    prepared.actionKind,
    prepared.actionPayloadHash,
    prepared.actionSequence,
  ),
});

describe("externally signed Compact issuer governance", () => {
  it("requires two distinct active maintainers for proposal, approval, and activation", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-signers");
    const second = createMaintainerScenarioFixture("external-second");
    const third = createMaintainerScenarioFixture("external-third");
    const issuer = createIssuerScenarioFixture("external-issuer");

    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const evidence = harness.createApplicationEvidence({
      applicationId: issuer.authorizationId,
      subjectDid: issuer.subjectDid,
      role: "issuer",
      scope: createIssuerAuthorizationScopeFixture(issuer),
      governedResource: { type: "credentialFamily", id: issuer.resourceId },
    });
    const proposal = harness.prepareIssuerProposalAction(issuer, evidence);
    const verifierSeed = createMaintainerFixture("evidence-verifier", 41).seed;
    const verifierSignature = signIssuerProposalEvidenceFromSeed(
      verifierSeed,
      proposal.registryId,
      proposal.evidenceVerifierKeyIdCommitment,
      proposal.actionPayloadHash,
    );
    const proposalSigners = [signPreparedAction(harness, second, proposal), signPreparedAction(harness, third, proposal)];
    const beforeProposal = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeIssuerProposalWithSignatures(
      issuer, evidence, [proposalSigners[0]!], verifierSignature,
    )).toThrow();
    expect(() => harness.executeIssuerProposalWithSignatures(
      issuer, evidence, proposalSigners,
      signIssuerProposalEvidenceFromSeed(
        new Uint8Array(32).fill(99), proposal.registryId,
        proposal.evidenceVerifierKeyIdCommitment, proposal.actionPayloadHash,
      ),
    )).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeProposal);
    harness.executeIssuerProposalWithSignatures(issuer, evidence, proposalSigners, verifierSignature);
    expect(() => harness.executeIssuerProposalWithSignatures(
      issuer, evidence, proposalSigners, verifierSignature,
    )).toThrow();

    const approval = harness.prepareIssuerDecisionAction(issuer, "approve");
    expect(approval.actionPayloadHash).toEqual(computeUpdateIssuerAuthorizationPayloadHash(
      approval.authorizationId,
      approval.previousLifecycleEventHash,
      approval.evidenceHash,
    ));
    const firstSignature = signPreparedAction(harness, second, approval);
    const secondSignature = signPreparedAction(harness, third, approval);
    const beforeApproval = harness.simulator.getLedger().governanceActionCount;

    expect(() => harness.executeIssuerDecisionWithSignatures(
      issuer, "approve", [firstSignature],
    )).toThrow();
    expect(() => harness.executeIssuerDecisionWithSignatures(
      issuer, "approve", [firstSignature, firstSignature],
    )).toThrow();
    expect(() => harness.executeIssuerDecisionWithSignatures(
      issuer, "approve", [
        firstSignature,
        signPreparedAction(harness, createMaintainerScenarioFixture("unknown-signer"), approval),
      ],
    )).toThrow();
    expect(() => harness.prepareIssuerDecisionAction(issuer, "unknown" as "approve")).toThrow(
      /Unsupported issuer decision action/,
    );
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeApproval);

    harness.executeIssuerDecisionWithSignatures(issuer, "approve", [firstSignature, secondSignature]);
    const activation = harness.prepareIssuerDecisionAction(issuer, "activate");
    const beforeActivation = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeIssuerDecisionWithSignatures(
      issuer, "activate", [firstSignature, secondSignature],
    )).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeActivation);

    harness.executeIssuerDecisionWithSignatures(issuer, "activate", [
      signPreparedAction(harness, second, activation),
      signPreparedAction(harness, third, activation),
    ]);
    expect(harness.evaluateCurrentIssuerDecision(issuer).authorization?.status).toBe("active");
  });

  it("rejects a policy-substituted signature without changing the proposal", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-policy");
    const issuer = createIssuerScenarioFixture("external-policy-issuer");
    const second = createMaintainerScenarioFixture("external-policy-second");
    const third = createMaintainerScenarioFixture("external-policy-third");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    harness.proposeIssuer(issuer, [second]);

    const prepared = harness.prepareIssuerDecisionAction(issuer, "approve");
    const altered = { ...prepared, policyCommitment: new Uint8Array(32) };
    const before = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeIssuerDecisionWithSignatures(issuer, "approve", [
      signPreparedAction(harness, second, altered),
      signPreparedAction(harness, third, prepared),
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before);
  });
});
