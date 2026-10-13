import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  signIssuerProposalEvidenceFromSeed,
  signPolicyBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { createMaintainerFixture, type MaintainerCoAuthorizer } from "@midnight-ntwrk/trust-registry-contract/testing";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";

import {
  ApplicationChallengeBindingSchema,
  computeAuthorizationScopeCommitment,
  createScopedIdentifier,
  sha256Hex,
  type ApplicationEvidenceSubmission,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  createApplicationVpIntakePorts,
  createApplicationVpScenarioFixture,
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  type MaintainerScenarioFixture,
  type PreparedIssuerDecisionAction,
  VP_FIXTURE_TIME_MS,
} from "@midnight-ntwrk/trust-registry-integration";

import { ApplicationChallengeService, InMemoryApplicationChallengeStore } from "../application-challenges.js";
import { consumeChallengeAndSubmitApplication } from "../application-intake.js";

const signAction = (
  maintainer: MaintainerScenarioFixture,
  action: Pick<PreparedIssuerDecisionAction,
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

describe("published VP proof to governed issuer decision", () => {
  it("carries one redacted VC/VP intake through a 2-of-3 issuer decision and authenticated lookup", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const second = createMaintainerScenarioFixture("vp-quorum-second");
    const third = createMaintainerScenarioFixture("vp-quorum-third");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    harness.advanceEvidenceTimeBy(60_000);
    const issuer = createIssuerScenarioFixture("vp");
    const scope = createIssuerAuthorizationScopeFixture(issuer);
    const governedResource = { type: "credentialFamily", id: issuer.resourceId } as const;
    const binding = ApplicationChallengeBindingSchema.parse({
      registryId: harness.registryId,
      applicationId: createScopedIdentifier("application", "issuer", issuer.authorizationId),
      subjectDid: issuer.subjectDid,
      evidenceVerifierDid: harness.evidenceVerifier.did,
      role: "issuer",
      policyId: harness.policyId,
      policyVersion: harness.policyRecord.version,
      scope,
      scopeCommitment: computeAuthorizationScopeCommitment(scope),
      governedResource,
    });
    const challengeService = new ApplicationChallengeService(
      new InMemoryApplicationChallengeStore(), () => VP_FIXTURE_TIME_MS,
    );
    const issued = await challengeService.issue(binding);
    const proof = await createApplicationVpScenarioFixture(issued.nonce, {
      subjectDid: issuer.subjectDid,
      evidenceVerifierDid: harness.evidenceVerifier.did,
      evidenceVerifierMethodId: harness.evidenceVerifier.keyIds[0]!.split("#")[1]!,
    });
    const ports = await createApplicationVpIntakePorts({
      resolver: proof.input.resolver,
      family: proof.input.family,
      signer: proof.signer,
    });
    let submitted: ApplicationEvidenceSubmission | undefined;
    const input = {
      challengeService,
      binding,
      expectedBinding: binding,
      nonce: issued.nonce,
      challengeHash: issued.challengeHash,
      presentation: proof.input.submission,
      ...ports,
      authorizedVerifiers: [harness.evidenceVerifier],
      evaluatedAt: new Date(VP_FIXTURE_TIME_MS).toISOString(),
      propose: async ({ evidence }: { evidence: ApplicationEvidenceSubmission }) => {
        submitted = evidence;
        expect(evidence.signature.keyId).toBe(harness.evidenceVerifier.keyIds[0]);
        expect(harness.verifyApplicationEvidenceSignature(
          evidence.commitment, evidence.signature, harness.evidenceVerifier,
        )).toBe(true);
        const expectedEvidence = {
          scope,
          challengeHash: issued.challengeHash,
          governedResource,
        };
        const action = harness.prepareIssuerProposalAction(issuer, evidence, expectedEvidence);
        const verifierSignature = signIssuerProposalEvidenceFromSeed(
          createMaintainerFixture("evidence-verifier", 41).seed,
          action.registryId,
          action.evidenceVerifierKeyIdCommitment,
          action.actionPayloadHash,
        );
        return harness.executeIssuerProposalWithSignatures(
          issuer, evidence,
          [signAction(second, action), signAction(third, action)],
          verifierSignature,
          expectedEvidence,
        );
      },
    };

    const wrongChallenge = await createApplicationVpIntakePorts({
      resolver: proof.input.resolver,
      family: {
        ...proof.input.family,
        prepare: async () => ({
          ...proof.material,
          presentationProof: {
            ...proof.material.presentationProof,
            challengeHash: new Uint8Array(32).fill(7),
          },
        }),
      },
      signer: proof.signer,
    });
    await expect(consumeChallengeAndSubmitApplication({
      ...input, ...wrongChallenge,
    })).rejects.toMatchObject({ category: "invalid_presentation" });
    const wrongScope = await createApplicationVpIntakePorts({
      resolver: proof.input.resolver,
      family: {
        ...proof.input.family,
        assertRoleClaims: async () => ({
          claimsCommitment: sha256Hex("wrong-scope-claims"),
          scopeCommitment: sha256Hex("different-scope"),
        }),
      },
      signer: proof.signer,
    });
    await expect(consumeChallengeAndSubmitApplication({
      ...input, ...wrongScope,
    })).rejects.toMatchObject({ category: "ineligible" });
    expect(await challengeService.isLive({ binding, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBe(true);
    expect(harness.simulator.getLedger().issuerAuthorizationCount).toBe(0n);

    const eventHash = await consumeChallengeAndSubmitApplication(input);
    const proposal = harness.simulator.getIssuerProposalEvidence(issuer.authorizationIdCommitment);
    expect(Buffer.from(proposal.proposalGovernanceEventHash)).toEqual(Buffer.from(eventHash));
    expect(Buffer.from(proposal.evidenceCommitment)).toEqual(
      Buffer.from(submitted!.commitment.slice(2), "hex"),
    );
    expect(submitted!.envelope.evidenceVerifierDid).toBe(harness.evidenceVerifier.did);
    expect(JSON.stringify(submitted)).not.toContain("private-presentation-payload");
    expect(harness.simulator.getLedger().issuerAuthorizationCount).toBe(1n);
    await expect(consumeChallengeAndSubmitApplication(input)).rejects.toThrow(/already consumed/u);
    expect(harness.simulator.getLedger().issuerAuthorizationCount).toBe(1n);

    const approval = harness.prepareIssuerDecisionAction(issuer, "approve");
    harness.executeIssuerDecisionWithSignatures(issuer, "approve", [
      signAction(second, approval), signAction(third, approval),
    ]);
    const activation = harness.prepareIssuerDecisionAction(issuer, "activate");
    harness.executeIssuerDecisionWithSignatures(issuer, "activate", [
      signAction(second, activation), signAction(third, activation),
    ]);
    const decision = harness.evaluateCurrentIssuerDecision(issuer, {
      expectedRegistryId: harness.registryId,
    });
    expect(decision.authorization?.status).toBe("active");
    expect(decision.authorization?.subjectDid).toBe(issuer.subjectDid);
    expect(decision.epoch.stateRoot).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(() => new TrustRegistrySimulatorClient(harness.simulator)
      .verifyIssuerAuthorizationBundle(decision, {})).not.toThrow();
  });
});
