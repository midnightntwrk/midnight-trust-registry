import { Buffer } from "node:buffer";

import { describe, expect, it, vi } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { AuthorizationStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import type { MaintainerCoAuthorizer } from "@midnight-ntwrk/trust-registry-contract/testing";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";
import {
  ApplicationChallengeBindingSchema,
  computeAuthorizationScopeCommitment,
  createScopedIdentifier,
  sha256Hex,
  type ApplicationEvidenceSubmission,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  createQualifiedApplicationVpIntakePorts,
  createApplicationVpScenarioFixture,
  ApplicationVpVerificationError,
  createAuditorAuthorizationScopeFixture,
  createAuditorScenarioFixture,
  createMaintainerAuthorizationScopeFixture,
  createMaintainerScenarioFixture,
  createVerifierAuthorizationScopeFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  type MaintainerScenarioFixture,
  VP_FIXTURE_TIME_MS,
  VP_FIXTURE_TRUST_CONTEXT,
} from "@midnight-ntwrk/trust-registry-integration";

import { ApplicationChallengeService, InMemoryApplicationChallengeStore } from "../application-challenges.js";
import { consumeChallengeAndSubmitApplication } from "../application-intake.js";

const roles = ["verifier", "auditor", "maintainer"] as const;

const signPrepared = async (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: MaintainerScenarioFixture,
  prepared: {
    registryId: Uint8Array;
    policyCommitment: Uint8Array;
    actionKind: Uint8Array;
    actionPayloadHash: Uint8Array;
    actionSequence: bigint;
  },
): Promise<MaintainerCoAuthorizer> => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed,
    prepared.registryId,
    (await harness.simulator.getLedger()).deploymentNetworkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"),
    prepared.policyCommitment,
    prepared.actionKind,
    prepared.actionPayloadHash,
    prepared.actionSequence,
  ),
});

function scenario(role: typeof roles[number], harness: LocalTrustRegistryIntegrationHarness) {
  if (role === "verifier") {
    const fixture = createVerifierScenarioFixture("vp");
    return {
      role: "verifier" as const,
      fixture,
      applicationId: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      scope: createVerifierAuthorizationScopeFixture(fixture),
      governedResource: { type: "requestProfile", id: fixture.scopeResourceId } as const,
    };
  }
  if (role === "auditor") {
    const fixture = createAuditorScenarioFixture("vp");
    return {
      role: "auditor" as const,
      fixture,
      applicationId: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      scope: createAuditorAuthorizationScopeFixture(fixture),
      governedResource: { type: "requestProfile", id: fixture.scopeResourceId } as const,
    };
  }
  const fixture = createMaintainerScenarioFixture("vp");
  return {
    role: "maintainer" as const,
    fixture,
    applicationId: fixture.maintainerId,
    subjectDid: fixture.subjectDid,
    scope: createMaintainerAuthorizationScopeFixture(harness.registryId),
    governedResource: { type: "registry", id: harness.registryId } as const,
  };
}

describe("published VP proof for non-issuer application roles", () => {
  it.each(roles)("checks %s claims and consumes a challenge once", async (role) => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const second = createMaintainerScenarioFixture(`vp-${role}-quorum-second`);
    const third = createMaintainerScenarioFixture(`vp-${role}-quorum-third`);
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(third);
    await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    harness.advanceEvidenceTimeBy(60_000);
    const applicant = scenario(role, harness);
    const trustContext = { ...VP_FIXTURE_TRUST_CONTEXT, registryId: harness.registryId };
    const binding = ApplicationChallengeBindingSchema.parse({
      registryId: harness.registryId,
      applicationId: createScopedIdentifier("application", role, applicant.applicationId),
      subjectDid: applicant.subjectDid,
      evidenceVerifierDid: harness.evidenceVerifier.did,
      role,
      policyId: harness.policyId,
      policyVersion: harness.policyRecord.version,
      scope: applicant.scope,
      scopeCommitment: computeAuthorizationScopeCommitment(applicant.scope),
      governedResource: applicant.governedResource,
    });
    const challengeService = new ApplicationChallengeService(
      new InMemoryApplicationChallengeStore(), () => VP_FIXTURE_TIME_MS,
    );
    const issued = await challengeService.issue(binding);
    const proofOptions = {
      subjectDid: applicant.subjectDid,
      evidenceVerifierDid: harness.evidenceVerifier.did,
      evidenceVerifierMethodId: harness.evidenceVerifier.keyIds[0]!.split("#")[1]!,
      scope: applicant.scope,
      trustContext,
      policyId: binding.policyId,
      policyVersion: binding.policyVersion,
    };
    const proof = await createApplicationVpScenarioFixture(issued.nonce, proofOptions);
    const preparedClaims = await proof.input.family.prepare(proof.input.submission);
    expect((await proof.input.family.assertRoleClaims(preparedClaims)).scopeCommitment).toBe(binding.scopeCommitment);
    const ports = await createQualifiedApplicationVpIntakePorts({
      resolver: proof.input.resolver,
      family: proof.input.family,
      signer: proof.signer,
      trustContext,
    });
    const beforeProposal = (await harness.simulator.getLedger()).governanceActionCount;
    const propose = vi.fn(async ({ evidence }: { evidence: ApplicationEvidenceSubmission }) => {
      expect(evidence.signature.keyId).toBe(harness.evidenceVerifier.keyIds[0]);
      expect(await harness.verifyApplicationEvidenceSignature(
        evidence.commitment, evidence.signature, harness.evidenceVerifier,
      )).toBe(true);
      const expectedEvidence = {
        scope: applicant.scope,
        challengeHash: issued.challengeHash,
        governedResource: applicant.governedResource,
      };
      if (applicant.role === "verifier") {
        const prepared = await harness.prepareVerifierProposalAction(applicant.fixture, evidence, expectedEvidence);
        return {
          evidence,
          eventHash: await harness.executeVerifierProposalWithSignatures(
            applicant.fixture, evidence,
            [await signPrepared(harness, second, prepared), await signPrepared(harness, third, prepared)],
            harness.signVerifierProposalEvidence(prepared), expectedEvidence,
          ),
        };
      }
      if (applicant.role === "auditor") {
        const prepared = await harness.prepareAuditorProposalAction(applicant.fixture, evidence, expectedEvidence);
        return {
          evidence,
          eventHash: await harness.executeAuditorProposalWithSignatures(
            applicant.fixture, evidence,
            [await signPrepared(harness, second, prepared), await signPrepared(harness, third, prepared)],
            harness.signAuditorProposalEvidence(prepared), expectedEvidence,
          ),
        };
      }
      const prepared = await harness.prepareMaintainerProposalAction(applicant.fixture, evidence, expectedEvidence);
      return {
        evidence,
        eventHash: await harness.executeMaintainerProposalWithSignatures(
          applicant.fixture, evidence,
          [await signPrepared(harness, second, prepared), await signPrepared(harness, third, prepared)],
          harness.signMaintainerProposalEvidence(prepared), expectedEvidence,
        ),
      };
    });
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
      propose,
    };

    for (const presentationContext of [
      { registryId: "registry:other" },
      { policyVersion: "v9" },
    ]) {
      const mismatched = await createApplicationVpScenarioFixture(issued.nonce, {
        ...proofOptions,
        presentationContext,
      });
      const mismatchedPorts = await createQualifiedApplicationVpIntakePorts({
        resolver: mismatched.input.resolver,
        family: mismatched.input.family,
        signer: mismatched.signer,
        trustContext,
      });
      await expect(consumeChallengeAndSubmitApplication({
        ...input,
        presentation: mismatched.input.submission,
        ...mismatchedPorts,
      })).rejects.toMatchObject({ category: "invalid_presentation" });
      expect(await challengeService.isLive({ binding, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBe(true);
      expect(propose).not.toHaveBeenCalled();
    }

    const wrongRoleClaims = await createQualifiedApplicationVpIntakePorts({
      resolver: proof.input.resolver,
      family: {
        ...proof.input.family,
        assertRoleClaims: async () => ({
          claimsCommitment: sha256Hex("claims:wrong-role"),
          scopeCommitment: sha256Hex("scope:wrong-role"),
        }),
      },
      signer: proof.signer,
      trustContext,
    });
    await expect(consumeChallengeAndSubmitApplication({
      ...input, ...wrongRoleClaims,
    })).rejects.toMatchObject({ category: "ineligible" });
    expect(await challengeService.isLive({ binding, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBe(true);
    expect(propose).not.toHaveBeenCalled();

    for (const family of [
      {
        ...proof.input.family,
        assertStatusActive: async () => ({
          validUntilMs: VP_FIXTURE_TIME_MS,
          statusDecisionCommitment: sha256Hex("expired-status-decision"),
        }),
      },
      {
        ...proof.input.family,
        assertStatusActive: async (): Promise<{ validUntilMs: number; statusDecisionCommitment: string }> => {
          throw new ApplicationVpVerificationError("ineligible");
        },
      },
      {
        ...proof.input.family,
        prepare: async () => ({ ...proof.material, credentialExpiresAtMs: VP_FIXTURE_TIME_MS }),
      },
    ]) {
      const rejectedPorts = await createQualifiedApplicationVpIntakePorts({
        resolver: proof.input.resolver,
        family,
        signer: proof.signer,
        trustContext,
      });
      await expect(consumeChallengeAndSubmitApplication({
        ...input, ...rejectedPorts,
      })).rejects.toMatchObject({ category: expect.stringMatching(/expired|ineligible/u) });
      expect(await challengeService.isLive({ binding, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBe(true);
      expect(propose).not.toHaveBeenCalled();
    }

    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeProposal);
    const result = await consumeChallengeAndSubmitApplication(input);
    const { evidence, eventHash } = result;
    expect(eventHash).toHaveLength(32);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeProposal + 1n);
    expect(evidence.envelope.role).toBe(role);
    expect(evidence.envelope.subjectDid).toBe(applicant.subjectDid);
    expect(evidence.envelope.scopeCommitment).toBe(binding.scopeCommitment);
    expect(JSON.stringify(evidence)).not.toContain("private-presentation-payload");
    expect(propose).toHaveBeenCalledOnce();
    await expect(consumeChallengeAndSubmitApplication(input)).rejects.toThrow(/already consumed/u);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(beforeProposal + 1n);

    const client = new TrustRegistrySimulatorClient(harness.simulator);
    if (applicant.role === "verifier") {
      const record = await harness.simulator.getVerifierAuthorization(applicant.fixture.authorizationIdCommitment);
      expect(Buffer.from(record.evidenceHash).toString("hex")).toBe(evidence.commitment.slice(2));
      for (const action of ["approve", "activate"] as const) {
        const prepared = await harness.prepareVerifierDecisionAction(applicant.fixture, action);
        await harness.executeVerifierDecisionWithSignatures(applicant.fixture, action, [
          await signPrepared(harness, second, prepared), await signPrepared(harness, third, prepared),
        ]);
      }
      const bundle = await harness.evaluateCurrentVerifierDecision(applicant.fixture, {
        expectedRegistryId: harness.registryId,
      });
      expect(bundle.authorization?.status).toBe("active");
      expect(bundle.authorization?.resourceId).toBe(applicant.fixture.scopeResourceId);
      await expect(client.verifyVerifierAuthorizationBundle(bundle, {})).resolves.toBeDefined();
    } else if (applicant.role === "auditor") {
      const record = await harness.simulator.getAuditorAuthorization(applicant.fixture.authorizationIdCommitment);
      expect(Buffer.from(record.evidenceHash).toString("hex")).toBe(evidence.commitment.slice(2));
      for (const action of ["approve", "activate"] as const) {
        const prepared = await harness.prepareAuditorDecisionAction(applicant.fixture, action);
        await harness.executeAuditorDecisionWithSignatures(applicant.fixture, action, [
          await signPrepared(harness, second, prepared), await signPrepared(harness, third, prepared),
        ]);
      }
      const bundle = await harness.evaluateCurrentAuditorDecision(applicant.fixture, {
        expectedRegistryId: harness.registryId,
      });
      expect(bundle.authorization?.status).toBe("active");
      expect(bundle.authorization?.resourceId).toBe(applicant.fixture.scopeResourceId);
      await expect(client.verifyAuditorAuthorizationBundle(bundle, {})).resolves.toBeDefined();
    } else {
      const record = await harness.simulator.getMaintainerMembership(applicant.fixture.maintainerIdCommitment);
      expect(Buffer.from(record.evidenceHash).toString("hex")).toBe(evidence.commitment.slice(2));
      for (const action of ["approve", "activate"] as const) {
        const prepared = await harness.prepareMaintainerDecisionAction(applicant.fixture, action);
        await harness.executeMaintainerDecisionWithSignatures(applicant.fixture, action, [
          await signPrepared(harness, second, prepared), await signPrepared(harness, third, prepared),
        ]);
      }
      expect((await harness.simulator.getMaintainerMembership(applicant.fixture.maintainerIdCommitment)).status)
        .toBe(AuthorizationStatus.active);
    }
  });
});
