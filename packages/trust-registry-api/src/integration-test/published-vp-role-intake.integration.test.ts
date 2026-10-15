import { Buffer } from "node:buffer";

import { describe, expect, it, vi } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  signPolicyBoundMaintainerActionFromSeed,
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
  createApplicationVpIntakePorts,
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
} from "@midnight-ntwrk/trust-registry-integration";

import { ApplicationChallengeService, InMemoryApplicationChallengeStore } from "../application-challenges.js";
import { consumeChallengeAndSubmitApplication } from "../application-intake.js";

const roles = ["verifier", "auditor", "maintainer"] as const;

const signPrepared = (
  maintainer: MaintainerScenarioFixture,
  prepared: {
    registryId: Uint8Array;
    policyCommitment: Uint8Array;
    actionKind: Uint8Array;
    actionPayloadHash: Uint8Array;
    actionSequence: bigint;
  },
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    prepared.registryId,
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
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    harness.advanceEvidenceTimeBy(60_000);
    const applicant = scenario(role, harness);
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
    const proof = await createApplicationVpScenarioFixture(issued.nonce, {
      subjectDid: applicant.subjectDid,
      evidenceVerifierDid: harness.evidenceVerifier.did,
      evidenceVerifierMethodId: harness.evidenceVerifier.keyIds[0]!.split("#")[1]!,
      scope: applicant.scope,
    });
    const preparedClaims = await proof.input.family.prepare(proof.input.submission);
    expect((await proof.input.family.assertRoleClaims(preparedClaims)).scopeCommitment).toBe(binding.scopeCommitment);
    const ports = await createApplicationVpIntakePorts({
      resolver: proof.input.resolver,
      family: proof.input.family,
      signer: proof.signer,
    });
    const beforeProposal = harness.simulator.getLedger().governanceActionCount;
    const propose = vi.fn(async ({ evidence }: { evidence: ApplicationEvidenceSubmission }) => {
      expect(evidence.signature.keyId).toBe(harness.evidenceVerifier.keyIds[0]);
      expect(harness.verifyApplicationEvidenceSignature(
        evidence.commitment, evidence.signature, harness.evidenceVerifier,
      )).toBe(true);
      const expectedEvidence = {
        scope: applicant.scope,
        challengeHash: issued.challengeHash,
        governedResource: applicant.governedResource,
      };
      if (applicant.role === "verifier") {
        const prepared = harness.prepareVerifierProposalAction(applicant.fixture, evidence, expectedEvidence);
        return {
          evidence,
          eventHash: harness.executeVerifierProposalWithSignatures(
            applicant.fixture, evidence,
            [signPrepared(second, prepared), signPrepared(third, prepared)],
            harness.signVerifierProposalEvidence(prepared), expectedEvidence,
          ),
        };
      }
      if (applicant.role === "auditor") {
        const prepared = harness.prepareAuditorProposalAction(applicant.fixture, evidence, expectedEvidence);
        return {
          evidence,
          eventHash: harness.executeAuditorProposalWithSignatures(
            applicant.fixture, evidence,
            [signPrepared(second, prepared), signPrepared(third, prepared)],
            harness.signAuditorProposalEvidence(prepared), expectedEvidence,
          ),
        };
      }
      const prepared = harness.prepareMaintainerProposalAction(applicant.fixture, evidence, expectedEvidence);
      return {
        evidence,
        eventHash: harness.executeMaintainerProposalWithSignatures(
          applicant.fixture, evidence,
          [signPrepared(second, prepared), signPrepared(third, prepared)],
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

    const wrongRoleClaims = await createApplicationVpIntakePorts({
      resolver: proof.input.resolver,
      family: {
        ...proof.input.family,
        assertRoleClaims: async () => ({
          claimsCommitment: sha256Hex("claims:wrong-role"),
          scopeCommitment: sha256Hex("scope:wrong-role"),
        }),
      },
      signer: proof.signer,
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
      const rejectedPorts = await createApplicationVpIntakePorts({
        resolver: proof.input.resolver,
        family,
        signer: proof.signer,
      });
      await expect(consumeChallengeAndSubmitApplication({
        ...input, ...rejectedPorts,
      })).rejects.toMatchObject({ category: expect.stringMatching(/expired|ineligible/u) });
      expect(await challengeService.isLive({ binding, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBe(true);
      expect(propose).not.toHaveBeenCalled();
    }

    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeProposal);
    const result = await consumeChallengeAndSubmitApplication(input);
    const { evidence, eventHash } = result;
    expect(eventHash).toHaveLength(32);
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeProposal + 1n);
    expect(evidence.envelope.role).toBe(role);
    expect(evidence.envelope.subjectDid).toBe(applicant.subjectDid);
    expect(evidence.envelope.scopeCommitment).toBe(binding.scopeCommitment);
    expect(JSON.stringify(evidence)).not.toContain("private-presentation-payload");
    expect(propose).toHaveBeenCalledOnce();
    await expect(consumeChallengeAndSubmitApplication(input)).rejects.toThrow(/already consumed/u);
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeProposal + 1n);

    const client = new TrustRegistrySimulatorClient(harness.simulator);
    if (applicant.role === "verifier") {
      const record = harness.simulator.getVerifierAuthorization(applicant.fixture.authorizationIdCommitment);
      expect(Buffer.from(record.evidenceHash).toString("hex")).toBe(evidence.commitment.slice(2));
      for (const action of ["approve", "activate"] as const) {
        const prepared = harness.prepareVerifierDecisionAction(applicant.fixture, action);
        harness.executeVerifierDecisionWithSignatures(applicant.fixture, action, [
          signPrepared(second, prepared), signPrepared(third, prepared),
        ]);
      }
      const bundle = harness.evaluateCurrentVerifierDecision(applicant.fixture, {
        expectedRegistryId: harness.registryId,
      });
      expect(bundle.authorization?.status).toBe("active");
      expect(bundle.authorization?.resourceId).toBe(applicant.fixture.scopeResourceId);
      expect(() => client.verifyVerifierAuthorizationBundle(bundle, {})).not.toThrow();
    } else if (applicant.role === "auditor") {
      const record = harness.simulator.getAuditorAuthorization(applicant.fixture.authorizationIdCommitment);
      expect(Buffer.from(record.evidenceHash).toString("hex")).toBe(evidence.commitment.slice(2));
      for (const action of ["approve", "activate"] as const) {
        const prepared = harness.prepareAuditorDecisionAction(applicant.fixture, action);
        harness.executeAuditorDecisionWithSignatures(applicant.fixture, action, [
          signPrepared(second, prepared), signPrepared(third, prepared),
        ]);
      }
      const bundle = harness.evaluateCurrentAuditorDecision(applicant.fixture, {
        expectedRegistryId: harness.registryId,
      });
      expect(bundle.authorization?.status).toBe("active");
      expect(bundle.authorization?.resourceId).toBe(applicant.fixture.scopeResourceId);
      expect(() => client.verifyAuditorAuthorizationBundle(bundle, {})).not.toThrow();
    } else {
      const record = harness.simulator.getMaintainerMembership(applicant.fixture.maintainerIdCommitment);
      expect(Buffer.from(record.evidenceHash).toString("hex")).toBe(evidence.commitment.slice(2));
      for (const action of ["approve", "activate"] as const) {
        const prepared = harness.prepareMaintainerDecisionAction(applicant.fixture, action);
        harness.executeMaintainerDecisionWithSignatures(applicant.fixture, action, [
          signPrepared(second, prepared), signPrepared(third, prepared),
        ]);
      }
      expect(harness.simulator.getMaintainerMembership(applicant.fixture.maintainerIdCommitment).status)
        .toBe(AuthorizationStatus.active);
    }
  });
});
