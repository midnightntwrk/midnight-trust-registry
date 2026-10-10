import { describe, expect, it, vi } from "vitest";

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
  createAuditorAuthorizationScopeFixture,
  createAuditorScenarioFixture,
  createMaintainerAuthorizationScopeFixture,
  createMaintainerScenarioFixture,
  createVerifierAuthorizationScopeFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  VP_FIXTURE_TIME_MS,
} from "@midnight-ntwrk/trust-registry-integration";

import { ApplicationChallengeService, InMemoryApplicationChallengeStore } from "../application-challenges.js";
import { consumeChallengeAndSubmitApplication } from "../application-intake.js";

const roles = ["verifier", "auditor", "maintainer"] as const;

function scenario(role: typeof roles[number], harness: LocalTrustRegistryIntegrationHarness) {
  if (role === "verifier") {
    const fixture = createVerifierScenarioFixture("vp");
    return {
      applicationId: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      scope: createVerifierAuthorizationScopeFixture(fixture),
      governedResource: { type: "requestProfile", id: fixture.scopeResourceId } as const,
    };
  }
  if (role === "auditor") {
    const fixture = createAuditorScenarioFixture("vp");
    return {
      applicationId: fixture.authorizationId,
      subjectDid: fixture.subjectDid,
      scope: createAuditorAuthorizationScopeFixture(fixture),
      governedResource: { type: "requestProfile", id: fixture.scopeResourceId } as const,
    };
  }
  const fixture = createMaintainerScenarioFixture("vp");
  return {
    applicationId: fixture.maintainerId,
    subjectDid: fixture.subjectDid,
    scope: createMaintainerAuthorizationScopeFixture(harness.registryId),
    governedResource: { type: "registry", id: harness.registryId } as const,
  };
}

describe("published VP proof for non-issuer application roles", () => {
  it.each(roles)("checks %s claims and consumes a challenge once", async (role) => {
    const harness = new LocalTrustRegistryIntegrationHarness();
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
      scopeCommitment: binding.scopeCommitment,
    });
    const ports = await createApplicationVpIntakePorts({
      resolver: proof.input.resolver,
      family: proof.input.family,
      signer: proof.signer,
    });
    const propose = vi.fn(async ({ evidence }: { evidence: ApplicationEvidenceSubmission }) => evidence);
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

    const evidence = await consumeChallengeAndSubmitApplication(input);
    expect(evidence.envelope.role).toBe(role);
    expect(evidence.envelope.subjectDid).toBe(applicant.subjectDid);
    expect(evidence.envelope.scopeCommitment).toBe(binding.scopeCommitment);
    expect(JSON.stringify(evidence)).not.toContain("private-presentation-payload");
    expect(propose).toHaveBeenCalledOnce();
    await expect(consumeChallengeAndSubmitApplication(input)).rejects.toThrow(/already consumed/u);
  });
});
