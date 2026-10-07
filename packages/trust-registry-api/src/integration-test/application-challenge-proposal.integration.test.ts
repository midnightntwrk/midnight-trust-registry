import { describe, expect, it, vi } from "vitest";

import {
  ApplicationChallengeBindingSchema,
  computeApplicationEvidenceCommitment,
  computeAuthorizationScopeCommitment,
  createScopedIdentifier,
  sha256Hex,
  type ApplicationChallengeBinding,
  type ApplicationEvidenceSubmission,
  type AuthorizationScope,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  createAuditorAuthorizationScopeFixture,
  createAuditorScenarioFixture,
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createMaintainerAuthorizationScopeFixture,
  createMaintainerScenarioFixture,
  createVerifierAuthorizationScopeFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  type ApplicationEvidenceExpectation,
} from "@midnight-ntwrk/trust-registry-integration";

import { ApplicationChallengeService, InMemoryApplicationChallengeStore } from "../application-challenges.js";
import { consumeChallengeAndSubmitApplication } from "../application-intake.js";

const START = Date.parse("2026-05-20T00:01:00.000Z");
const VERIFIED_AT = new Date(START).toISOString();
const EXPIRES_AT = new Date(START + 60 * 60 * 1000).toISOString();
const ROLE_NAMES = ["issuer", "verifier", "auditor", "maintainer"] as const;
type Role = typeof ROLE_NAMES[number];

function scenario(role: Role, harness: LocalTrustRegistryIntegrationHarness) {
  let applicationId: string;
  let subjectDid: string;
  let scope: AuthorizationScope;
  let governedResource: { type: string; id: string };
  let propose: (evidence: ApplicationEvidenceSubmission, expected: ApplicationEvidenceExpectation) => Uint8Array;

  switch (role) {
    case "issuer": {
      const fixture = createIssuerScenarioFixture("challenge-proposal");
      applicationId = fixture.authorizationId;
      subjectDid = fixture.subjectDid;
      scope = createIssuerAuthorizationScopeFixture(fixture);
      governedResource = { type: "credentialFamily", id: fixture.resourceId };
      propose = (evidence, expected) => harness.proposeIssuerWithApplicationEvidence(fixture, evidence, [], expected);
      break;
    }
    case "verifier": {
      const fixture = createVerifierScenarioFixture("challenge-proposal");
      applicationId = fixture.authorizationId;
      subjectDid = fixture.subjectDid;
      scope = createVerifierAuthorizationScopeFixture(fixture);
      governedResource = { type: "requestProfile", id: fixture.requestProfileId };
      propose = (evidence, expected) => harness.proposeVerifierWithApplicationEvidence(fixture, evidence, expected);
      break;
    }
    case "auditor": {
      const fixture = createAuditorScenarioFixture("challenge-proposal");
      applicationId = fixture.authorizationId;
      subjectDid = fixture.subjectDid;
      scope = createAuditorAuthorizationScopeFixture(fixture);
      governedResource = { type: "requestProfile", id: fixture.requestProfileId };
      propose = (evidence, expected) => harness.proposeAuditorWithApplicationEvidence(fixture, evidence, expected);
      break;
    }
    case "maintainer": {
      const fixture = createMaintainerScenarioFixture("challenge-proposal");
      applicationId = fixture.maintainerId;
      subjectDid = fixture.subjectDid;
      scope = createMaintainerAuthorizationScopeFixture(harness.registryId);
      governedResource = { type: "registry", id: harness.registryId };
      propose = (evidence, expected) => harness.proposeMaintainerWithApplicationEvidence(fixture, evidence, expected);
      break;
    }
  }

  const binding = ApplicationChallengeBindingSchema.parse({
    registryId: harness.registryId,
    applicationId: createScopedIdentifier("application", role, applicationId),
    subjectDid,
    evidenceVerifierDid: harness.evidenceVerifier.did,
    role,
    policyId: harness.policyId,
    policyVersion: harness.policyRecord.version,
    scope,
    scopeCommitment: computeAuthorizationScopeCommitment(scope),
    governedResource,
  });
  return { binding, applicationId, propose };
}

describe("canonical challenge-to-Compact proposal bridge", () => {
  it.each(ROLE_NAMES)("uses one consumed %s challenge for signed canonical proposal evidence", async (role) => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const { binding, applicationId, propose } = scenario(role, harness);
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const issued = await service.issue(binding);
    const expected = {
      scope: binding.scope,
      challengeHash: issued.challengeHash,
    };
    expect(binding.scopeCommitment).not.toBe(sha256Hex(binding.governedResource.id));
    const verifyPresentation = vi.fn(async (_presentation: unknown, nonce: string, subjectDid: string) => ({
      nonce, subjectDid,
      presentationHash: `0x${"2".repeat(64)}`,
      claimsCommitment: `0x${"3".repeat(64)}`,
      verifiedAt: VERIFIED_AT,
      expiresAt: EXPIRES_AT,
    }));
    const proposeWithEvidence = vi.fn(async ({ evidence }: { evidence: ApplicationEvidenceSubmission }) => {
      expect(evidence.envelope.scopeCommitment).toBe(binding.scopeCommitment);
      expect(evidence.envelope.challengeHash).toBe(issued.challengeHash);
      return propose(evidence, expected);
    });
    const input = {
      challengeService: service,
      binding,
      expectedBinding: binding,
      nonce: issued.nonce,
      challengeHash: issued.challengeHash,
      presentation: { privateVp: "holder-secret-not-for-ledger" },
      verifyPresentation,
      signEvidence: async (commitment: string) => harness.signApplicationEvidenceCommitment(commitment),
      authorizedVerifiers: [harness.evidenceVerifier],
      verifyEvidenceSignature: (commitment: string, signature: Parameters<typeof harness.verifyApplicationEvidenceSignature>[1], verifier: Parameters<typeof harness.verifyApplicationEvidenceSignature>[2]) =>
        harness.verifyApplicationEvidenceSignature(commitment, signature, verifier),
      evaluatedAt: VERIFIED_AT,
      propose: proposeWithEvidence,
    };

    await expect(consumeChallengeAndSubmitApplication({
      ...input,
      expectedBinding: { ...binding, scope: { ...binding.scope, role: role === "issuer" ? "verifier" : "issuer" } } as ApplicationChallengeBinding,
    })).rejects.toThrow();
    expect(verifyPresentation).not.toHaveBeenCalled();

    await expect(consumeChallengeAndSubmitApplication({
      ...input,
      expectedBinding: { ...binding, applicationId: binding.applicationId.toUpperCase() },
    })).rejects.toThrow();
    expect(verifyPresentation).not.toHaveBeenCalled();

    await expect(consumeChallengeAndSubmitApplication({
      ...input,
      expectedBinding: { ...binding, governedResource: { ...binding.governedResource, id: "other-resource" } },
    })).rejects.toThrow();
    expect(verifyPresentation).not.toHaveBeenCalled();

    const substitutedScope = binding.scope.role === "issuer"
      ? { ...binding.scope, schemaId: "schema:other-organization" }
      : binding.scope.role === "maintainer"
        ? { ...binding.scope, registryId: "registry:other:trusted" }
        : { ...binding.scope, allowedAttributes: ["name"] };
    await expect(consumeChallengeAndSubmitApplication({
      ...input,
      expectedBinding: {
        ...binding,
        ...(role === "maintainer" ? {
          registryId: "registry:other:trusted",
          governedResource: { type: "registry" as const, id: "registry:other:trusted" },
        } : {}),
        scope: substitutedScope,
        scopeCommitment: computeAuthorizationScopeCommitment(substitutedScope),
      } as ApplicationChallengeBinding,
    })).rejects.toThrow(/governed proposal/);
    expect(verifyPresentation).not.toHaveBeenCalled();

    verifyPresentation.mockImplementationOnce(async (_presentation, nonce, subjectDid) => ({
      nonce: `${nonce}-wrong`, subjectDid,
      presentationHash: `0x${"2".repeat(64)}`,
      claimsCommitment: `0x${"3".repeat(64)}`,
      verifiedAt: VERIFIED_AT,
      expiresAt: EXPIRES_AT,
    }));
    await expect(consumeChallengeAndSubmitApplication(input)).rejects.toThrow(/Presentation does not match/);

    verifyPresentation.mockImplementationOnce(async (_presentation, nonce) => ({
      nonce, subjectDid: "did:midnight:wrong-subject",
      presentationHash: `0x${"2".repeat(64)}`,
      claimsCommitment: `0x${"3".repeat(64)}`,
      verifiedAt: VERIFIED_AT,
      expiresAt: EXPIRES_AT,
    }));
    await expect(consumeChallengeAndSubmitApplication(input)).rejects.toThrow(/Presentation does not match/);

    const commitment = await consumeChallengeAndSubmitApplication(input);
    expect(commitment).toBeInstanceOf(Uint8Array);
    expect(proposeWithEvidence).toHaveBeenCalledOnce();
    const signedEvidence = proposeWithEvidence.mock.calls[0]![0].evidence;
    const wrongResourceScope = binding.scope.role === "issuer"
      ? { ...binding.scope, credentialFamilyId: "credential-family:other" }
      : binding.scope.role === "maintainer"
        ? { ...binding.scope, registryId: "registry:other:trusted" }
        : { ...binding.scope, requestProfileId: "request-profile:other" };
    expect(() => propose(signedEvidence, { ...expected, scope: wrongResourceScope })).toThrow(/proposal scope does not match/);
    for (const [field, value, message] of [
      ["scopeCommitment", `0x${"a".repeat(64)}`, /scopeCommitment/],
      ["challengeHash", `0x${"b".repeat(64)}`, /challengeHash/],
    ] as const) {
      const envelope = { ...signedEvidence.envelope, [field]: value };
      const evidenceCommitment = computeApplicationEvidenceCommitment(envelope);
      expect(() => harness.assertApplicationEvidence({
        evidence: {
          envelope,
          commitment: evidenceCommitment,
          signature: harness.signApplicationEvidenceCommitment(evidenceCommitment),
        },
        applicationId,
        subjectDid: binding.subjectDid,
        role,
        ...expected,
      })).toThrow(message);
    }
    await expect(consumeChallengeAndSubmitApplication(input)).rejects.toThrow(/already consumed/);
    const serializedLedger = JSON.stringify(harness.simulator.getLedger(), (_key, value: unknown) =>
      typeof value === "bigint" ? value.toString() : value);
    const serializedProposal = JSON.stringify(proposeWithEvidence.mock.calls);
    expect(serializedLedger).not.toContain("holder-secret-not-for-ledger");
    expect(serializedLedger).not.toContain(issued.nonce);
    expect(serializedProposal).not.toContain("holder-secret-not-for-ledger");
    expect(serializedProposal).not.toContain(issued.nonce);

    let expiryClock = START;
    const expiredService = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => expiryClock);
    const expired = await expiredService.issue(binding);
    expiryClock += 6 * 60_000;
    await expect(consumeChallengeAndSubmitApplication({
      ...input,
      challengeService: expiredService,
      nonce: expired.nonce,
      challengeHash: expired.challengeHash,
    })).rejects.toThrow(/invalid or already consumed/);
    expect(proposeWithEvidence).toHaveBeenCalledOnce();
  });
});
