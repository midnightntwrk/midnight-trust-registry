import { describe, expect, it, vi } from "vitest";

import {
  computeAuthorizationScopeCommitment,
  type ApplicationChallengeBinding,
  type AuthorizationScope,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  ApplicationChallengeService,
  InMemoryApplicationChallengeStore,
} from "../application-challenges.js";
import { consumeChallengeAndSubmitApplication } from "../application-intake.js";

const START = Date.parse("2026-10-06T00:00:00.000Z");
const ISSUER_SCOPE = {
  version: "tr-scope-v1",
  role: "issuer",
  credentialFamilyId: "credential-family:organization",
  schemaId: "schema:organization",
  schemaVersion: "1.0.0",
  credentialDefinitionId: "credential-definition:organization",
  statusMethod: "midnight-status-registry-v1",
} as const;
const REQUEST_SCOPE = {
  version: "tr-scope-v1",
  requestProfileId: "request-profile:admission",
  purpose: "admission",
  credentialScopeCommitment: `0x${"1".repeat(64)}`,
  allowedAttributes: ["degree"],
  allowedPredicates: ["age-over-18"],
  disclosureLevel: "minimum",
} as const;

const cases = [
  { role: "issuer", scope: ISSUER_SCOPE, resource: { type: "credentialFamily", id: ISSUER_SCOPE.credentialFamilyId } },
  { role: "verifier", scope: { ...REQUEST_SCOPE, role: "verifier" }, resource: { type: "requestProfile", id: REQUEST_SCOPE.requestProfileId } },
  { role: "auditor", scope: { ...REQUEST_SCOPE, role: "auditor" }, resource: { type: "requestProfile", id: REQUEST_SCOPE.requestProfileId } },
  { role: "maintainer", scope: { version: "tr-scope-v1", role: "maintainer", registryId: "registry:kanon:trusted" }, resource: { type: "registry", id: "registry:kanon:trusted" } },
] as const;

function bindingFor(role: typeof cases[number]["role"]): ApplicationChallengeBinding {
  const selected = cases.find((item) => item.role === role)!;
  const scope = selected.scope as AuthorizationScope;
  return {
    registryId: "registry:kanon:trusted",
    applicationId: `application:${role}:one`,
    subjectDid: `did:midnight:${role}:one`,
    evidenceVerifierDid: "did:midnight:evidence-verifier:one",
    role,
    policyId: "policy:kanon:v1",
    policyVersion: "v1",
    scope,
    scopeCommitment: computeAuthorizationScopeCommitment(scope),
    governedResource: selected.resource,
  };
}

function intakeInput(binding: ApplicationChallengeBinding, service: ApplicationChallengeService, nonce: string, challengeHash: string) {
  return {
    challengeService: service,
    binding,
    expectedBinding: binding,
    nonce,
    challengeHash,
    presentation: { rawVp: "private-holder-presentation" },
    verifyPresentation: vi.fn(async (_presentation: unknown, expectedNonce: string, subjectDid: string) => ({
      subjectDid,
      nonce: expectedNonce,
      presentationHash: `0x${"2".repeat(64)}`,
      claimsCommitment: `0x${"3".repeat(64)}`,
      verifiedAt: "2026-10-06T00:00:00.000Z",
      expiresAt: "2026-10-06T01:00:00.000Z",
    })),
    signEvidence: vi.fn(async () => ({
      keyId: "did:midnight:evidence-verifier:one#key-1",
      algorithm: "jubjub-schnorr" as const,
      value: "test-signature",
    })),
    authorizedVerifiers: [{
      did: binding.evidenceVerifierDid,
      keyIds: ["did:midnight:evidence-verifier:one#key-1"],
      algorithms: ["jubjub-schnorr" as const],
    }],
    verifyEvidenceSignature: (_commitment: string, signature: { value: string }) => signature.value === "test-signature",
    evaluatedAt: "2026-10-06T00:00:00.000Z",
    propose: vi.fn(async (proposal: { evidence: { commitment: string; envelope: { challengeHash: string; scopeCommitment: string } } }) => proposal),
  };
}

describe("challenge-backed application intake", () => {
  it.each(cases)("consumes one $role challenge before signing and proposing canonical evidence", async ({ role }) => {
    const binding = bindingFor(role);
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const issued = await service.issue(binding);
    const input = intakeInput(binding, service, issued.nonce, issued.challengeHash);

    const proposal = await consumeChallengeAndSubmitApplication(input);
    expect(input.verifyPresentation).toHaveBeenCalledOnce();
    expect(input.signEvidence).toHaveBeenCalledOnce();
    expect(input.propose).toHaveBeenCalledOnce();
    expect(proposal.evidence.envelope.challengeHash).toBe(issued.challengeHash);
    expect(proposal.evidence.envelope.scopeCommitment).toBe(binding.scopeCommitment);
    expect(JSON.stringify(proposal)).not.toContain("private-holder-presentation");
    expect(JSON.stringify(proposal)).not.toContain(issued.nonce);
    await expect(consumeChallengeAndSubmitApplication(input)).rejects.toThrow(/already consumed/);
  });

  it("does not consume on a failed VP binding, but spends a challenge after signing fails", async () => {
    const binding = bindingFor("issuer");
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const issued = await service.issue(binding);
    const input = intakeInput(binding, service, issued.nonce, issued.challengeHash);
    input.verifyPresentation.mockImplementationOnce(async (_presentation, nonce, subjectDid) => ({
      subjectDid,
      nonce: `${nonce}-wrong`,
      presentationHash: `0x${"2".repeat(64)}`,
      claimsCommitment: `0x${"3".repeat(64)}`,
      verifiedAt: "2026-10-06T00:00:00.000Z",
      expiresAt: "2026-10-06T01:00:00.000Z",
    }));
    await expect(consumeChallengeAndSubmitApplication(input)).rejects.toThrow(/Presentation does not match/);
    expect(input.propose).not.toHaveBeenCalled();
    input.signEvidence.mockRejectedValueOnce(new Error("signer failed"));
    await expect(consumeChallengeAndSubmitApplication(input)).rejects.toThrow(/signer failed/);
    await expect(consumeChallengeAndSubmitApplication(input)).rejects.toThrow(/already consumed/);
  });

  it("rejects a binding that differs from the governed proposal before VP verification", async () => {
    const binding = bindingFor("issuer");
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => START);
    const issued = await service.issue(binding);
    const input = intakeInput(binding, service, issued.nonce, issued.challengeHash);
    const substituted = {
      ...input,
      expectedBinding: {
        ...binding,
        scope: { ...ISSUER_SCOPE, credentialFamilyId: "credential-family:other" },
        scopeCommitment: computeAuthorizationScopeCommitment({ ...ISSUER_SCOPE, credentialFamilyId: "credential-family:other" }),
        governedResource: { type: "credentialFamily" as const, id: "credential-family:other" },
      },
    };
    await expect(consumeChallengeAndSubmitApplication(substituted)).rejects.toThrow(/governed proposal/);
    expect(input.verifyPresentation).not.toHaveBeenCalled();
    expect(input.propose).not.toHaveBeenCalled();
    await expect(consumeChallengeAndSubmitApplication(input)).resolves.toBeDefined();
  });
});
