import { describe, expect, it, vi } from "vitest";

import {
  ApplicationChallengeBindingSchema,
  computeAuthorizationScopeCommitment,
  issuerGovernedResourceId,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  createApplicationVpIntakePorts,
  createApplicationVpScenarioFixture,
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createMidnightDid,
  VP_FIXTURE_TIME_MS,
} from "@midnight-ntwrk/trust-registry-integration";

import { ApplicationChallengeService, InMemoryApplicationChallengeStore } from "../application-challenges.js";
import { consumeChallengeAndSubmitApplication } from "../application-intake.js";

describe("published VP proof through one-use application intake", () => {
  it("consumes the issued challenge once and submits only signed, redacted evidence", async () => {
    const scope = createIssuerAuthorizationScopeFixture(createIssuerScenarioFixture("vp"));
    const verifierDid = createMidnightDid("vp-evidence-verifier");
    const binding = ApplicationChallengeBindingSchema.parse({
      registryId: "registry:vp:test",
      applicationId: "application:vp:one-use",
      subjectDid: createMidnightDid("vp-holder"),
      evidenceVerifierDid: verifierDid,
      role: "issuer",
      policyId: "policy:vp:v1",
      policyVersion: "v1",
      scope,
      scopeCommitment: computeAuthorizationScopeCommitment(scope),
      governedResource: { type: "credentialFamily", id: issuerGovernedResourceId(scope, "credentialFamily") },
    });
    const service = new ApplicationChallengeService(new InMemoryApplicationChallengeStore(), () => VP_FIXTURE_TIME_MS);
    const issued = await service.issue(binding);
    const fixture = await createApplicationVpScenarioFixture(issued.nonce);
    const signer = fixture.signer;
    const ports = await createApplicationVpIntakePorts({
      resolver: fixture.input.resolver,
      family: fixture.input.family,
      signer,
    });
    const propose = vi.fn(async ({ evidence }: { evidence: { envelope: { presentationHash: string }; signature: { value: string } } }) => evidence);
    const input = {
      challengeService: service,
      binding,
      expectedBinding: binding,
      nonce: issued.nonce,
      challengeHash: issued.challengeHash,
      presentation: fixture.input.submission,
      ...ports,
      authorizedVerifiers: [{ did: signer.did, keyIds: [signer.keyId], algorithms: ["jubjub-schnorr" as const] }],
      evaluatedAt: new Date(VP_FIXTURE_TIME_MS).toISOString(),
      propose,
    };

    await expect(consumeChallengeAndSubmitApplication({
      ...input,
      authorizedVerifiers: [],
    })).rejects.toThrow(/not authorized by policy/u);
    expect(await service.isLive({ binding, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBe(true);
    expect(propose).not.toHaveBeenCalled();

    const evidence = await consumeChallengeAndSubmitApplication(input);
    expect(evidence.envelope.presentationHash).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(evidence.signature.value).toMatch(/^0x[0-9a-f]+$/u);
    expect(JSON.stringify(evidence)).not.toContain("private-presentation-payload");
    expect(propose).toHaveBeenCalledOnce();
    expect(await service.isLive({ binding, nonce: issued.nonce, challengeHash: issued.challengeHash })).toBe(false);
    await expect(consumeChallengeAndSubmitApplication(input)).rejects.toThrow(/already consumed/u);
    expect(propose).toHaveBeenCalledOnce();
  });
});
