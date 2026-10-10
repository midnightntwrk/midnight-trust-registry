import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

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
  LocalTrustRegistryIntegrationHarness,
  VP_FIXTURE_TIME_MS,
} from "@midnight-ntwrk/trust-registry-integration";

import { ApplicationChallengeService, InMemoryApplicationChallengeStore } from "../application-challenges.js";
import { consumeChallengeAndSubmitApplication } from "../application-intake.js";

describe("published VP proof to governed issuer proposal", () => {
  it("submits one redacted, DID-signed evidence commitment to the Compact simulator", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
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
        return harness.proposeIssuerWithApplicationEvidence(issuer, evidence, [], {
          scope,
          challengeHash: issued.challengeHash,
          governedResource,
        });
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
  });
});
