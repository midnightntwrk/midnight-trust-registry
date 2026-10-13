import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signPolicyBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";

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
  VP_FIXTURE_TIME_MS,
} from "@midnight-ntwrk/trust-registry-integration";

import { ApplicationChallengeService, InMemoryApplicationChallengeStore } from "../application-challenges.js";
import { consumeChallengeAndSubmitApplication } from "../application-intake.js";
import { GovernedIssuerProposalRejectedError, type PreparedGovernedIssuerProposal } from "../governed-issuer-proposals.js";
import { GovernedMembershipActionRejectedError, type PreparedGovernedMembershipAction } from "../governed-membership-actions.js";
import { createTrustRegistryApiServer } from "../server.js";

const signHttpAction = (
  maintainer: MaintainerScenarioFixture,
  prepared: Pick<PreparedGovernedMembershipAction,
    "registryId" | "policyCommitment" | "actionKind" | "actionPayloadHash" | "actionSequence">,
) => {
  const fromHex = (value: string) => Buffer.from(value.slice(2), "hex");
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const signature = signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    fromHex(prepared.registryId),
    fromHex(prepared.policyCommitment),
    fromHex(prepared.actionKind),
    fromHex(prepared.actionPayloadHash),
    BigInt(prepared.actionSequence),
  );
  return {
    keyId: `0x${Buffer.from(maintainer.keyId).toString("hex")}`,
    publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
    signature: `0x${Buffer.from(encodeJubjubSignature(signature)).toString("hex")}`,
  };
};

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
    const expectedEvidence = {
      scope,
      challengeHash: issued.challengeHash,
      governedResource,
    };
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
        expect(evidence.signature.keyId).toBe(harness.evidenceVerifier.keyIds[0]);
        expect(harness.verifyApplicationEvidenceSignature(
          evidence.commitment, evidence.signature, harness.evidenceVerifier,
        )).toBe(true);
        return evidence;
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

    const submitted = await consumeChallengeAndSubmitApplication(input);
    expect(submitted.envelope.evidenceVerifierDid).toBe(harness.evidenceVerifier.did);
    expect(JSON.stringify(submitted)).not.toContain("private-presentation-payload");
    expect(harness.simulator.getLedger().issuerAuthorizationCount).toBe(0n);
    await expect(consumeChallengeAndSubmitApplication(input)).rejects.toThrow(/already consumed/u);
    expect(harness.simulator.getLedger().issuerAuthorizationCount).toBe(0n);

    const fixtures = {
      label: "vp-governed",
      issuers: [{ label: "vp", fixture: issuer }],
    };
    let snapshot = publishSimulatorSnapshot(harness, { label: fixtures.label });
    const server = createTrustRegistryApiServer({
      source: { mode: "memory", loadSnapshot: async () => snapshot },
      governedIssuerProposals: {
        async prepare(authorizationId, evidence) {
          if (authorizationId !== issuer.authorizationId) {
            throw new GovernedIssuerProposalRejectedError("unknown-authorization");
          }
          try {
            return harness.prepareIssuerProposalAction(issuer, evidence, expectedEvidence);
          } catch {
            throw new GovernedIssuerProposalRejectedError("invalid-evidence");
          }
        },
        async execute(authorizationId, evidence, signers, verifierSignature) {
          if (authorizationId !== issuer.authorizationId) {
            throw new GovernedIssuerProposalRejectedError("unknown-authorization");
          }
          let accepted: Uint8Array;
          try {
            accepted = harness.executeIssuerProposalWithSignatures(
              issuer, evidence, signers, verifierSignature, expectedEvidence,
            );
          } catch {
            throw new GovernedIssuerProposalRejectedError("invalid-signers");
          }
          snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
          return { eventHash: `0x${Buffer.from(accepted).toString("hex")}` };
        },
      },
      governedMembershipActions: {
        async prepare(role, authorizationId, action) {
          if (role !== "issuer" || authorizationId !== issuer.authorizationId) {
            throw new GovernedMembershipActionRejectedError("unknown-authorization");
          }
          return harness.prepareIssuerDecisionAction(issuer, action);
        },
        async execute(role, authorizationId, action, signers) {
          if (role !== "issuer" || authorizationId !== issuer.authorizationId) {
            throw new GovernedMembershipActionRejectedError("unknown-authorization");
          }
          let accepted: Uint8Array;
          try {
            accepted = harness.executeIssuerDecisionWithSignatures(issuer, action, signers);
          } catch {
            throw new GovernedMembershipActionRejectedError("invalid-signers");
          }
          snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
          return { eventHash: `0x${Buffer.from(accepted).toString("hex")}` };
        },
      },
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("API listener address unavailable");
      const base = `http://127.0.0.1:${address.port}`;
      const proposalEndpoint = `${base}/v1/governed/issuer/${issuer.authorizationId}/proposal`;
      const proposalPreparedResponse = await fetch(`${proposalEndpoint}/prepare`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ evidence: submitted }),
      });
      expect(proposalPreparedResponse.status).toBe(200);
      const proposalPrepared = await proposalPreparedResponse.json() as PreparedGovernedIssuerProposal;
      expect(proposalPrepared.evidenceHash).toBe(submitted.commitment);
      const verifierSignature = harness.signIssuerProposalEvidence(
        harness.prepareIssuerProposalAction(issuer, submitted, expectedEvidence),
      );
      const proposalAccepted = await fetch(`${proposalEndpoint}/submit`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          evidence: submitted,
          prepared: proposalPrepared,
          signers: [signHttpAction(second, proposalPrepared), signHttpAction(third, proposalPrepared)],
          evidenceVerifierSignature: `0x${Buffer.from(encodeJubjubSignature(verifierSignature)).toString("hex")}`,
        }),
      });
      expect(proposalAccepted.status).toBe(202);
      const proposalEvent = (await proposalAccepted.json()).eventHash as string;
      const proposal = harness.simulator.getIssuerProposalEvidence(issuer.authorizationIdCommitment);
      expect(proposalEvent).toBe(`0x${Buffer.from(proposal.proposalGovernanceEventHash).toString("hex")}`);
      expect(Buffer.from(proposal.evidenceCommitment)).toEqual(Buffer.from(submitted.commitment.slice(2), "hex"));
      expect(harness.simulator.getLedger().issuerAuthorizationCount).toBe(1n);
      for (const action of ["approve", "activate"] as const) {
        const endpoint = `${base}/v1/governed/issuer/${issuer.authorizationId}/actions/${action}`;
        const preparedResponse = await fetch(endpoint);
        expect(preparedResponse.status).toBe(200);
        const prepared = await preparedResponse.json() as PreparedGovernedMembershipAction;
        const accepted = await fetch(endpoint, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            prepared,
            signers: [signHttpAction(second, prepared), signHttpAction(third, prepared)],
          }),
        });
        expect(accepted.status).toBe(202);
        expect((await accepted.json()).eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      }
      const decision = harness.evaluateCurrentIssuerDecision(issuer, {
        expectedRegistryId: harness.registryId,
      });
      expect(decision.authorization?.status).toBe("active");
      expect(decision.authorization?.subjectDid).toBe(issuer.subjectDid);
      expect(decision.epoch.stateRoot).toMatch(/^0x[0-9a-f]{64}$/u);
      expect(() => new TrustRegistrySimulatorClient(harness.simulator)
        .verifyIssuerAuthorizationBundle(decision, {})).not.toThrow();

      const evidenceResponse = await fetch(
        `${base}/v1/authorizations/issuer/${issuer.authorizationId}/evidence`,
      );
      expect(evidenceResponse.status).toBe(200);
      const publicBundle = await evidenceResponse.json();
      expect(publicBundle.epoch.stateRoot).toBe(decision.epoch.stateRoot);
      expect(publicBundle.authorization.authorizationId).toBe(issuer.authorizationId);
      expect(() => new TrustRegistrySimulatorClient(harness.simulator)
        .verifyIssuerAuthorizationBundle(publicBundle, {})).not.toThrow();

      const resolutionResponse = await fetch(`${base}/v1/authorizations/resolve`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          role: "issuer", subjectDid: issuer.subjectDid, resourceId: issuer.resourceId,
        }),
      });
      expect(resolutionResponse.status).toBe(200);
      const resolution = await resolutionResponse.json();
      expect(resolution.authorization.authorizationId).toBe(issuer.authorizationId);
      expect(resolution.authorization.status).toBe("active");

      const wrongScopeResponse = await fetch(`${base}/v1/authorizations/resolve`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          role: "issuer",
          subjectDid: issuer.subjectDid,
          resourceId: createIssuerScenarioFixture("other-vp-scope").resourceId,
        }),
      });
      expect(wrongScopeResponse.status).toBe(404);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
