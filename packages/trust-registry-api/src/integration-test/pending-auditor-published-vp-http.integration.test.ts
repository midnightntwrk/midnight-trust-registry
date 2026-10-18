import { Buffer } from "node:buffer";
import type { Server } from "node:http";

import { createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import { encodeJubjubSignature, payloadToJubjubDigest, signJubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import {
  computeAuthorizationScopeCommitment,
  computePendingApplicationPayloadCommitment,
  mutationIntentDigestBytes,
  requestGovernedResourceId,
  type MutationIntent,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  createApplicationVpIntakePorts,
  createApplicationVpScenarioFixture,
  createMidnightDid,
  VP_FIXTURE_TIME_MS,
} from "@midnight-ntwrk/trust-registry-integration";
import { afterEach, describe, expect, it } from "vitest";

import { InMemoryApplicationChallengeStore } from "../application-challenges.js";
import type { ApplicationVpHttpPort } from "../application-vp-http.js";
import { InMemoryPendingApplicationRegistrationPort } from "../pending-application-registration.js";
import { createTrustRegistryApiServer } from "../server.js";
import { createInMemorySource } from "../source.js";
import { computeOperatorWorkspaceCommitment } from "../workspace-commitment.js";

const NOW = new Date(VP_FIXTURE_TIME_MS).toISOString();
const subjectDid = createMidnightDid("vp-holder");
const evidenceVerifierDid = createMidnightDid("vp-evidence-verifier");
const applicationId = "application:auditor:published-vp";
const scope = {
  version: "tr-scope-v1" as const,
  role: "auditor" as const,
  requestProfileId: "audit-profile:published-vp",
  purpose: "compliance-review",
  credentialScopeCommitment: `0x${"11".repeat(32)}`,
  allowedAttributes: ["company-id"],
  allowedPredicates: ["is-licensed"],
  disclosureLevel: "restricted",
};
const governedResource = { type: "requestProfile" as const, id: requestGovernedResourceId(scope) };

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address expected");
  return `http://127.0.0.1:${address.port.toString()}`;
}

describe("auditor signed apply through published DID/VC/VP HTTP intake", () => {
  let server: Server | undefined;
  afterEach(async () => {
    if (server !== undefined) {
      await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve()));
      server = undefined;
    }
  });

  it("registers a DID applicant and accepts one genuinely signed, policy-scoped VP without exposing claims", async () => {
    const fixture = await createApplicationVpScenarioFixture(undefined, { scope, subjectDid, evidenceVerifierDid });
    const workspace = createOperatorWorkspace({ label: "auditor-published-vp-http" });
    const registration = new InMemoryPendingApplicationRegistrationPort({
      workspace, applications: [], consumedNonces: [],
    }, evidenceVerifierDid, fixture.input.resolver);
    const ports = await createApplicationVpIntakePorts({
      resolver: fixture.input.resolver,
      family: fixture.family,
      signer: fixture.signer,
    });
    let storedEvidence: unknown;
    const applicationVp: ApplicationVpHttpPort = {
      challengeStore: new InMemoryApplicationChallengeStore(),
      authorizeRequest: async (id, request) => {
        const pending = registration.readPending(id);
        if (pending === null || request.headers["x-applicant-did"] !== pending.binding.subjectDid) {
          throw new Error("unauthorized");
        }
      },
      resolvePendingApplication: async (id) => {
        const pending = registration.readPending(id);
        return pending === null ? null : {
          binding: pending.binding,
          authorizedVerifiers: [{
            did: fixture.signer.did,
            keyIds: [fixture.signer.keyId],
            algorithms: ["jubjub-schnorr"],
          }],
        };
      },
      ...ports,
      persistRedactedEvidence: async (_id, evidence) => {
        storedEvidence = evidence;
        return {
          receiptId: `0x${"77".repeat(32)}`,
          evidenceCommitment: evidence.commitment,
          acceptedAt: NOW,
        };
      },
    };
    server = createTrustRegistryApiServer({
      source: createInMemorySource(workspace.snapshot),
      clock: () => NOW,
      pendingApplicationRegistration: registration,
      applicationVp,
    });
    const base = await listen(server);
    const intent: MutationIntent = {
      version: "tr-mutation-intent-v1",
      registryId: workspace.snapshot.registry.registryId,
      actorDid: subjectDid,
      actorKeyId: `${subjectDid}#auth-1`,
      actorRole: "applicant",
      action: "apply",
      target: "auditor",
      targetId: applicationId,
      scopeCommitment: computeAuthorizationScopeCommitment(scope),
      payloadCommitment: computePendingApplicationPayloadCommitment({
        applicationId, authorizationId: "auth:auditor:published-vp:v1", scope, governedResource,
      }),
      nonce: `0x${"22".repeat(32)}`,
      expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(workspace),
      expectedEpochId: workspace.snapshot.currentEpoch.epochId,
      issuedAt: new Date(VP_FIXTURE_TIME_MS - 60_000).toISOString(),
      expiresAt: new Date(VP_FIXTURE_TIME_MS + 60_000).toISOString(),
    };
    const signed = {
      applicationId,
      authorizationId: "auth:auditor:published-vp:v1",
      scope,
      governedResource,
      intent,
      signature: {
        keyId: intent.actorKeyId,
        algorithm: "jubjub-schnorr",
        value: `0x${Buffer.from(encodeJubjubSignature(signJubjubDigest(
          23n, payloadToJubjubDigest(mutationIntentDigestBytes(intent)),
        ))).toString("hex")}`,
      },
    };
    const post = (path: string, body: unknown) => fetch(`${base}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-applicant-did": subjectDid },
      body: JSON.stringify(body),
    });
    const registered = await post("/v1/pending-applications", signed);
    expect(registered.status).toBe(201);
    expect((await registered.json() as { binding: { scope: unknown } }).binding.scope).toEqual(scope);
    const path = `/v1/application-evidence/${applicationId}`;
    const challengeResponse = await post(`${path}/challenges`, {});
    expect(challengeResponse.status).toBe(201);
    const challenge = await challengeResponse.json() as { nonce: string; challengeHash: string };
    const validVp = await createApplicationVpScenarioFixture(challenge.nonce, {
      scope, subjectDid, evidenceVerifierDid,
    });
    const wrongScopeVp = await createApplicationVpScenarioFixture(challenge.nonce, {
      scope: { ...scope, purpose: "different-purpose" }, subjectDid, evidenceVerifierDid,
    });
    const wrongCredentialScopeVp = await createApplicationVpScenarioFixture(challenge.nonce, {
      scope: { ...scope, credentialScopeCommitment: `0x${"33".repeat(32)}` }, subjectDid, evidenceVerifierDid,
    });
    const submission = (presentation: unknown) => ({
      nonce: challenge.nonce,
      challengeHash: challenge.challengeHash,
      presentation,
    });
    const wrong = await post(`${path}/submissions`, submission(wrongScopeVp.input.submission));
    expect(wrong.status).toBe(403);
    expect((await post(`${path}/submissions`, submission(wrongCredentialScopeVp.input.submission))).status).toBe(403);
    const assertStatusActive = fixture.family.assertStatusActive;
    fixture.family.assertStatusActive = async () => { throw new Error("Credential status is revoked"); };
    try {
      expect((await post(`${path}/submissions`, submission(validVp.input.submission))).status).toBe(403);
    } finally {
      fixture.family.assertStatusActive = assertStatusActive;
    }
    expect(storedEvidence).toBeUndefined();
    const accepted = await post(`${path}/submissions`, submission(validVp.input.submission));
    expect(accepted.status).toBe(202);
    const body = await accepted.json() as { evidence: { signature: { value: string } }; receipt: unknown };
    expect(body.evidence.signature.value).toMatch(/^0x[0-9a-f]{192}$/u);
    expect(body.receipt).toBeDefined();
    expect(JSON.stringify(body)).not.toContain("private-presentation-payload");
    expect(JSON.stringify(storedEvidence)).not.toContain("private-presentation-payload");
    expect((await post(`${path}/submissions`, submission(validVp.input.submission))).status).toBe(409);
  });
});
