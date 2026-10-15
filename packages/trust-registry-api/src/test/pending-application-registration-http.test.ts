import { Buffer } from "node:buffer";
import type { Server } from "node:http";

import { createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";
import { deriveJubjubPublicKeyFromSeed, encodeJubjubSignature, signJubjubPayloadFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import {
  computeAuthorizationScopeCommitment,
  computePendingApplicationPayloadCommitment,
  issuerGovernedResourceId,
  mutationIntentDigestBytes,
  requestGovernedResourceId,
  type AuthorizationScope,
  type GovernedResource,
  type MutationIntent,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  bytes32Commitment,
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createMidnightDid,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
  LocalTrustRegistryIntegrationHarness,
} from "@midnight-ntwrk/trust-registry-integration";
import { afterEach, describe, expect, it } from "vitest";

import { InMemoryApplicationChallengeStore } from "../application-challenges.js";
import type { ApplicationVpHttpPort } from "../application-vp-http.js";
import {
  InMemoryPendingApplicationRegistrationPort,
  type PendingApplicationRegistrationState,
} from "../pending-application-registration.js";
import { createTrustRegistryApiServer } from "../server.js";
import { createInMemorySource } from "../source.js";
import { computeOperatorWorkspaceCommitment } from "../workspace-commitment.js";

const NOW = "2026-10-13T00:01:00.000Z";
const seed = new Uint8Array(32).fill(47);
const applicantDid = createMidnightDid("http-auditor-applicant");
const evidenceVerifierDid = createMidnightDid("http-auditor-evidence-verifier");
const applicationId = "application:auditor:http-company:v1";
const scope = {
  version: "tr-scope-v1" as const,
  role: "auditor" as const,
  requestProfileId: "audit-profile:company:v1",
  purpose: "compliance-review",
  credentialScopeCommitment: `0x${"11".repeat(32)}`,
  allowedAttributes: ["company-id", "license-state"],
  allowedPredicates: ["is-licensed", "status-active"],
  disclosureLevel: "restricted",
};
const governedResource = { type: "requestProfile" as const, id: requestGovernedResourceId(scope) };
const resolver = createMidnightDidResolver([
  createMidnightDidLedgerFixture(applicantDid, {
    verificationMethodId: "authentication-1",
    schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(seed),
  }),
]);

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address expected");
  return `http://127.0.0.1:${address.port.toString()}`;
}

function signedRequest(
  state: PendingApplicationRegistrationState,
  nonceByte = "22",
  candidate: { applicationId: string; authorizationId?: string; scope: AuthorizationScope; governedResource: GovernedResource } = {
    applicationId, scope, governedResource,
  },
) {
  const payload = {
    ...candidate,
    authorizationId: candidate.authorizationId ?? `auth:${candidate.scope.role}:company:v1`,
  };
  const intent: MutationIntent = {
    version: "tr-mutation-intent-v1",
    registryId: state.workspace.snapshot.registry.registryId,
    actorDid: applicantDid,
    actorKeyId: `${applicantDid}#authentication-1`,
    actorRole: "applicant",
    action: "apply",
    target: candidate.scope.role,
    targetId: candidate.applicationId,
    scopeCommitment: computeAuthorizationScopeCommitment(candidate.scope),
    payloadCommitment: computePendingApplicationPayloadCommitment(payload),
    nonce: `0x${nonceByte.repeat(32)}`,
    expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(state.workspace),
    expectedEpochId: state.workspace.snapshot.currentEpoch.epochId,
    issuedAt: "2026-10-13T00:00:00.000Z",
    expiresAt: "2026-10-13T00:05:00.000Z",
  };
  return {
    ...payload,
    intent,
    signature: {
      keyId: intent.actorKeyId,
      algorithm: "jubjub-schnorr" as const,
      value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
        seed, mutationIntentDigestBytes(intent),
      ))).toString("hex")}`,
    },
  };
}

describe("pending application registration over private HTTP", () => {
  let server: Server | undefined;
  afterEach(async () => {
    if (server !== undefined) {
      await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve()));
      server = undefined;
    }
  });

  it("fails closed without an injected registration port and never advertises private CORS", async () => {
    server = createTrustRegistryApiServer({
      source: createInMemorySource(createOperatorWorkspace({ label: "no-registration-port" }).snapshot),
    });
    const base = await listen(server);
    const path = `${base}/v1/pending-applications`;
    const unavailable = await fetch(path, { method: "POST", body: "{}" });
    expect(unavailable.status).toBe(503);
    expect(unavailable.headers.get("access-control-allow-origin")).toBeNull();
    const preflight = await fetch(path, { method: "OPTIONS", headers: { origin: "https://untrusted.example" } });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-origin")).toBeNull();
    const bindingPreflight = await fetch(`${base}/v1/application-evidence/${applicationId}/binding`, { method: "OPTIONS" });
    expect(bindingPreflight.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("accepts a fresh DID-signed application after a verified archived proposal", async () => {
    const label = "issuer-reapply-http";
    const harness = new LocalTrustRegistryIntegrationHarness(label);
    const baseIssuer = createIssuerScenarioFixture(label);
    const issuer = {
      ...baseIssuer,
      subjectDid: applicantDid,
      subjectDidCommitment: bytes32Commitment(applicantDid),
    };
    const issuerScope = createIssuerAuthorizationScopeFixture(issuer);
    const issuerResource = { type: "credentialFamily" as const, id: issuer.resourceId };
    const state: PendingApplicationRegistrationState = {
      workspace: createOperatorWorkspace({ label }), applications: [], consumedNonces: [],
    };
    const registration = new InMemoryPendingApplicationRegistrationPort(state, evidenceVerifierDid, resolver);
    server = createTrustRegistryApiServer({
      source: createInMemorySource(state.workspace.snapshot),
      clock: () => NOW,
      pendingApplicationRegistration: registration,
    });
    const base = await listen(server);
    const post = (body: unknown) => fetch(`${base}/v1/pending-applications`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    });
    const first = signedRequest(state, "22", {
      applicationId: "application:issuer:reapply:v1",
      authorizationId: issuer.authorizationId,
      scope: issuerScope,
      governedResource: issuerResource,
    });
    expect((await post(first)).status).toBe(201);
    const pending = registration.readPending(first.applicationId)!;
    const replacement = signedRequest(state, "23", {
      applicationId: "application:issuer:reapply:v2",
      authorizationId: `${issuer.authorizationId}:replacement`,
      scope: issuerScope,
      governedResource: issuerResource,
    });
    expect((await post(replacement)).status).toBe(409);
    harness.proposeIssuer(issuer);
    const eventHash = harness.archiveIssuer(issuer);
    const bundle = harness.buildIssuerHistoricalEvidence(issuer);
    const observation = {
      authorizationId: pending.authorizationId,
      binding: pending.binding,
      status: "archived" as const,
      archiveEventHash: `0x${Buffer.from(eventHash).toString("hex")}`,
    };
    const verify = () => {
      new TrustRegistrySimulatorClient(harness.simulator).verifyIssuerAuthorizationBundle(
        bundle, { expectedRegistryId: harness.registryId, requireActive: false },
      );
      return bundle.authorization?.status === "archived"
        && bundle.authorization.authorizationId === observation.authorizationId
        && bundle.authorization.subjectDid === observation.binding.subjectDid
        ? bundle.authorization.lifecycleEventRoot : null;
    };
    await registration.recordArchived(observation, verify);
    expect(registration.readPending(first.applicationId)).toBeNull();
    const accepted = await post(replacement);
    expect(accepted.status).toBe(201);
    expect(registration.readPending(replacement.applicationId)?.status).toBe("pending");
    expect((await post(first)).status).toBe(409);
  });

  it("registers a DID-signed exact scope, then admits one challenge-bound VP for that pending record", async () => {
    const state: PendingApplicationRegistrationState = {
      workspace: createOperatorWorkspace({ label: "auditor-http-registration" }),
      applications: [],
      consumedNonces: [],
    };
    const registration = new InMemoryPendingApplicationRegistrationPort(state, evidenceVerifierDid, resolver);
    const applicationVp: ApplicationVpHttpPort = {
      challengeStore: new InMemoryApplicationChallengeStore(),
      authorizeRequest: async (id, request) => {
        const current = registration.readPending(id);
        if (current === null || request.headers["x-applicant-did"] !== current.binding.subjectDid) {
          throw new Error("unauthorized");
        }
      },
      resolvePendingApplication: async (id) => {
        const current = registration.readPending(id);
        return current === null ? null : {
          binding: current.binding,
          authorizedVerifiers: [{
            did: evidenceVerifierDid,
            keyIds: [`${evidenceVerifierDid}#assertion-1`],
            algorithms: ["jubjub-schnorr"],
          }],
        };
      },
      verifyPresentation: async (presentation) => {
        const proof = presentation as { nonce: string; subjectDid: string; scopeCommitment: string; secret: string };
        if (proof.secret !== "private-vp") throw new Error("invalid VP");
        return {
          nonce: proof.nonce,
          subjectDid: proof.subjectDid,
          scopeCommitment: proof.scopeCommitment,
          presentationHash: `0x${"55".repeat(32)}`,
          claimsCommitment: `0x${"66".repeat(32)}`,
          verifiedAt: NOW,
          expiresAt: "2026-10-13T00:02:00.000Z",
        };
      },
      signEvidence: async () => ({
        keyId: `${evidenceVerifierDid}#assertion-1`, algorithm: "jubjub-schnorr", value: "fixture-signature",
      }),
      verifyEvidenceSignature: (_commitment, signature) => signature.value === "fixture-signature",
      persistRedactedEvidence: async (_id, evidence) => ({
        receiptId: `0x${"77".repeat(32)}`, evidenceCommitment: evidence.commitment, acceptedAt: NOW,
      }),
    };
    server = createTrustRegistryApiServer({
      source: createInMemorySource(state.workspace.snapshot),
      clock: () => NOW,
      pendingApplicationRegistration: registration,
      applicationVp,
    });
    const base = await listen(server);
    const post = (path: string, body: unknown, authenticated = false) => fetch(`${base}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(authenticated ? { "x-applicant-did": applicantDid } : {}) },
      body: JSON.stringify(body),
    });
    const path = "/v1/pending-applications";
    const malformed = await fetch(`${base}${path}`, { method: "POST", body: '{"secret":"not-for-errors"' });
    expect(malformed.status).toBe(400);
    expect(await malformed.text()).not.toContain("not-for-errors");
    expect(registration.readPending(applicationId)).toBeNull();
    const signed = signedRequest(state);
    expect((await post(path, { ...signed, authorizationId: "auth:auditor:substituted:v1" })).status).toBe(400);
    expect(registration.readPending(applicationId)).toBeNull();
    const invalid = await post(path, { ...signed, signature: { ...signed.signature, value: `0x${"00".repeat(96)}` } });
    expect(invalid.status).toBe(401);
    expect(registration.readPending(applicationId)).toBeNull();
    const submitted = await post(path, signed);
    expect(submitted.status).toBe(201);
    expect(submitted.headers.get("access-control-allow-origin")).toBeNull();
    const pending = await submitted.json() as { authorizationId: string; binding: { scope: unknown } };
    expect(pending.binding.scope).toEqual(scope);
    expect(pending.authorizationId).toBe(signed.authorizationId);
    expect(registration.readPending(applicationId)?.binding.applicationId).toBe(applicationId);
    expect((await post(path, signed)).status).toBe(409);

    const evidencePath = `/v1/application-evidence/${applicationId}`;
    const denied = await fetch(`${base}${evidencePath}/binding`);
    expect(denied.status).toBe(403);
    expect(denied.headers.get("access-control-allow-origin")).toBeNull();
    const bindingResponse = await fetch(`${base}${evidencePath}/binding`, { headers: { "x-applicant-did": applicantDid } });
    expect(bindingResponse.status).toBe(200);
    const binding = await bindingResponse.json() as { scopeCommitment: string; subjectDid: string };
    expect(binding.subjectDid).toBe(applicantDid);
    const challengeResponse = await post(`${evidencePath}/challenges`, {}, true);
    expect(challengeResponse.status).toBe(201);
    const challenge = await challengeResponse.json() as { nonce: string; challengeHash: string };
    const presentation = {
      nonce: challenge.nonce, subjectDid: applicantDid,
      scopeCommitment: binding.scopeCommitment, secret: "private-vp",
    };
    const accepted = await post(`${evidencePath}/submissions`, {
      nonce: challenge.nonce, challengeHash: challenge.challengeHash, presentation,
    }, true);
    expect(accepted.status).toBe(202);
    const text = await accepted.text();
    expect(text).not.toContain("private-vp");
    expect(text).not.toContain(challenge.nonce);
    expect(JSON.parse(text).receipt.evidenceCommitment).toBe(JSON.parse(text).evidence.commitment);
    expect((await post(`${evidencePath}/submissions`, {
      nonce: challenge.nonce, challengeHash: challenge.challengeHash, presentation,
    }, true)).status).toBe(409);
  });

  it("registers issuer, verifier, and maintainer applications over the same signed endpoint", async () => {
    const state: PendingApplicationRegistrationState = {
      workspace: createOperatorWorkspace({ label: "multi-role-http-registration" }),
      applications: [], consumedNonces: [],
    };
    const registration = new InMemoryPendingApplicationRegistrationPort(state, evidenceVerifierDid, resolver);
    const applicationVp: ApplicationVpHttpPort = {
      challengeStore: new InMemoryApplicationChallengeStore(),
      authorizeRequest: async (id, request) => {
        const current = registration.readPending(id);
        if (current === null || request.headers["x-applicant-did"] !== current.binding.subjectDid) {
          throw new Error("unauthorized");
        }
      },
      resolvePendingApplication: async (id) => {
        const current = registration.readPending(id);
        return current === null ? null : {
          binding: current.binding,
          authorizedVerifiers: [{
            did: evidenceVerifierDid,
            keyIds: [`${evidenceVerifierDid}#assertion-1`],
            algorithms: ["jubjub-schnorr"],
          }],
        };
      },
      verifyPresentation: async (presentation) => {
        const proof = presentation as { nonce: string; subjectDid: string; scopeCommitment: string };
        return {
          nonce: proof.nonce,
          subjectDid: proof.subjectDid,
          scopeCommitment: proof.scopeCommitment,
          presentationHash: `0x${"55".repeat(32)}`,
          claimsCommitment: `0x${"66".repeat(32)}`,
          verifiedAt: NOW,
          expiresAt: "2026-10-13T00:02:00.000Z",
        };
      },
      signEvidence: async () => ({
        keyId: `${evidenceVerifierDid}#assertion-1`, algorithm: "jubjub-schnorr", value: "fixture-signature",
      }),
      verifyEvidenceSignature: (_commitment, signature) => signature.value === "fixture-signature",
      persistRedactedEvidence: async (_id, evidence) => ({
        receiptId: `0x${"77".repeat(32)}`, evidenceCommitment: evidence.commitment, acceptedAt: NOW,
      }),
    };
    server = createTrustRegistryApiServer({
      source: createInMemorySource(state.workspace.snapshot),
      clock: () => NOW,
      pendingApplicationRegistration: registration,
      applicationVp,
    });
    const base = await listen(server);
    const path = `${base}/v1/pending-applications`;
    const issuerScope = {
      version: "tr-scope-v1" as const, role: "issuer" as const,
      credentialFamilyId: "degree", schemaId: "degree-schema", schemaVersion: "1.0.0",
      credentialDefinitionId: "degree-definition", statusMethod: "status-registry",
    };
    const verifierScope = { ...scope, role: "verifier" as const };
    const cases = [
      { applicationId: "application:issuer:company:v1", scope: issuerScope,
        governedResource: { type: "schema" as const, id: issuerGovernedResourceId(issuerScope, "schema") } },
      { applicationId: "application:verifier:company:v1", scope: verifierScope,
        governedResource: { type: "requestProfile" as const, id: requestGovernedResourceId(verifierScope) } },
      { applicationId: "application:maintainer:company:v1",
        scope: { version: "tr-scope-v1" as const, role: "maintainer" as const,
          registryId: state.workspace.snapshot.registry.registryId },
        governedResource: { type: "registry" as const, id: state.workspace.snapshot.registry.registryId } },
    ];
    for (const [index, candidate] of cases.entries()) {
      const signed = signedRequest(state, (index + 3).toString(16).padStart(2, "0"), candidate);
      const response = await fetch(path, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(signed),
      });
      expect(response.status).toBe(201);
      expect((await response.json() as { binding: { role: string; governedResource: unknown } }).binding)
        .toMatchObject({ role: candidate.scope.role, governedResource: candidate.governedResource });
      expect(registration.readPending(candidate.applicationId)?.binding.scope).toEqual(candidate.scope);
      expect((await fetch(path, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(signed),
      })).status).toBe(409);
      const wrongResource = { ...signed, governedResource: { ...candidate.governedResource, id: "tr:wrong-resource" } };
      expect((await fetch(path, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(wrongResource),
      })).status).toBe(400);

      const evidencePath = `${base}/v1/application-evidence/${candidate.applicationId}`;
      const applicantHeaders = { "content-type": "application/json", "x-applicant-did": applicantDid };
      const bindingResponse = await fetch(`${evidencePath}/binding`, { headers: applicantHeaders });
      expect(bindingResponse.status).toBe(200);
      const binding = await bindingResponse.json() as { scopeCommitment: string; governedResource: unknown; role: string };
      expect(binding.governedResource).toEqual(candidate.governedResource);
      expect(binding.role).toBe(candidate.scope.role);
      const issued = await fetch(`${evidencePath}/challenges`, {
        method: "POST", headers: applicantHeaders, body: "{}",
      });
      expect(issued.status).toBe(201);
      const challenge = await issued.json() as { nonce: string; challengeHash: string };
      const submitted = await fetch(`${evidencePath}/submissions`, {
        method: "POST", headers: applicantHeaders,
        body: JSON.stringify({
          nonce: challenge.nonce,
          challengeHash: challenge.challengeHash,
          presentation: { nonce: challenge.nonce, subjectDid: applicantDid, scopeCommitment: binding.scopeCommitment },
        }),
      });
      expect(submitted.status).toBe(202);
      expect((await submitted.json() as { receipt: { evidenceCommitment: string } }).receipt.evidenceCommitment)
        .toMatch(/^0x[0-9a-f]{64}$/u);
    }
  });
});
