import { Buffer } from "node:buffer";

import { createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
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
import { createMidnightDid, createMidnightDidLedgerFixture, createMidnightDidResolver } from "@midnight-ntwrk/trust-registry-integration";
import { describe, expect, it } from "vitest";

import {
  InMemoryPendingApplicationRegistrationPort,
  transitionPendingApplicationRegistration,
  type PendingApplicationRegistrationState,
} from "../pending-application-registration.js";
import { computeOperatorWorkspaceCommitment } from "../workspace-commitment.js";

const applicantSeed = new Uint8Array(32).fill(47);
const wrongSeed = new Uint8Array(32).fill(61);
const applicantDid = createMidnightDid("pending-auditor-applicant");
const evidenceVerifierDid = createMidnightDid("pending-auditor-evidence-verifier");
const now = new Date("2026-10-13T00:01:00.000Z");
const scope = {
  version: "tr-scope-v1" as const,
  role: "auditor" as const,
  requestProfileId: "audit-profile:company:v1",
  purpose: "license-audit",
  credentialScopeCommitment: `0x${"11".repeat(32)}`,
  allowedAttributes: ["company-id", "license-state"],
  allowedPredicates: ["is-licensed", "status-active"],
  disclosureLevel: "restricted",
};
const governedResource = { type: "requestProfile" as const, id: requestGovernedResourceId(scope) };

const resolver = createMidnightDidResolver([
  createMidnightDidLedgerFixture(applicantDid, {
    verificationMethodId: "authentication-1",
    schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(applicantSeed),
  }),
]);

const sign = (intent: MutationIntent, seed = applicantSeed) => ({
  keyId: intent.actorKeyId,
  algorithm: "jubjub-schnorr" as const,
  value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
    seed, mutationIntentDigestBytes(intent),
  ))).toString("hex")}`,
});

const requestFor = (
  state: PendingApplicationRegistrationState,
  options: {
    applicationId?: string;
    authorizationId?: string;
    nonceByte?: string;
    candidateScope?: AuthorizationScope;
    governedResource?: GovernedResource;
  } = {},
) => {
  const applicationId = options.applicationId ?? "application:auditor:company:v1";
  const candidateScope = options.candidateScope ?? scope;
  const authorizationId = options.authorizationId ?? `auth:${candidateScope.role}:company:v1`;
  const candidateResource: GovernedResource = options.governedResource ?? {
    type: "requestProfile", id: requestGovernedResourceId(scope),
  };
  const intent: MutationIntent = {
    version: "tr-mutation-intent-v1",
    registryId: state.workspace.snapshot.registry.registryId,
    actorDid: applicantDid,
    actorKeyId: `${applicantDid}#authentication-1`,
    actorRole: "applicant",
    action: "apply",
    target: candidateScope.role,
    targetId: applicationId,
    scopeCommitment: computeAuthorizationScopeCommitment(candidateScope),
    payloadCommitment: computePendingApplicationPayloadCommitment({
      applicationId,
      authorizationId,
      scope: candidateScope,
      governedResource: candidateResource,
    }),
    nonce: `0x${(options.nonceByte ?? "22").repeat(32)}`,
    expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(state.workspace),
    expectedEpochId: state.workspace.snapshot.currentEpoch.epochId,
    issuedAt: "2026-10-13T00:00:00.000Z",
    expiresAt: "2026-10-13T00:05:00.000Z",
  };
  return {
    applicationId, authorizationId, scope: candidateScope,
    governedResource: candidateResource,
    intent, signature: sign(intent),
  };
};

const initialState = (): PendingApplicationRegistrationState => ({
  workspace: createOperatorWorkspace({ label: "pending-application-registration" }),
  applications: [],
  consumedNonces: [],
});

describe("pending application registration transition", () => {
  it("serializes concurrent applications for one scope without consuming two nonces", async () => {
    const state = initialState();
    const port = new InMemoryPendingApplicationRegistrationPort(state, evidenceVerifierDid, resolver);
    const first = requestFor(state);
    const outcomes = await Promise.allSettled([
      port.register(first, now),
      port.register(requestFor(state, { applicationId: "application:auditor:company:v2", nonceByte: "23" }), now),
    ]);
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);
    expect(port.readPending(first.applicationId)?.status).toBe("pending");
    expect(port.readPending("application:auditor:company:v2")).toBeNull();
  });

  it("authenticates the applicant DID and binds the complete request scope to current policy", async () => {
    const initial = initialState();
    const request = requestFor(initial);
    const next = await transitionPendingApplicationRegistration(initial, request, evidenceVerifierDid, now, resolver);
    expect(initial.applications).toHaveLength(0);
    expect(initial.consumedNonces).toHaveLength(0);
    expect(next.applications).toHaveLength(1);
    expect(next.consumedNonces).toHaveLength(1);
    expect(next.applications[0]).toEqual({
      status: "pending",
      authorizationId: request.authorizationId,
      createdAt: now.toISOString(),
      binding: {
        registryId: initial.workspace.snapshot.registry.registryId,
        applicationId: request.applicationId,
        subjectDid: applicantDid,
        evidenceVerifierDid,
        role: "auditor",
        policyId: initial.workspace.snapshot.policy.policyId,
        policyVersion: initial.workspace.snapshot.policy.version,
        scope,
        scopeCommitment: computeAuthorizationScopeCommitment(scope),
        governedResource,
      },
    });
  });

  it("rejects replay, duplicate ID or authorization target, duplicate exact scope, and invalid signatures", async () => {
    const initial = initialState();
    const first = requestFor(initial);
    const accepted = await transitionPendingApplicationRegistration(initial, first, evidenceVerifierDid, now, resolver);
    const cases = [
      [first, "nonce-used"],
      [requestFor(accepted, { nonceByte: "23" }), "duplicate-application"],
      [requestFor(accepted, { applicationId: "application:auditor:company:v2", nonceByte: "24" }), "duplicate-authorization"],
      [requestFor(accepted, { applicationId: "application:auditor:company:v3", authorizationId: "auth:auditor:company:v2", nonceByte: "26" }), "duplicate-scope"],
      [{ ...requestFor(initial, { nonceByte: "25" }), signature: sign(requestFor(initial, { nonceByte: "25" }).intent, wrongSeed) }, "invalid-signature"],
    ] as const;
    for (const [candidate, reason] of cases) {
      await expect(transitionPendingApplicationRegistration(accepted, candidate, evidenceVerifierDid, now, resolver))
        .rejects.toMatchObject({ reason });
    }
    expect(accepted.applications).toHaveLength(1);
    expect(accepted.consumedNonces).toHaveLength(1);
  });

  it("rejects expired, stale, and substituted application contexts", async () => {
    const state = initialState();
    const request = requestFor(state);
    await expect(transitionPendingApplicationRegistration(
      state, request, evidenceVerifierDid, new Date("2026-10-13T00:05:00.000Z"), resolver,
    )).rejects.toMatchObject({ reason: "expired" });
    const stale = { ...request, intent: { ...request.intent, expectedWorkspaceCommitment: `0x${"55".repeat(32)}` } };
    await expect(transitionPendingApplicationRegistration(state, {
      ...stale, signature: sign(stale.intent),
    }, evidenceVerifierDid, now, resolver)).rejects.toMatchObject({ reason: "stale-workspace" });
    await expect(transitionPendingApplicationRegistration(state, {
      ...request, scope: { ...scope, purpose: "marketing" },
    }, evidenceVerifierDid, now, resolver)).rejects.toThrow();
    expect(state.applications).toHaveLength(0);
    expect(state.consumedNonces).toHaveLength(0);
  });

  it("registers issuer, verifier, and maintainer scopes with DID signatures and exact resources", async () => {
    const issuerScope = {
      version: "tr-scope-v1" as const, role: "issuer" as const,
      credentialFamilyId: "degree", schemaId: "degree-schema", schemaVersion: "1.0.0",
      credentialDefinitionId: "degree-definition", statusMethod: "status-registry",
    };
    const verifierScope = { ...scope, role: "verifier" as const };
    for (const [role, create] of [
      ["issuer", (_registryId: string) => ({
        scope: issuerScope,
        resource: { type: "schema" as const, id: issuerGovernedResourceId(issuerScope, "schema") },
      })],
      ["verifier", (_registryId: string) => ({
        scope: verifierScope,
        resource: { type: "requestProfile" as const, id: requestGovernedResourceId(verifierScope) },
      })],
      ["maintainer", (registryId: string) => ({
        scope: { version: "tr-scope-v1" as const, role: "maintainer" as const, registryId },
        resource: { type: "registry" as const, id: registryId },
      })],
    ] as const) {
      const state = initialState();
      const { scope: candidateScope, resource } = create(state.workspace.snapshot.registry.registryId);
      const request = requestFor(state, {
        applicationId: `application:${role}:company:v1`, candidateScope, governedResource: resource,
      });
      const next = await transitionPendingApplicationRegistration(state, request, evidenceVerifierDid, now, resolver);
      expect(next.applications[0]?.binding).toMatchObject({
        role, scope: candidateScope, governedResource: resource, subjectDid: applicantDid,
      });
      expect(next.consumedNonces).toHaveLength(1);
      await expect(transitionPendingApplicationRegistration(next, request, evidenceVerifierDid, now, resolver))
        .rejects.toMatchObject({ reason: "nonce-used" });
      await expect(transitionPendingApplicationRegistration(state, {
        ...request, governedResource: governedResource,
      }, evidenceVerifierDid, now, resolver)).rejects.toThrow();
      expect(state.applications).toHaveLength(0);
    }
  });
});
