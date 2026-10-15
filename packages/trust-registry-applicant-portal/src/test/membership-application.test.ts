import {
  computeAuthorizationScopeCommitment,
  computePendingApplicationPayloadCommitment,
  issuerGovernedResourceId,
  requestGovernedResourceId,
} from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it } from "vitest";

import {
  prepareIssuerApplication,
  prepareMaintainerApplication,
  prepareMembershipApplication,
  prepareVerifierApplication,
  signPreparedMembershipApplication,
  type IssuerApplicationDraft,
  type VerifierApplicationDraft,
} from "../membership-application.js";

const did = `did:midnight:undeployed:${"1".repeat(64)}`;
const context = {
  registryId: "registry:test:trusted",
  expectedEpochId: "epoch:registry:test:trusted:seq-1",
  expectedWorkspaceCommitment: `0x${"b".repeat(64)}`,
  evaluatedAt: "2026-10-15T05:00:00.000Z",
};
const nonce = `0x${"c".repeat(64)}`;
const identity = {
  actorDid: did,
  actorKeyId: `${did}#authentication-1`,
};
const issuerDraft: IssuerApplicationDraft = {
  ...identity,
  applicationId: "application:issuer:degree:v1",
  authorizationId: "auth:issuer:degree:v1",
  credentialFamilyId: "family:degree:v1",
  schemaId: "schema:degree",
  schemaVersion: "1.0.0",
  credentialDefinitionId: "definition:degree:v1",
  statusMethod: "status:registry:v1",
  governedResourceType: "credentialFamily",
};
const verifierDraft: VerifierApplicationDraft = {
  ...identity,
  applicationId: "application:verifier:age-gate:v1",
  authorizationId: "auth:verifier:age-gate:v1",
  requestProfileId: "profile:age-gate:v1",
  purpose: "age-gate",
  credentialScopeCommitment: `0x${"a".repeat(64)}`,
  allowedAttributes: ["attribute:age"],
  allowedPredicates: ["predicate:over-18"],
  disclosureLevel: "minimal",
};

describe("issuer and verifier application preparation", () => {
  it("binds the issuer's exact credential scope and selected resource type", () => {
    const prepared = prepareIssuerApplication(issuerDraft, context, nonce);
    expect(prepared.payload.scope.role).toBe("issuer");
    expect(prepared.payload.governedResource).toEqual({
      type: issuerDraft.governedResourceType,
      id: issuerGovernedResourceId(prepared.payload.scope as Extract<typeof prepared.payload.scope, { role: "issuer" }>, issuerDraft.governedResourceType),
    });
    expect(prepared.intent).toMatchObject({
      actorRole: "applicant", action: "apply", target: "issuer",
      targetId: issuerDraft.applicationId,
      scopeCommitment: computeAuthorizationScopeCommitment(prepared.payload.scope),
      payloadCommitment: computePendingApplicationPayloadCommitment(prepared.payload),
      expectedWorkspaceCommitment: context.expectedWorkspaceCommitment,
    });
    const signature = `0x${"d".repeat(192)}`;
    expect(signPreparedMembershipApplication(prepared, signature).signature).toEqual({
      algorithm: "jubjub-schnorr", keyId: identity.actorKeyId, value: signature,
    });
    for (const changed of [
      { credentialFamilyId: "family:other:v1" },
      { schemaId: "schema:other" },
      { schemaVersion: "2.0.0" },
      { credentialDefinitionId: "definition:other:v1" },
      { statusMethod: "status:other:v1" },
      { governedResourceType: "schema" as const },
    ]) {
      expect(prepareIssuerApplication({ ...issuerDraft, ...changed }, context, nonce).digest).not.toBe(prepared.digest);
    }
  });

  it("binds every verifier request field to a composite resource and digest", () => {
    const prepared = prepareVerifierApplication(verifierDraft, context, nonce);
    expect(prepared.payload.scope.role).toBe("verifier");
    expect(prepared.payload.governedResource).toEqual({
      type: "requestProfile",
      id: requestGovernedResourceId(prepared.payload.scope as Extract<typeof prepared.payload.scope, { role: "verifier" }>),
    });
    for (const changed of [
      { requestProfileId: "profile:other:v1" },
      { purpose: "different-purpose" },
      { credentialScopeCommitment: `0x${"e".repeat(64)}` },
      { allowedAttributes: ["attribute:residency"] },
      { allowedPredicates: ["predicate:resident"] },
      { disclosureLevel: "full" },
    ]) {
      const other = prepareVerifierApplication({ ...verifierDraft, ...changed }, context, nonce);
      expect(other.digest).not.toBe(prepared.digest);
      expect(other.payload.governedResource.id).not.toBe(prepared.payload.governedResource.id);
    }
  });

  it("derives maintainer scope and resource from the authenticated host context", () => {
    const draft = { ...identity, applicationId: "application:maintainer:one", authorizationId: "auth:maintainer:one" };
    const prepared = prepareMaintainerApplication(draft, context, nonce);
    expect(prepared.payload.scope).toEqual({ version: "tr-scope-v1", role: "maintainer", registryId: context.registryId });
    expect(prepared.payload.governedResource).toEqual({ type: "registry", id: context.registryId });
    expect(prepared.intent).toMatchObject({
      target: "maintainer", registryId: context.registryId,
      scopeCommitment: computeAuthorizationScopeCommitment(prepared.payload.scope),
      payloadCommitment: computePendingApplicationPayloadCommitment(prepared.payload),
    });
    expect(prepareMaintainerApplication(draft, { ...context, registryId: "registry:other:trusted" }, nonce).digest)
      .not.toBe(prepared.digest);
    expect(() => prepareMaintainerApplication(draft, { ...context, registryId: "*" }, nonce)).toThrow();
  });

  it("rejects malformed or wildcard scope, stale context shape, and bad signatures", () => {
    expect(() => prepareIssuerApplication({ ...issuerDraft, schemaVersion: "latest" }, context, nonce)).toThrow();
    expect(() => prepareIssuerApplication({ ...issuerDraft, governedResourceType: "requestProfile" as IssuerApplicationDraft["governedResourceType"] }, context, nonce)).toThrow();
    expect(() => prepareVerifierApplication({ ...verifierDraft, allowedAttributes: ["attribute:age", "attribute:age"] }, context, nonce)).toThrow();
    expect(() => prepareVerifierApplication({ ...verifierDraft, purpose: "*" }, context, nonce)).toThrow();
    expect(() => prepareVerifierApplication(verifierDraft, { ...context, evaluatedAt: "invalid" }, nonce)).toThrow();
    expect(() => prepareIssuerApplication(issuerDraft, context, "bad nonce")).toThrow();
    const prepared = prepareIssuerApplication(issuerDraft, context, nonce);
    expect(() => prepareMembershipApplication(issuerDraft, {
      ...prepared.payload, authorizationId: "auth:issuer:other:v1",
    }, context, nonce)).toThrow("Prepared application IDs must match");
    expect(() => signPreparedMembershipApplication(prepareIssuerApplication(issuerDraft, context, nonce), "0x01")).toThrow();
  });
});
