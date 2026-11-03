import { computeAuthorizationScopeCommitment, computePendingApplicationPayloadCommitment, requestGovernedResourceId } from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it } from "vitest";

import { prepareAuditorApplication, signPreparedAuditorApplication, type AuditorApplicationDraft } from "../auditor-application.js";

const did = `did:midnight:undeployed:${"1".repeat(64)}`;
const draft: AuditorApplicationDraft = {
  applicationId: "application:auditor:compliance:v1",
  authorizationId: "auth:auditor:compliance:v1",
  actorDid: did,
  actorKeyId: `${did}#authentication-1`,
  requestProfileId: "profile:compliance:v1",
  purpose: "regulated-audit",
  credentialScopeCommitment: `0x${"a".repeat(64)}`,
  allowedAttributes: ["attribute:age", "attribute:residency"],
  allowedPredicates: ["predicate:over-18"],
  disclosureLevel: "minimal",
};
const context = {
  registryId: "registry:test:trusted",
  expectedEpochId: "epoch:registry:test:trusted:seq-1",
  expectedWorkspaceCommitment: `0x${"b".repeat(64)}`,
  evaluatedAt: "2026-10-15T05:00:00.000Z",
};
const nonce = `0x${"c".repeat(64)}`;

describe("auditor application signing preparation", () => {
  it("derives the exact resource and role-bound intent for an external DID signer", () => {
    const prepared = prepareAuditorApplication(draft, context, nonce);
    expect(prepared.payload.scope.role).toBe("auditor");
    expect(prepared.payload.governedResource).toEqual({
      type: "requestProfile",
      id: requestGovernedResourceId(prepared.payload.scope as Extract<typeof prepared.payload.scope, { role: "auditor" }>),
    });
    expect(prepared.intent).toMatchObject({
      registryId: context.registryId,
      actorDid: did,
      actorRole: "applicant",
      action: "apply",
      target: "auditor",
      targetId: draft.applicationId,
      scopeCommitment: computeAuthorizationScopeCommitment(prepared.payload.scope),
      payloadCommitment: computePendingApplicationPayloadCommitment(prepared.payload),
      expectedEpochId: context.expectedEpochId,
      expectedWorkspaceCommitment: context.expectedWorkspaceCommitment,
    });
    expect(prepared.digest).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(signPreparedAuditorApplication(prepared, `0x${"d".repeat(192)}`)).toMatchObject({
      applicationId: draft.applicationId,
      signature: { keyId: draft.actorKeyId, algorithm: "jubjub-schnorr" },
    });
  });

  it("changes the signed payload for purpose, credential scope, or disclosure changes", () => {
    const original = prepareAuditorApplication(draft, context, nonce);
    for (const changed of [
      { purpose: "different-audit" },
      { credentialScopeCommitment: `0x${"e".repeat(64)}` },
      { disclosureLevel: "full" },
      { allowedAttributes: ["attribute:age"] },
    ]) {
      const prepared = prepareAuditorApplication({ ...draft, ...changed }, context, nonce);
      expect(prepared.digest).not.toBe(original.digest);
      expect(prepared.payload.governedResource.id).not.toBe(original.payload.governedResource.id);
    }
  });

  it("rejects a bare request profile, wrong DID key, duplicate scope, and malformed signature", () => {
    expect(() => prepareAuditorApplication({ ...draft, requestProfileId: "" }, context, nonce)).toThrow();
    expect(() => prepareAuditorApplication({ ...draft, actorKeyId: `${did}#other`, actorDid: `did:midnight:undeployed:${"2".repeat(64)}` }, context, nonce)).toThrow();
    expect(() => prepareAuditorApplication({ ...draft, allowedAttributes: ["attribute:age", "attribute:age"] }, context, nonce)).toThrow();
    expect(() => prepareAuditorApplication(draft, context, "bad nonce")).toThrow();
    const prepared = prepareAuditorApplication(draft, context, nonce);
    expect(() => signPreparedAuditorApplication(prepared, "0x01")).toThrow();
  });
});
