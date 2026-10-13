import { describe, expect, it } from "vitest";

import { computeAuthorizationScopeCommitment } from "../scope.js";
import {
  SignedPendingAuditorApplicationSchema,
  computePendingAuditorApplicationPayloadCommitment,
} from "../pending-auditor-application.js";

const did = `did:midnight:testnet:${"aa".repeat(32)}`;
const scope = {
  version: "tr-scope-v1" as const,
  role: "auditor" as const,
  requestProfileId: "audit-profile:compliance:v1",
  purpose: "compliance-review",
  credentialScopeCommitment: `0x${"11".repeat(32)}`,
  allowedAttributes: ["company-id", "license-state"],
  allowedPredicates: ["is-licensed", "status-active"],
  disclosureLevel: "restricted",
};
const payload = { applicationId: "application:auditor:alice:v1", scope };
const request = {
  ...payload,
  intent: {
    version: "tr-mutation-intent-v1" as const,
    registryId: "tr:registry:demo",
    actorDid: did,
    actorKeyId: `${did}#authentication-1`,
    actorRole: "applicant" as const,
    action: "apply" as const,
    target: "auditor" as const,
    targetId: payload.applicationId,
    scopeCommitment: computeAuthorizationScopeCommitment(scope),
    payloadCommitment: computePendingAuditorApplicationPayloadCommitment(payload),
    nonce: `0x${"22".repeat(32)}`,
    expectedWorkspaceCommitment: `0x${"33".repeat(32)}`,
    expectedEpochId: "epoch:one",
    issuedAt: "2026-10-13T00:00:00.000Z",
    expiresAt: "2026-10-13T00:05:00.000Z",
  },
  signature: { keyId: `${did}#authentication-1`, algorithm: "jubjub-schnorr" as const, value: `0x${"44".repeat(96)}` },
};

describe("pending auditor application signing boundary", () => {
  it("accepts one exact scope and normalizes set ordering for the payload commitment", () => {
    expect(SignedPendingAuditorApplicationSchema.parse(request).applicationId).toBe(payload.applicationId);
    expect(computePendingAuditorApplicationPayloadCommitment({
      ...payload,
      scope: {
        ...scope,
        allowedAttributes: [...scope.allowedAttributes].reverse(),
        allowedPredicates: [...scope.allowedPredicates].reverse(),
      },
    })).toBe(request.intent.payloadCommitment);
  });

  it("rejects cross-role, altered identity, scope, payload, and signing key", () => {
    const invalid = [
      { ...request, applicationId: "application:auditor:bob:v1" },
      { ...request, scope: { ...scope, purpose: "marketing" } },
      { ...request, scope: { ...scope, allowedAttributes: ["company-id"] } },
      { ...request, scope: { ...scope, role: "verifier" } },
      { ...request, intent: { ...request.intent, action: "submit" } },
      { ...request, intent: { ...request.intent, target: "verifier" } },
      { ...request, intent: { ...request.intent, actorRole: "maintainer" } },
      { ...request, intent: { ...request.intent, targetId: "application:auditor:bob:v1" } },
      { ...request, intent: { ...request.intent, scopeCommitment: `0x${"55".repeat(32)}` } },
      { ...request, intent: { ...request.intent, payloadCommitment: `0x${"55".repeat(32)}` } },
      { ...request, signature: { ...request.signature, keyId: `${did}#authentication-2` } },
      { ...request, unsigned: true },
    ];
    for (const candidate of invalid) {
      expect(SignedPendingAuditorApplicationSchema.safeParse(candidate).success).toBe(false);
    }
  });
});
