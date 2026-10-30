import { describe, expect, it } from "vitest";

import {
  canonicalizeIssuerStatusPolicyBinding,
  computeIssuerStatusPolicyBindingCommitment,
  type IssuerStatusPolicyBinding,
} from "../status-policy.js";

const binding = {
  version: "tr-issuer-status-policy-v1",
  trustRegistryId: "tr:midnight:example",
  issuerAuthorizationId: "auth:issuer:acme:v1",
  statusRegistryId: `0x${"1".repeat(64)}`,
  statusAuthorityVerificationMethod: "did:midnight:issuer:acme#status-1",
  statusPolicyId: "policy:status:acme",
  statusPolicyVersion: "v1",
  statusPolicyContentCommitment: `0x${"2".repeat(64)}`,
} as const;

describe("issuer status policy binding v1", () => {
  it("has a stable canonical preimage independent of object field order", () => {
    const canonical = '{"issuerAuthorizationId":"auth:issuer:acme:v1","statusAuthorityVerificationMethod":"did:midnight:issuer:acme#status-1","statusPolicyContentCommitment":"0x2222222222222222222222222222222222222222222222222222222222222222","statusPolicyId":"policy:status:acme","statusPolicyVersion":"v1","statusRegistryId":"0x1111111111111111111111111111111111111111111111111111111111111111","trustRegistryId":"tr:midnight:example","version":"tr-issuer-status-policy-v1"}';
    expect(canonicalizeIssuerStatusPolicyBinding(binding)).toBe(canonical);
    expect(canonicalizeIssuerStatusPolicyBinding({
      statusPolicyId: binding.statusPolicyId,
      version: binding.version,
      statusRegistryId: binding.statusRegistryId,
      trustRegistryId: binding.trustRegistryId,
      statusPolicyContentCommitment: binding.statusPolicyContentCommitment,
      issuerAuthorizationId: binding.issuerAuthorizationId,
      statusPolicyVersion: binding.statusPolicyVersion,
      statusAuthorityVerificationMethod: binding.statusAuthorityVerificationMethod,
    })).toBe(canonical);
    expect(computeIssuerStatusPolicyBindingCommitment(binding)).toBe(
      "0x017aa24b5830dd91bb75baf2dc6306316fb45da1f2f79b77d1bbc574589510a8",
    );
  });

  it.each([
    { statusRegistryId: `0x${"3".repeat(64)}` },
    { statusAuthorityVerificationMethod: "did:midnight:issuer:acme#status-2" },
    { statusPolicyContentCommitment: `0x${"4".repeat(64)}` },
    { statusPolicyVersion: "v2" },
    { issuerAuthorizationId: "auth:issuer:other:v1" },
    { trustRegistryId: "tr:midnight:other" },
  ])("changes the commitment when a governed field changes: %j", (change) => {
    expect(computeIssuerStatusPolicyBindingCommitment({ ...binding, ...change }))
      .not.toBe(computeIssuerStatusPolicyBindingCommitment(binding));
  });

  it.each([
    { version: "tr-issuer-status-policy-v2" },
    { statusRegistryId: `0x${"A".repeat(64)}` },
    { statusPolicyContentCommitment: `0x${"B".repeat(64)}` },
    { statusAuthorityVerificationMethod: "did:midnight:issuer:acme" },
    { statusAuthorityVerificationMethod: "did:midnight:issuer:acme#status-1#other" },
    { statusAuthorityVerificationMethod: "did:midnight:issuer:acme#status-*" },
    { statusAuthorityVerificationMethod: "did:midnight:issuer:acme#status-\u200b1" },
    { statusPolicyVersion: "v01" },
    { statusPolicyId: "Policy:Status:Acme" },
    { extra: "ignored" },
  ])("rejects noncanonical or ambiguous binding fields: %j", (change) => {
    expect(() => canonicalizeIssuerStatusPolicyBinding({ ...binding, ...change } as IssuerStatusPolicyBinding))
      .toThrow();
  });
});
