import { describe, expect, it } from "vitest";

import {
  issuerGovernedResourceIdFromScopeCommitment,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  TrustRegistryApiEvaluateAuthorizationRequestSchema,
  TrustRegistryApiResolveAuthorizationRequestSchema,
} from "../schemas.js";

const request = {
  role: "issuer",
  subjectDid: "did:midnight:issuer:one",
  resourceType: "schema-version",
  resourceId: issuerGovernedResourceIdFromScopeCommitment(`0x${"a".repeat(64)}`, "schemaVersion"),
} as const;

describe("issuer authorization query identity", () => {
  it("requires composite IDs for current and historical issuer lookup", () => {
    expect(TrustRegistryApiResolveAuthorizationRequestSchema.safeParse(request).success).toBe(true);
    expect(TrustRegistryApiEvaluateAuthorizationRequestSchema.safeParse({
      ...request,
      at: "2026-10-08T00:00:00Z",
    }).success).toBe(true);
    expect(TrustRegistryApiResolveAuthorizationRequestSchema.safeParse({
      ...request,
      resourceId: "1.0.0",
    }).success).toBe(false);
    expect(TrustRegistryApiEvaluateAuthorizationRequestSchema.safeParse({
      ...request,
      resourceId: "1.0.0",
      at: "2026-10-08T00:00:00Z",
    }).success).toBe(false);
    expect(TrustRegistryApiResolveAuthorizationRequestSchema.safeParse({
      ...request,
      role: "verifier",
      resourceType: "request-profile",
      resourceId: "request-profile:admission",
    }).success).toBe(true);
  });
});
