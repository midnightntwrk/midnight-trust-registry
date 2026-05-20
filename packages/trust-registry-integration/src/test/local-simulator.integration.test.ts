import { describe, expect, it } from "vitest";

import {
  createIssuerScenarioFixture,
  createVerifierScenarioFixture,
} from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("trust registry local simulator integration", () => {
  it("authorizes an issuer and emits a valid active evidence bundle", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("degree");

    harness.authorizeIssuer(issuer);

    const bundle = harness.evaluateCurrentIssuerDecision(issuer, {
      expectedRegistryId: harness.registryId,
    });

    expect(bundle.authorization?.role).toBe("issuer");
    expect(bundle.authorization?.status).toBe("active");
    expect(bundle.authorization?.resourceId).toBe(issuer.resourceId);
    expect(bundle.subjectDid).toBe(issuer.subjectDid);
    expect(bundle.registryId).toBe(harness.registryId);
    expect(bundle.referencedStatusRegistryId).toBe(issuer.referencedStatusRegistryId);
  });

  it("rejects current issuer trust after suspension and revocation but preserves historical evidence through archival", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("passport");

    harness.authorizeIssuer(issuer);
    harness.suspendIssuer(issuer);

    expect(() => harness.evaluateCurrentIssuerDecision(issuer)).toThrow(/not active/i);
    const suspendedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(suspendedBundle.authorization?.status).toBe("suspended");

    harness.revokeIssuer(issuer);
    expect(() => harness.evaluateCurrentIssuerDecision(issuer)).toThrow(/not active/i);
    const revokedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(revokedBundle.authorization?.status).toBe("revoked");

    harness.archiveIssuer(issuer);
    const archivedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(archivedBundle.authorization?.status).toBe("archived");
    expect(archivedBundle.authorization?.archivedAt).toBeDefined();
  });

  it("authorizes a verifier for a composite request scope and emits a valid active evidence bundle", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const verifier = createVerifierScenarioFixture("age-gate");

    harness.authorizeVerifier(verifier);

    const bundle = harness.evaluateCurrentVerifierDecision(verifier, {
      expectedRegistryId: harness.registryId,
    });

    expect(bundle.authorization?.role).toBe("verifier");
    expect(bundle.authorization?.status).toBe("active");
    expect(bundle.authorization?.resourceType).toBe("request-profile");
    expect(bundle.authorization?.resourceId).toBe(verifier.scopeResourceId);
    expect(bundle.subjectDid).toBe(verifier.subjectDid);
  });

  it("rejects verifier trust for wrong registry, mismatched scope, and revoked lifecycle state", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const verifier = createVerifierScenarioFixture("employment");

    harness.authorizeVerifier(verifier);

    expect(() =>
      harness.evaluateCurrentVerifierDecision(verifier, {
        expectedRegistryId: "registry:other:trusted",
      }),
    ).toThrow(/registry mismatch/i);

    const mismatchedScope = {
      ...verifier,
      allowedPredicateSetCommitment: verifier.allowedAttributeSetCommitment,
    };
    expect(() => harness.evaluateCurrentVerifierDecision(mismatchedScope)).toThrow(
      /scope is not registered/i,
    );

    harness.revokeVerifier(verifier);
    expect(() => harness.evaluateCurrentVerifierDecision(verifier)).toThrow(
      /not active/i,
    );
    const revokedBundle = harness.buildVerifierHistoricalEvidence(verifier);
    expect(revokedBundle.authorization?.status).toBe("revoked");
  });
});
