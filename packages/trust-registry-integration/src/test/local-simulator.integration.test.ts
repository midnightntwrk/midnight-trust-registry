import { describe, expect, it } from "vitest";

import {
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
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
    expect(bundle.epoch.maintainerSignatures).toHaveLength(1);
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

  it("authorizes an external recognition and emits a valid active evidence bundle", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("gaia-x");

    harness.authorizeRecognition(recognition);

    const bundle = harness.evaluateCurrentRecognitionDecision(recognition, {
      expectedRegistryId: harness.registryId,
    });

    expect(bundle.recognition?.status).toBe("active");
    expect(bundle.recognition?.recognizedAuthorityDid).toBe(
      recognition.recognizedAuthorityDid,
    );
    expect(bundle.recognition?.recognizedRegistryId).toBe(
      recognition.recognizedRegistryId,
    );
    expect(bundle.recognition?.scope.resourceType).toBe(
      recognition.scopeResourceType,
    );
    expect(bundle.recognition?.scope.resourceId).toBe(recognition.scopeResourceId);
    expect(bundle.subjectDid).toBe(recognition.recognizedAuthorityDid);
    expect(bundle.authorization).toBeUndefined();
  });

  it("rejects current recognition after suspension and revocation but preserves historical evidence through archival", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("eidas");

    harness.authorizeRecognition(recognition);
    harness.suspendRecognition(recognition);

    expect(() => harness.evaluateCurrentRecognitionDecision(recognition)).toThrow(
      /not active/i,
    );
    const suspendedBundle = harness.buildRecognitionHistoricalEvidence(recognition);
    expect(suspendedBundle.recognition?.status).toBe("suspended");

    harness.revokeRecognition(recognition);
    expect(() => harness.evaluateCurrentRecognitionDecision(recognition)).toThrow(
      /not active/i,
    );
    const revokedBundle = harness.buildRecognitionHistoricalEvidence(recognition);
    expect(revokedBundle.recognition?.status).toBe("revoked");

    harness.archiveRecognition(recognition);
    const archivedBundle = harness.buildRecognitionHistoricalEvidence(recognition);
    expect(archivedBundle.recognition?.status).toBe("archived");
    expect(archivedBundle.recognition?.archivedAt).toBeDefined();
  });

  it("rejects recognition trust for wrong registry, mismatched scope, and revoked lifecycle state", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("ebsi");

    harness.authorizeRecognition(recognition);

    expect(() =>
      harness.evaluateCurrentRecognitionDecision(recognition, {
        expectedRegistryId: "registry:other:trusted",
      }),
    ).toThrow(/registry mismatch/i);

    const mismatchedScope = {
      ...recognition,
      scopeResourceIdCommitment: recognition.scopeResourceTypeCommitment,
    };
    expect(() => harness.evaluateCurrentRecognitionDecision(mismatchedScope)).toThrow(
      /scope is not registered/i,
    );

    harness.revokeRecognition(recognition);
    expect(() => harness.evaluateCurrentRecognitionDecision(recognition)).toThrow(
      /not active/i,
    );
    const revokedBundle = harness.buildRecognitionHistoricalEvidence(recognition);
    expect(revokedBundle.recognition?.status).toBe("revoked");
  });

  it("rejects anchored evidence with a wrong root, a stale epoch window, or a tampered maintainer signature", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("university");

    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);
    const originalSignature = bundle.epoch.maintainerSignatures[0];
    if (originalSignature === undefined) {
      throw new Error("expected an epoch maintainer signature");
    }

    expect(() =>
      harness.assertPublishedEpochEvidence({
        ...bundle,
        epoch: {
          ...bundle.epoch,
          stateRoot: bundle.epoch.eventRoot,
        },
      }),
    ).toThrow(/state root mismatch/i);

    expect(() =>
      harness.assertPublishedEpochEvidence(bundle, {
        evaluationTime: new Date(
          Date.parse(bundle.epoch.validUntil) + 60_000,
        ).toISOString(),
      }),
    ).toThrow(/stale/i);

    expect(() =>
      harness.assertPublishedEpochEvidence({
        ...bundle,
        epoch: {
          ...bundle.epoch,
          maintainerSignatures: [
            {
              keyId: originalSignature.keyId,
              algorithm: originalSignature.algorithm,
              signature: `${originalSignature.signature.slice(0, -1)}0`,
            },
          ],
        },
      }),
    ).toThrow(/invalid/i);
  });
});
