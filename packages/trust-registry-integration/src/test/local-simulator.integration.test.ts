import { describe, expect, it } from "vitest";

import {
  createAuditorScenarioFixture,
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
} from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("trust registry local simulator integration", () => {
  it("preserves issuer application history before activation", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("application");

    harness.proposeIssuer(issuer);

    expect(() => harness.evaluateCurrentIssuerDecision(issuer)).toThrow(/not active/i);
    const proposedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(proposedBundle.authorization?.status).toBe("proposed");
    expect(proposedBundle.authorization?.authorizedAt).toBeUndefined();
    expect(proposedBundle.authorization?.activeFrom).toBeUndefined();

    harness.approveIssuer(issuer);

    expect(() => harness.evaluateCurrentIssuerDecision(issuer)).toThrow(/not active/i);
    const authorizedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(authorizedBundle.authorization?.status).toBe("authorized");
    expect(authorizedBundle.authorization?.authorizedAt).toBeDefined();
    expect(authorizedBundle.authorization?.activeFrom).toBeUndefined();

    harness.activateIssuer(issuer);

    const activeBundle = harness.evaluateCurrentIssuerDecision(issuer, {
      expectedRegistryId: harness.registryId,
    });
    expect(activeBundle.authorization?.status).toBe("active");
    expect(activeBundle.authorization?.activeFrom).toBeDefined();
  });

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

  it("preserves verifier application history before activation", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const verifier = createVerifierScenarioFixture("employment-application");

    harness.proposeVerifier(verifier);

    expect(() => harness.evaluateCurrentVerifierDecision(verifier)).toThrow(/not active/i);
    const proposedBundle = harness.buildVerifierHistoricalEvidence(verifier);
    expect(proposedBundle.authorization?.status).toBe("proposed");
    expect(proposedBundle.authorization?.authorizedAt).toBeUndefined();
    expect(proposedBundle.authorization?.activeFrom).toBeUndefined();

    harness.approveVerifier(verifier);

    expect(() => harness.evaluateCurrentVerifierDecision(verifier)).toThrow(/not active/i);
    const authorizedBundle = harness.buildVerifierHistoricalEvidence(verifier);
    expect(authorizedBundle.authorization?.status).toBe("authorized");
    expect(authorizedBundle.authorization?.authorizedAt).toBeDefined();
    expect(authorizedBundle.authorization?.activeFrom).toBeUndefined();

    harness.activateVerifier(verifier);

    const activeBundle = harness.evaluateCurrentVerifierDecision(verifier, {
      expectedRegistryId: harness.registryId,
    });
    expect(activeBundle.authorization?.status).toBe("active");
    expect(activeBundle.authorization?.activeFrom).toBeDefined();
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

  it("preserves recognition application history before activation", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("gaia-x-application");

    harness.proposeRecognition(recognition);

    expect(() => harness.evaluateCurrentRecognitionDecision(recognition)).toThrow(
      /not active/i,
    );
    const proposedBundle = harness.buildRecognitionHistoricalEvidence(recognition);
    expect(proposedBundle.recognition?.status).toBe("proposed");
    expect(proposedBundle.recognition?.authorizedAt).toBeUndefined();
    expect(proposedBundle.recognition?.effectiveFrom).toBeUndefined();

    harness.approveRecognition(recognition);

    expect(() => harness.evaluateCurrentRecognitionDecision(recognition)).toThrow(
      /not active/i,
    );
    const authorizedBundle = harness.buildRecognitionHistoricalEvidence(recognition);
    expect(authorizedBundle.recognition?.status).toBe("authorized");
    expect(authorizedBundle.recognition?.authorizedAt).toBeDefined();
    expect(authorizedBundle.recognition?.effectiveFrom).toBeUndefined();

    harness.activateRecognition(recognition);

    const activeBundle = harness.evaluateCurrentRecognitionDecision(recognition, {
      expectedRegistryId: harness.registryId,
    });
    expect(activeBundle.recognition?.status).toBe("active");
    expect(activeBundle.recognition?.effectiveFrom).toBeDefined();
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

  it("authorizes a trusted auditor and emits a valid active evidence bundle", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const auditor = createAuditorScenarioFixture("iso-27001");

    harness.authorizeAuditor(auditor);

    const bundle = harness.evaluateCurrentAuditorDecision(auditor, {
      expectedRegistryId: harness.registryId,
    });

    expect(bundle.authorization?.role).toBe("auditor");
    expect(bundle.authorization?.status).toBe("active");
    expect(bundle.authorization?.resourceType).toBe("request-profile");
    expect(bundle.authorization?.resourceId).toBe(auditor.scopeResourceId);
    expect(bundle.subjectDid).toBe(auditor.subjectDid);
  });

  it("rejects current auditor trust after suspension and revocation but preserves historical evidence through archival", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const auditor = createAuditorScenarioFixture("gdpr");

    harness.authorizeAuditor(auditor);
    harness.suspendAuditor(auditor);

    expect(() => harness.evaluateCurrentAuditorDecision(auditor)).toThrow(/not active/i);
    const suspendedBundle = harness.buildAuditorHistoricalEvidence(auditor);
    expect(suspendedBundle.authorization?.status).toBe("suspended");

    harness.revokeAuditor(auditor);
    expect(() => harness.evaluateCurrentAuditorDecision(auditor)).toThrow(/not active/i);
    const revokedBundle = harness.buildAuditorHistoricalEvidence(auditor);
    expect(revokedBundle.authorization?.status).toBe("revoked");

    harness.archiveAuditor(auditor);
    const archivedBundle = harness.buildAuditorHistoricalEvidence(auditor);
    expect(archivedBundle.authorization?.status).toBe("archived");
    expect(archivedBundle.authorization?.archivedAt).toBeDefined();
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
