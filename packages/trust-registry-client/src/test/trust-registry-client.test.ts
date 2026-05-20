import { describe, expect, it } from "vitest";

import {
  LocalTrustRegistryIntegrationHarness,
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";

import { TrustRegistrySimulatorClient } from "../index.js";

describe("trust registry client", () => {
  it("queries current and historical issuer state plus the published epoch anchor", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("degree");

    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);
    const client = new TrustRegistrySimulatorClient(harness.simulator);

    const currentRecord = client.getCurrentIssuerAuthorization({
      subjectDid: issuer.subjectDid,
      resourceType: issuer.resourceType,
      resourceId: issuer.resourceId,
    });
    const historicalRecord = client.getIssuerAuthorizationById(issuer.authorizationId);
    const epochRecord = client.getEpochCommitmentById(bundle.epoch.epochId);

    expect(currentRecord.status).toEqual(historicalRecord.status);
    expect(epochRecord.validFromSequence).toBeGreaterThanOrEqual(0n);
  });

  it("verifies an active issuer bundle and rejects wrong-registry or revoked evidence", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("passport");

    harness.authorizeIssuer(issuer);
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    const activeBundle = harness.evaluateCurrentIssuerDecision(issuer);

    expect(() =>
      client.verifyIssuerAuthorizationBundle(activeBundle, {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: issuer.subjectDid,
        expectedResourceId: issuer.resourceId,
        registryIdCommitment: harness.registryIdCommitment,
      }),
    ).not.toThrow();

    expect(() =>
      client.verifyIssuerAuthorizationBundle(activeBundle, {
        expectedRegistryId: "registry:other:trusted",
        registryIdCommitment: harness.registryIdCommitment,
      }),
    ).toThrow(/mismatch/i);

    harness.revokeIssuer(issuer);
    const revokedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(() =>
      client.verifyIssuerAuthorizationBundle(revokedBundle, {
        expectedRegistryId: harness.registryId,
        registryIdCommitment: harness.registryIdCommitment,
      }),
    ).toThrow(/not active/i);
  });

  it("verifies active verifier and recognition bundles", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const verifier = createVerifierScenarioFixture("age-gate");
    const recognition = createRecognitionScenarioFixture("gaia-x");
    const client = new TrustRegistrySimulatorClient(harness.simulator);

    harness.authorizeVerifier(verifier);
    const verifierBundle = harness.evaluateCurrentVerifierDecision(verifier);
    expect(() =>
      client.verifyVerifierAuthorizationBundle(verifierBundle, {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: verifier.subjectDid,
        expectedResourceId: verifier.scopeResourceId,
        registryIdCommitment: harness.registryIdCommitment,
      }),
    ).not.toThrow();

    harness.authorizeRecognition(recognition);
    const recognitionBundle = harness.evaluateCurrentRecognitionDecision(recognition);
    expect(() =>
      client.verifyRecognitionBundle(recognitionBundle, {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: recognition.recognizedAuthorityDid,
        expectedResourceId: recognition.scopeResourceId,
        expectedRecognizedRegistryId: recognition.recognizedRegistryId,
        registryIdCommitment: harness.registryIdCommitment,
      }),
    ).not.toThrow();
  });

  it("rejects stale epochs and tampered maintainer signatures deterministically", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("employment");
    const client = new TrustRegistrySimulatorClient(harness.simulator);

    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);

    expect(() =>
      client.verifyIssuerAuthorizationBundle(bundle, {
        registryIdCommitment: harness.registryIdCommitment,
        evaluationTime: new Date(
          Date.parse(bundle.epoch.validUntil) + 60_000,
        ).toISOString(),
      }),
    ).toThrow(/stale/i);

    const originalSignature = bundle.epoch.maintainerSignatures[0];
    if (originalSignature === undefined) {
      throw new Error("expected epoch signature");
    }

    expect(() =>
      client.verifyIssuerAuthorizationBundle(
        {
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
        },
        {
          registryIdCommitment: harness.registryIdCommitment,
        },
      ),
    ).toThrow(/invalid/i);
  });
});
