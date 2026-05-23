import { describe, expect, it } from "vitest";

import {
  createAuditorScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
} from "../../../trust-registry-integration/src/index.js";

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
      }),
    ).not.toThrow();
    expect(activeBundle.inclusionProof.proofType).toBe("merkle-inclusion");
    expect(activeBundle.inclusionProof.root).toBe(activeBundle.epoch.stateRoot);
    expect(activeBundle.inclusionProof.path[0]).toBe(activeBundle.epoch.eventRoot);

    expect(() =>
      client.verifyIssuerAuthorizationBundle(activeBundle, {
        expectedRegistryId: "registry:other:trusted",
      }),
    ).toThrow(/mismatch/i);

    harness.revokeIssuer(issuer);
    const revokedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(() =>
      client.verifyIssuerAuthorizationBundle(revokedBundle, {
        expectedRegistryId: harness.registryId,
      }),
    ).toThrow(/not active/i);

    expect(() =>
      client.verifyIssuerAuthorizationBundle(
        {
          ...activeBundle,
          inclusionProof: {
            ...activeBundle.inclusionProof,
            leafHash: `${activeBundle.inclusionProof.leafHash.slice(0, -1)}0`,
          },
        },
        {
          expectedRegistryId: harness.registryId,
        },
      ),
    ).toThrow(/leaf hash/i);

    expect(() =>
      client.verifyIssuerAuthorizationBundle(
        {
          ...activeBundle,
          inclusionProof: {
            ...activeBundle.inclusionProof,
            path: [`${activeBundle.inclusionProof.path[0]!.slice(0, -1)}0`],
          },
        },
        {
          expectedRegistryId: harness.registryId,
        },
      ),
    ).toThrow(/event sibling/i);

    expect(() =>
      client.verifyIssuerAuthorizationBundle(
        {
          ...activeBundle,
          inclusionProof: {
            ...activeBundle.inclusionProof,
            root: activeBundle.epoch.eventRoot,
          },
        },
        {
          expectedRegistryId: harness.registryId,
        },
      ),
    ).toThrow(/anchored state root/i);

    expect(() =>
      client.verifyIssuerAuthorizationBundle(
        {
          ...activeBundle,
          inclusionProof: {
            ...activeBundle.inclusionProof,
            leafIndex: 1,
          },
        },
        {
          expectedRegistryId: harness.registryId,
        },
      ),
    ).toThrow(/reconstructed state root/i);

    expect(() =>
      client.verifyIssuerAuthorizationBundle(
        {
          ...activeBundle,
          inclusionProof: {
            ...activeBundle.inclusionProof,
            proofType: "signed-statement" as "merkle-inclusion",
          },
        },
        {
          expectedRegistryId: harness.registryId,
        },
      ),
    ).toThrow(/invalid literal|merkle-inclusion/i);
  });

  it("preserves issuer proposal and approval evidence while rejecting non-active decisions by default", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("application");
    const client = new TrustRegistrySimulatorClient(harness.simulator);

    harness.proposeIssuer(issuer);
    const proposedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(() =>
      client.verifyIssuerAuthorizationBundle(proposedBundle, {
        expectedRegistryId: harness.registryId,
      }),
    ).toThrow(/not active/i);
    expect(() =>
      client.verifyIssuerAuthorizationBundle(proposedBundle, {
        expectedRegistryId: harness.registryId,
        requireActive: false,
      }),
    ).not.toThrow();

    harness.approveIssuer(issuer);
    const authorizedBundle = harness.buildIssuerHistoricalEvidence(issuer);
    expect(() =>
      client.verifyIssuerAuthorizationBundle(authorizedBundle, {
        expectedRegistryId: harness.registryId,
      }),
    ).toThrow(/not active/i);
    expect(() =>
      client.verifyIssuerAuthorizationBundle(authorizedBundle, {
        expectedRegistryId: harness.registryId,
        requireActive: false,
      }),
    ).not.toThrow();
  });

  it("verifies active verifier, auditor, and recognition bundles", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const verifier = createVerifierScenarioFixture("age-gate");
    const auditor = createAuditorScenarioFixture("iso-27001");
    const recognition = createRecognitionScenarioFixture("gaia-x");
    const client = new TrustRegistrySimulatorClient(harness.simulator);

    harness.authorizeVerifier(verifier);
    const verifierBundle = harness.evaluateCurrentVerifierDecision(verifier);
    expect(() =>
      client.verifyVerifierAuthorizationBundle(verifierBundle, {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: verifier.subjectDid,
        expectedResourceId: verifier.scopeResourceId,
      }),
    ).not.toThrow();

    harness.authorizeAuditor(auditor);
    const auditorBundle = harness.evaluateCurrentAuditorDecision(auditor);
    expect(() =>
      client.verifyAuditorAuthorizationBundle(auditorBundle, {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: auditor.subjectDid,
        expectedResourceId: auditor.scopeResourceId,
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
        evaluationTime: new Date(
          Date.parse(bundle.epoch.validUntil) + 60_000,
        ).toISOString(),
      }),
    ).toThrow(/stale/i);

    const originalSignature = bundle.epoch.maintainerSignatures[0];
    if (originalSignature === undefined) {
      throw new Error("expected epoch signature");
    }
    const tamperedSignature = `0x${
      originalSignature.signature.slice(2, 3) === "0" ? "1" : "0"
    }${originalSignature.signature.slice(3)}`;

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
                signature: tamperedSignature,
              },
            ],
          },
        },
        {
        },
      ),
    ).toThrow(/invalid/i);

    expect(() =>
      client.verifyIssuerAuthorizationBundle(
        {
          ...bundle,
          policy: {
            ...bundle.policy,
            policyId: "policy:other:v1",
          },
        },
        {},
      ),
    ).toThrow(/policy root/i);
  });
});
