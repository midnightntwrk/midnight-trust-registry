import { describe, expect, it, vi } from "vitest";
import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";

import {
  computeGovernancePolicySnapshotCommitment,
  computeIssuerStatusPolicyBindingCommitment,
  deriveGovernancePolicySnapshot,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  createAuditorScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
} from "../../../trust-registry-integration/src/index.js";

import {
  bytes32Commitment,
  TrustRegistrySimulatorClient,
  verifyTrustRegistryEvidenceBundle,
} from "../index.js";

const changeLastHexNibble = (hash: string): string =>
  `${hash.slice(0, -1)}${hash.endsWith("0") ? "1" : "0"}`;

describe("trust registry client", () => {
  it("rejects every raw record read if the ledger format changes after construction", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    expect(Reflect.get(client, "simulator")).toBeUndefined();
    const ledger = harness.simulator.getLedger();
    const wrongFormat = vi.spyOn(harness.simulator, "getLedger").mockImplementation(() => ({
      ...ledger,
      contractVersion: 2n,
    }));
    const id = new Uint8Array(32);
    const request = {
      subjectDid: id,
      requestProfileId: id,
      allowedAttributeSetCommitment: id,
      allowedPredicateSetCommitment: id,
      disclosureLevelCommitment: id,
    };
    try {
      const reads = [
        () => client.getIssuerAuthorizationById(id),
        () => client.getCurrentIssuerAuthorization({ subjectDid: id, resourceType: createIssuerScenarioFixture("format").resourceType, resourceId: id }),
        () => client.getVerifierAuthorizationById(id),
        () => client.getCurrentVerifierAuthorization(request),
        () => client.getAuditorAuthorizationById(id),
        () => client.getCurrentAuditorAuthorization(request),
        () => client.getRecognitionById(id),
        () => client.getCurrentRecognition({ recognizedAuthorityDid: id, recognizedRegistryId: id, scopeResourceType: id, scopeResourceId: id }),
        () => client.getEpochCommitmentById(id),
        () => client.getCurrentEpochCommitment(),
        () => client.getMaintainerMembershipById(id),
        () => client.getCurrentMaintainerMembership(id),
        () => client.getMaintainerRecordByKeyId(id),
      ];
      for (const read of reads) {
        expect(read).toThrow(/Unsupported trust registry format/);
      }
    } finally {
      wrongFormat.mockRestore();
    }
  });

  it("queries current and historical issuer state plus the published epoch anchor", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("degree");

    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);

    expect(bundle.epoch.policyRoot).toBe(
      computeGovernancePolicySnapshotCommitment(
        deriveGovernancePolicySnapshot(bundle.policy),
      ),
    );
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
    expect(activeBundle.statusPolicyBinding).toBeDefined();
    expect(activeBundle.authorization?.statusPolicyBindingCommitment).toBe(
      computeIssuerStatusPolicyBindingCommitment(activeBundle.statusPolicyBinding!),
    );

    expect(() => client.verifyIssuerAuthorizationBundle({
      ...activeBundle,
      statusPolicyBinding: undefined,
    }, { expectedRegistryId: harness.registryId })).toThrow(/preimage is missing/i);
    expect(() => client.verifyIssuerAuthorizationBundle({
      ...activeBundle,
      statusPolicyBinding: {
        ...activeBundle.statusPolicyBinding!,
        statusRegistryId: `0x${"9".repeat(64)}`,
      },
    }, { expectedRegistryId: harness.registryId })).toThrow(/does not match governed authorization/i);
    const epochRecord = client.getEpochCommitmentById(activeBundle.epoch.epochId);
    const maintainerRecord = client.getMaintainerRecordByKeyId(epochRecord.maintainerKeyId);
    expect(() => verifyTrustRegistryEvidenceBundle({
      ...activeBundle,
      statusPolicyBinding: {
        ...activeBundle.statusPolicyBinding!,
        statusAuthorityVerificationMethod: "did:midnight:attacker#status-1",
      },
    }, {
      expectedRegistryId: harness.registryId,
      epochRecord,
      maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
      registryIdCommitment: bytes32Commitment(harness.registryId),
    })).toThrow(/does not match governed authorization/i);
    expect(() => client.verifyIssuerAuthorizationBundle({
      ...activeBundle,
      referencedStatusRegistryId: "status-registry:attacker:v1",
    }, { expectedRegistryId: harness.registryId })).toThrow(/unanchored issuer status metadata/i);
    expect(() => client.verifyIssuerAuthorizationBundle({
      ...activeBundle,
      authorization: {
        ...activeBundle.authorization!,
        statusPolicyBindingCommitment: `0x${"8".repeat(64)}`,
      },
    }, { expectedRegistryId: harness.registryId })).toThrow(/leaf hash/i);

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
            leafHash: changeLastHexNibble(activeBundle.inclusionProof.leafHash),
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
            path: [changeLastHexNibble(activeBundle.inclusionProof.path[0]!)],
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

  it("rejects an epoch record missing its publication policy commitment", () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("missing-policy-epoch");
    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    const epochRecord = client.getEpochCommitmentById(bundle.epoch.epochId);
    const maintainerRecord = client.getMaintainerRecordByKeyId(epochRecord.maintainerKeyId);

    expect(() => verifyTrustRegistryEvidenceBundle(bundle, {
      epochRecord: { ...epochRecord, publicationPolicyCommitment: undefined as never },
      maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
      registryIdCommitment: bytes32Commitment(harness.registryId),
    })).toThrow(/Epoch publication policy commitment is missing or malformed/);
    expect(() => verifyTrustRegistryEvidenceBundle(bundle, {
      epochRecord: { ...epochRecord, publicationPolicyCommitment: new Uint8Array(32) },
      maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
      registryIdCommitment: bytes32Commitment(harness.registryId),
    })).toThrow(/Epoch publication policy commitment is missing or malformed/);
    expect(() => verifyTrustRegistryEvidenceBundle(bundle, {
      epochRecord,
      maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
      registryIdCommitment: new Uint8Array(31),
    })).toThrow(/Registry ID commitment is missing or malformed/);
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
    const extraSignatures = [originalSignature, {
      ...originalSignature,
      keyId: "did:midnight:untrusted#key-2",
    }] as unknown as
      typeof bundle.epoch.maintainerSignatures;
    let cardinalityError: unknown;
    try {
      client.verifyIssuerAuthorizationBundle({
        ...bundle,
        epoch: {
          ...bundle.epoch,
          maintainerSignatures: extraSignatures,
        },
      }, {});
    } catch (error) {
      cardinalityError = error;
    }
    expect(cardinalityError).toHaveProperty("issues", expect.arrayContaining([
      expect.objectContaining({ code: "too_big", path: ["epoch", "maintainerSignatures"] }),
    ]));
    let missingSignatureError: unknown;
    try {
      client.verifyIssuerAuthorizationBundle({
        ...bundle,
        epoch: {
          ...bundle.epoch,
          maintainerSignatures: [] as unknown as typeof bundle.epoch.maintainerSignatures,
        },
      }, {});
    } catch (error) {
      missingSignatureError = error;
    }
    expect(missingSignatureError).toHaveProperty("issues", expect.arrayContaining([
      expect.objectContaining({ code: "too_small", path: ["epoch", "maintainerSignatures"] }),
    ]));
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
          epoch: {
            ...bundle.epoch,
            maintainerSignatures: [{
              ...originalSignature,
              signature: `0x${"00".repeat(96)}`,
            }],
          },
        },
        {},
      ),
    ).toThrow("Epoch maintainer signature is invalid");

    for (const malformed of [
      originalSignature.signature.slice(0, -1),
      originalSignature.signature.toUpperCase(),
      `${originalSignature.signature.slice(0, -1)}g`,
    ]) {
      let encodingError: unknown;
      try {
        client.verifyIssuerAuthorizationBundle({
          ...bundle,
          epoch: {
            ...bundle.epoch,
            maintainerSignatures: [{ ...originalSignature, signature: malformed }],
          },
        }, {});
      } catch (error) {
        encodingError = error;
      }
      expect(encodingError).toHaveProperty("message", "Epoch maintainer signature encoding is invalid");
      expect(encodingError).toHaveProperty("cause.message", "Jubjub signature encoding is invalid");
    }

    expect(() => client.verifyIssuerAuthorizationBundle({
      ...bundle,
      epoch: {
        ...bundle.epoch,
        maintainerSignatures: [{ ...originalSignature, algorithm: "ed25519" }],
      },
    }, {})).toThrow(/signature algorithm is unsupported/);

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

    expect(() =>
      client.verifyIssuerAuthorizationBundle(
        {
          ...bundle,
          policy: {
            ...bundle.policy,
            decisionRules: [...bundle.policy.decisionRules, "unauthorized rule"],
          },
        },
        {},
      ),
    ).toThrow(/policy root/i);
  });
});
