import { describe, expect, it, vi } from "vitest";
import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";

import {
  computeGovernancePolicySnapshotCommitment,
  computeIssuerStatusPolicyBindingCommitment,
  deriveGovernancePolicySnapshot,
} from "@midnightntwrk/trust-registry-domain";

import {
  createAuditorAuthorizationScopeFixture,
  createAuditorScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
} from "../../../trust-registry-integration/src/index.js";

import {
  bytes32Commitment,
  verifyTrustRegistryEvidenceBundle,
} from "../index.js";
import { TrustRegistrySimulatorClient } from "../simulator-client.js";
import { defaultSequenceToTimestamp, hashHexToBytes32 } from "../utils.js";
import * as ClientRoot from "../index.js";

const changeLastHexNibble = (hash: string): string =>
  `${hash.slice(0, -1)}${hash.endsWith("0") ? "1" : "0"}`;

describe("trust registry client", () => {
  it("verifies an exact auditor mandate without granting data access", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("audit-mandate-check");
    const auditor = createAuditorScenarioFixture("audit-mandate-check");
    const verifier = createVerifierScenarioFixture("audit-mandate-check");
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    await harness.authorizeAuditor(auditor);
    await harness.authorizeVerifier(verifier);
    const scope = createAuditorAuthorizationScopeFixture(auditor);
    const bundle = await harness.evaluateCurrentAuditorDecision(auditor);
    const options = {
      expectedRegistryId: harness.registryId,
      expectedSubjectDid: auditor.subjectDid,
      evaluationTime: bundle.generatedAt,
    };
    const mandate = await client.verifyAuditorRequestMandate(bundle, scope, options);
    expect(mandate).toEqual({
      authorizationId: auditor.authorizationId,
      auditorDid: auditor.subjectDid,
      requestResourceId: auditor.scopeResourceId,
      scopeCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
      epochId: bundle.epoch.epochId,
    });
    for (const changed of [
      { ...scope, purpose: "unapproved-audit-purpose" },
      { ...scope, allowedAttributes: [...scope.allowedAttributes, "audit-attribute-set:extra"] },
      { ...scope, allowedPredicates: [...scope.allowedPredicates, "audit-predicate-set:extra"] },
      { ...scope, disclosureLevel: "audit-disclosure-level:unrestricted" },
    ]) {
      await expect(client.verifyAuditorRequestMandate(bundle, changed, options))
        .rejects.toThrow(/resource mismatch/u);
    }
    await expect(client.verifyAuditorRequestMandate(bundle, scope, {
      ...options, expectedRegistryId: "registry:wrong",
    })).rejects.toThrow(/registry mismatch/u);
    await expect(client.verifyAuditorRequestMandate(bundle, scope, {
      ...options, expectedSubjectDid: verifier.subjectDid,
    })).rejects.toThrow(/Subject DID mismatch/u);
    await expect(client.verifyAuditorRequestMandate(bundle, scope, {
      ...options, expectedRegistryId: undefined as unknown as string,
    })).rejects.toThrow(/requires expected registry/u);
    await expect(client.verifyAuditorRequestMandate(bundle, scope, {
      ...options, expectedSubjectDid: undefined as unknown as string,
    })).rejects.toThrow(/requires expected registry/u);
    await expect(client.verifyAuditorRequestMandate(bundle, scope, {
      ...options, evaluationTime: undefined as unknown as string,
    })).rejects.toThrow(/requires expected registry/u);
    const liveRecord = await harness.simulator.getAuditorAuthorization(auditor.authorizationIdCommitment);
    for (const [field, replacement, message] of [
      ["policyId", bytes32Commitment("policy:substituted"), /current governed policy mismatch/u],
      ["trustLevel", bytes32Commitment("trust-level:substituted"), /current trust level mismatch/u],
      ["lifecycleEventHash", new Uint8Array(32), /current lifecycle event mismatch/u],
    ] as const) {
      const changed = vi.spyOn(harness.simulator, "getAuditorAuthorization")
        .mockResolvedValue({ ...liveRecord, [field]: replacement });
      try {
        await expect(client.verifyAuditorRequestMandate(bundle, scope, options)).rejects.toThrow(message);
      } finally {
        changed.mockRestore();
      }
    }
    await expect(client.verifyAuditorRequestMandate(
      await harness.evaluateCurrentVerifierDecision(verifier), scope, options,
    )).rejects.toThrow();
    await harness.suspendAuditor(auditor);
    await expect(client.verifyAuditorRequestMandate(bundle, scope, options))
      .rejects.toThrow(/not active in current ledger state/u);
    const suspendedBundle = await harness.buildAuditorHistoricalEvidence(auditor);
    await expect(client.verifyAuditorRequestMandate(
      suspendedBundle, scope, { ...options, evaluationTime: suspendedBundle.generatedAt },
    )).rejects.toThrow(/not active/u);
    await harness.revokeAuditor(auditor);
    await expect(client.verifyAuditorRequestMandate(bundle, scope, options))
      .rejects.toThrow(/not active in current ledger state/u);
  }, 30_000);

  it("keeps simulator helpers out of the production root", () => {
    expect(ClientRoot).not.toHaveProperty("TrustRegistrySimulatorClient");
    expect(TrustRegistrySimulatorClient).toBeDefined();
  });
  it("rejects every raw record read if the ledger format changes after construction", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    expect(Reflect.get(client, "simulator")).toBeUndefined();
    await harness.ready;
    const ledger = await harness.simulator.getLedger();
    const wrongFormat = vi.spyOn(harness.simulator, "getLedger").mockImplementation(async () => ({
      ...ledger,
      contractVersion: 2n,
    }));
    const id = new Uint8Array(32);
    const request = {
      subjectDid: id,
      requestResourceId: id,
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
        await expect(read()).rejects.toThrow(/Unsupported trust registry format/);
      }
    } finally {
      wrongFormat.mockRestore();
    }
  }, 20_000);

  it("queries current and historical issuer state plus the published epoch anchor", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("degree");

    await harness.authorizeIssuer(issuer);
    const bundle = await harness.evaluateCurrentIssuerDecision(issuer);

    expect(bundle.epoch.policyRoot).toBe(
      computeGovernancePolicySnapshotCommitment(
        deriveGovernancePolicySnapshot(bundle.policy),
      ),
    );
    const client = new TrustRegistrySimulatorClient(harness.simulator);

    const currentRecord = await client.getCurrentIssuerAuthorization({
      subjectDid: issuer.subjectDid,
      resourceType: issuer.resourceType,
      resourceId: issuer.resourceId,
    });
    const historicalRecord = await client.getIssuerAuthorizationById(issuer.authorizationId);
    const epochRecord = await client.getEpochCommitmentById(bundle.epoch.epochId);

    expect(currentRecord.status).toEqual(historicalRecord.status);
    expect(epochRecord.validFromSequence).toBeGreaterThanOrEqual(0n);
  });

  it("verifies an active issuer bundle and rejects wrong-registry or revoked evidence", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("passport");

    await harness.authorizeIssuer(issuer);
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    const activeBundle = await harness.evaluateCurrentIssuerDecision(issuer);

    await expect(
      client.verifyIssuerAuthorizationBundle(activeBundle, {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: issuer.subjectDid,
        expectedResourceId: issuer.resourceId,
      }),
    ).resolves.toBeDefined();
    expect(activeBundle.inclusionProof.proofType).toBe("merkle-inclusion");
    expect(activeBundle.inclusionProof.root).toBe(activeBundle.epoch.stateRoot);
    expect(activeBundle.inclusionProof.path[0]).toBe(activeBundle.epoch.eventRoot);
    expect(activeBundle.statusPolicyBinding).toBeDefined();
    expect(activeBundle.authorization?.statusPolicyBindingCommitment).toBe(
      computeIssuerStatusPolicyBindingCommitment(activeBundle.statusPolicyBinding!),
    );

    await expect(client.verifyIssuerAuthorizationBundle({
      ...activeBundle,
      statusPolicyBinding: undefined,
    }, { expectedRegistryId: harness.registryId })).rejects.toThrow(/preimage is missing/i);
    await expect(client.verifyIssuerAuthorizationBundle({
      ...activeBundle,
      statusPolicyBinding: {
        ...activeBundle.statusPolicyBinding!,
        statusRegistryId: `0x${"9".repeat(64)}`,
      },
    }, { expectedRegistryId: harness.registryId })).rejects.toThrow(/does not match governed authorization/i);
    const epochRecord = await client.getEpochCommitmentById(activeBundle.epoch.epochId);
    const maintainerRecord = await client.getMaintainerRecordByKeyId(epochRecord.maintainerKeyId);
    const deploymentContext = {
      networkIdCommitment: (await harness.simulator.getLedger()).deploymentNetworkIdCommitment,
      contractAddress: hashHexToBytes32(harness.simulator.contractAddress),
    };
    const equivalentEpochSpelling = {
      ...activeBundle,
      epoch: {
        ...activeBundle.epoch,
        validFrom: activeBundle.epoch.validFrom.replace(/Z$/, "+00:00"),
        validUntil: activeBundle.epoch.validUntil.replace(/Z$/, "+00:00"),
      },
    };
    await expect(client.verifyIssuerAuthorizationBundle(equivalentEpochSpelling, {})).resolves.toBeDefined();
    const tamperedEpochRegistry = {
      ...activeBundle,
      epoch: { ...activeBundle.epoch, registryId: "registry:evil" },
    };
    await expect(client.verifyIssuerAuthorizationBundle(tamperedEpochRegistry, {}))
      .rejects.toThrow(/Epoch registry mismatch/);
    expect(() => verifyTrustRegistryEvidenceBundle(tamperedEpochRegistry, {
      ...deploymentContext,
      epochRecord,
      maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
      registryIdCommitment: bytes32Commitment(harness.registryId),
    })).toThrow(/Epoch registry mismatch/);
    await expect(client.verifyIssuerAuthorizationBundle({
      ...activeBundle,
      registryId: undefined as never,
    }, {})).rejects.toThrow(/Bundle registry ID is missing or malformed/);
    await expect(client.verifyIssuerAuthorizationBundle({
      ...activeBundle,
      authorization: { ...activeBundle.authorization!, registryId: "registry:evil" },
    }, {})).rejects.toThrow(/Authorization registry mismatch/);
    const tamperedRegistry = {
      ...activeBundle,
      registryId: "registry:evil",
      epoch: { ...activeBundle.epoch, registryId: "registry:evil" },
      authorization: { ...activeBundle.authorization!, registryId: "registry:evil" },
    };
    await expect(client.verifyIssuerAuthorizationBundle(tamperedRegistry, {}))
      .rejects.toThrow(/does not match the simulator ledger/);
    expect(() => verifyTrustRegistryEvidenceBundle(tamperedRegistry, {
      ...deploymentContext,
      epochRecord,
      maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
      registryIdCommitment: bytes32Commitment(harness.registryId),
    })).toThrow(/Registry ID commitment does not match/);
    expect(() => verifyTrustRegistryEvidenceBundle({
      ...activeBundle,
      statusPolicyBinding: {
        ...activeBundle.statusPolicyBinding!,
        statusAuthorityVerificationMethod: "did:midnight:attacker#status-1",
      },
    }, {
      ...deploymentContext,
      expectedRegistryId: harness.registryId,
      epochRecord,
      maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
      registryIdCommitment: bytes32Commitment(harness.registryId),
    })).toThrow(/does not match governed authorization/i);
    await expect(client.verifyIssuerAuthorizationBundle({
      ...activeBundle,
      referencedStatusRegistryId: "status-registry:attacker:v1",
    }, { expectedRegistryId: harness.registryId })).rejects.toThrow(/unanchored issuer status metadata/i);
    await expect(client.verifyIssuerAuthorizationBundle({
      ...activeBundle,
      authorization: {
        ...activeBundle.authorization!,
        statusPolicyBindingCommitment: `0x${"8".repeat(64)}`,
      },
    }, { expectedRegistryId: harness.registryId })).rejects.toThrow(/leaf hash/i);

    await expect(
      client.verifyIssuerAuthorizationBundle(activeBundle, {
        expectedRegistryId: "registry:other:trusted",
      }),
    ).rejects.toThrow(/mismatch/i);

    await harness.revokeIssuer(issuer);
    const revokedBundle = await harness.buildIssuerHistoricalEvidence(issuer);
    await expect(
      client.verifyIssuerAuthorizationBundle(revokedBundle, {
        expectedRegistryId: harness.registryId,
      }),
    ).rejects.toThrow(/not active/i);

    await expect(
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
    ).rejects.toThrow(/leaf hash/i);

    await expect(
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
    ).rejects.toThrow(/event sibling/i);

    await expect(
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
    ).rejects.toThrow(/anchored state root/i);

    await expect(
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
    ).rejects.toThrow(/reconstructed state root/i);

    await expect(
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
    ).rejects.toThrow(/invalid literal|merkle-inclusion/i);
  }, 20_000);

  it("rejects an epoch record missing its publication policy commitment", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("missing-policy-epoch");
    await harness.authorizeIssuer(issuer);
    const bundle = await harness.evaluateCurrentIssuerDecision(issuer);
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    const epochRecord = await client.getEpochCommitmentById(bundle.epoch.epochId);
    const maintainerRecord = await client.getMaintainerRecordByKeyId(epochRecord.maintainerKeyId);
    const deploymentContext = {
      networkIdCommitment: (await harness.simulator.getLedger()).deploymentNetworkIdCommitment,
      contractAddress: hashHexToBytes32(harness.simulator.contractAddress),
    };

    expect(() => verifyTrustRegistryEvidenceBundle(bundle, {
      ...deploymentContext,
      epochRecord: { ...epochRecord, publicationPolicyCommitment: undefined as never },
      maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
      registryIdCommitment: bytes32Commitment(harness.registryId),
    })).toThrow(/Epoch publication policy commitment is missing or malformed/);
    expect(() => verifyTrustRegistryEvidenceBundle(bundle, {
      ...deploymentContext,
      epochRecord: { ...epochRecord, publicationPolicyCommitment: new Uint8Array(32) },
      maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
      registryIdCommitment: bytes32Commitment(harness.registryId),
    })).toThrow(/Epoch publication policy commitment is missing or malformed/);
    for (const malformed of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(32), "not-bytes"]) {
      expect(() => verifyTrustRegistryEvidenceBundle(bundle, {
        ...deploymentContext,
        epochRecord,
        maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
        registryIdCommitment: malformed as never,
      })).toThrow(/Registry ID commitment is missing or malformed/);
    }

    let verifierFault: unknown;
    try {
      verifyTrustRegistryEvidenceBundle(bundle, {
        ...deploymentContext,
        epochRecord: { ...epochRecord, publishedAtSequence: "invalid" as never },
        maintainerPublicKey: maintainerRecord.publicKey as JubjubPoint,
        registryIdCommitment: bytes32Commitment(harness.registryId),
      });
    } catch (error) {
      verifierFault = error;
    }
    expect(verifierFault).toHaveProperty("message", "Epoch maintainer signature is invalid");
    expect((verifierFault as Error).cause).toBeInstanceOf(Error);
  });

  it("preserves issuer proposal and approval evidence while rejecting non-active decisions by default", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("application");
    const client = new TrustRegistrySimulatorClient(harness.simulator);

    await harness.proposeIssuer(issuer);
    const proposedBundle = await harness.buildIssuerHistoricalEvidence(issuer);
    await expect(
      client.verifyIssuerAuthorizationBundle(proposedBundle, {
        expectedRegistryId: harness.registryId,
      }),
    ).rejects.toThrow(/not active/i);
    await expect(
      client.verifyIssuerAuthorizationBundle(proposedBundle, {
        expectedRegistryId: harness.registryId,
        requireActive: false,
      }),
    ).resolves.toBeDefined();

    await harness.approveIssuer(issuer);
    const authorizedBundle = await harness.buildIssuerHistoricalEvidence(issuer);
    await expect(
      client.verifyIssuerAuthorizationBundle(authorizedBundle, {
        expectedRegistryId: harness.registryId,
      }),
    ).rejects.toThrow(/not active/i);
    await expect(
      client.verifyIssuerAuthorizationBundle(authorizedBundle, {
        expectedRegistryId: harness.registryId,
        requireActive: false,
      }),
    ).resolves.toBeDefined();
  });

  it("verifies active verifier, auditor, and recognition bundles", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const verifier = createVerifierScenarioFixture("age-gate");
    const auditor = createAuditorScenarioFixture("iso-27001");
    const recognition = createRecognitionScenarioFixture("gaia-x");
    const client = new TrustRegistrySimulatorClient(harness.simulator);

    await harness.authorizeVerifier(verifier);
    const verifierBundle = await harness.evaluateCurrentVerifierDecision(verifier);
    await expect(
      client.verifyVerifierAuthorizationBundle(verifierBundle, {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: verifier.subjectDid,
        expectedResourceId: verifier.scopeResourceId,
      }),
    ).resolves.toBeDefined();

    await harness.authorizeAuditor(auditor);
    const auditorBundle = await harness.evaluateCurrentAuditorDecision(auditor);
    await expect(
      client.verifyAuditorAuthorizationBundle(auditorBundle, {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: auditor.subjectDid,
        expectedResourceId: auditor.scopeResourceId,
      }),
    ).resolves.toBeDefined();

    await harness.authorizeRecognition(recognition);
    const recognitionBundle = await harness.evaluateCurrentRecognitionDecision(recognition);
    await expect(
      client.verifyRecognitionBundle(recognitionBundle, {
        expectedRegistryId: harness.registryId,
        expectedSubjectDid: recognition.recognizedAuthorityDid,
        expectedResourceId: recognition.scopeResourceId,
        expectedRecognizedRegistryId: recognition.recognizedRegistryId,
      }),
    ).resolves.toBeDefined();
    await expect(client.verifyRecognitionBundle({
      ...recognitionBundle,
      recognition: { ...recognitionBundle.recognition!, registryId: "registry:evil" },
    }, {})).rejects.toThrow(/Recognition registry mismatch/);
  });

  it("uses the supplied sequence clock for policy supersession across every simulator verifier", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("policy-clock");
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    const issuer = createIssuerScenarioFixture("policy-clock");
    const verifier = createVerifierScenarioFixture("policy-clock");
    const auditor = createAuditorScenarioFixture("policy-clock");
    const recognition = createRecognitionScenarioFixture("policy-clock");
    await harness.authorizeIssuer(issuer);
    const issuerBundle = await harness.evaluateCurrentIssuerDecision(issuer);
    await harness.authorizeVerifier(verifier);
    const verifierBundle = await harness.evaluateCurrentVerifierDecision(verifier);
    await harness.authorizeAuditor(auditor);
    const auditorBundle = await harness.evaluateCurrentAuditorDecision(auditor);
    await harness.authorizeRecognition(recognition);
    const recognitionBundle = await harness.evaluateCurrentRecognitionDecision(recognition);
    await harness.updateMaintainerThresholdPolicy(1n, 1n, 1n);

    const effectiveSequence = (await harness.simulator.getLedger()).governancePolicyEffectiveFromByVersion.lookup(2n);
    const defaultCutoffMs = Date.parse(defaultSequenceToTimestamp(effectiveSequence));
    const beforeDefaultCutoff = new Date(defaultCutoffMs - 60_000).toISOString();
    const afterDefaultCutoff = new Date(defaultCutoffMs + 60_000).toISOString();
    const earlyCutoff = new Date(defaultCutoffMs - 2 * 60_000).toISOString();
    const lateCutoff = new Date(defaultCutoffMs + 2 * 60_000).toISOString();
    const clockWithCutoff = (cutoff: string) => (sequence: bigint) =>
      sequence === effectiveSequence ? cutoff : defaultSequenceToTimestamp(sequence);
    const optionsFor = (evaluationTime: string, sequenceToTimestamp?: (sequence: bigint) => string) => ({
      evaluationTime,
      ...(sequenceToTimestamp === undefined ? {} : { sequenceToTimestamp }),
    });
    const verify = [
      (evaluationTime: string, sequenceToTimestamp?: (sequence: bigint) => string) =>
        client.verifyIssuerAuthorizationBundle(issuerBundle, optionsFor(evaluationTime, sequenceToTimestamp)),
      (evaluationTime: string, sequenceToTimestamp?: (sequence: bigint) => string) =>
        client.verifyVerifierAuthorizationBundle(verifierBundle, optionsFor(evaluationTime, sequenceToTimestamp)),
      (evaluationTime: string, sequenceToTimestamp?: (sequence: bigint) => string) =>
        client.verifyAuditorAuthorizationBundle(auditorBundle, optionsFor(evaluationTime, sequenceToTimestamp)),
      (evaluationTime: string, sequenceToTimestamp?: (sequence: bigint) => string) =>
        client.verifyRecognitionBundle(recognitionBundle, optionsFor(evaluationTime, sequenceToTimestamp)),
      (evaluationTime: string, sequenceToTimestamp?: (sequence: bigint) => string) =>
        client.verifyAuditorRequestMandate(auditorBundle, createAuditorAuthorizationScopeFixture(auditor), {
          expectedRegistryId: harness.registryId,
          expectedSubjectDid: auditor.subjectDid,
          ...optionsFor(evaluationTime, sequenceToTimestamp),
        }),
    ];
    for (const check of verify) {
      await expect(check(beforeDefaultCutoff)).resolves.toBeDefined();
      await expect(check(afterDefaultCutoff)).rejects.toThrow(/Policy snapshot is superseded/u);
      await expect(check(afterDefaultCutoff, clockWithCutoff(lateCutoff))).resolves.toBeDefined();
      await expect(check(beforeDefaultCutoff, clockWithCutoff(earlyCutoff)))
        .rejects.toThrow(/Policy snapshot is superseded/u);
    }
  }, 30_000);

  it("rejects stale epochs and tampered maintainer signatures deterministically", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("employment");
    const client = new TrustRegistrySimulatorClient(harness.simulator);

    await harness.authorizeIssuer(issuer);
    const bundle = await harness.evaluateCurrentIssuerDecision(issuer);

    await expect(
      client.verifyIssuerAuthorizationBundle(bundle, {
        evaluationTime: new Date(
          Date.parse(bundle.epoch.validUntil) + 60_000,
        ).toISOString(),
      }),
    ).rejects.toThrow(/stale/i);

    const originalSignature = bundle.epoch.maintainerSignatures[0];
    if (originalSignature === undefined) {
      throw new Error("expected epoch signature");
    }
    await expect(client.verifyIssuerAuthorizationBundle({
      ...bundle,
      epoch: {
        ...bundle.epoch,
        maintainerSignatures: [{
          ...originalSignature,
          keyId: originalSignature.keyId.replace(/#key-1$/u, "#key-2"),
        }],
      },
    }, {})).rejects.toThrow(/DID method does not match its accepted key commitment/u);
    const extraSignatures = [originalSignature, {
      ...originalSignature,
      keyId: "did:midnight:untrusted#key-2",
    }] as unknown as
      typeof bundle.epoch.maintainerSignatures;
    let cardinalityError: unknown;
    try {
      await client.verifyIssuerAuthorizationBundle({
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
      await client.verifyIssuerAuthorizationBundle({
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

    await expect(
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
    ).rejects.toThrow(/invalid/i);

    await expect(
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
    ).rejects.toThrow("Epoch maintainer signature encoding is invalid");

    for (const malformed of [
      originalSignature.signature.slice(0, -1),
      originalSignature.signature.toUpperCase(),
      `${originalSignature.signature.slice(0, -1)}g`,
    ]) {
      let encodingError: unknown;
      try {
        await client.verifyIssuerAuthorizationBundle({
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

    await expect(client.verifyIssuerAuthorizationBundle({
      ...bundle,
      epoch: {
        ...bundle.epoch,
        maintainerSignatures: [{ ...originalSignature, algorithm: "ed25519" }],
      },
    }, {})).rejects.toThrow(/signature algorithm is unsupported/);

    await expect(
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
    ).rejects.toThrow(/statement policy ID does not match/i);

    await expect(
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
    ).rejects.toThrow(/policy root/i);
  });
});
