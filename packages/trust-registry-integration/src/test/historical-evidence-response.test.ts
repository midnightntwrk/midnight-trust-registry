import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import { describe, expect, it } from "vitest";

import {
  bytes32Commitment,
  verifyHistoricalAuthorizationEvidenceResponse,
  verifyHistoricalRecognitionEvidenceResponse,
  verifyTrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-client";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";

import { createIssuerScenarioFixture, createRecognitionScenarioFixture } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("historical native evidence responses", () => {
  it("verifies an archived issuer claim against an independent signed epoch anchor", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("historical-native-issuer");
    const issuer = createIssuerScenarioFixture("degree");
    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);
    if (bundle.authorization === undefined) throw new Error("expected issuer bundle");
    const authorization = bundle.authorization;
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    const epochRecord = client.getEpochCommitmentById(bundle.epoch.epochId);
    const maintainer = client.getMaintainerRecordByKeyId(epochRecord.maintainerKeyId);
    const anchor = {
      epochRecord,
      maintainerPublicKey: maintainer.publicKey as JubjubPoint,
      registryIdCommitment: bytes32Commitment(harness.registryId),
    };
    const selection = {
      role: "issuer" as const,
      subjectDid: issuer.subjectDid,
      resourceId: issuer.resourceId,
      resourceType: authorization.resourceType,
      at: bundle.epoch.validFrom,
    };
    const response = {
      evaluatedAt: selection.at,
      statusAtTime: "active",
      trustedAtTime: true,
      epoch: bundle.epoch,
      entry: { authorization },
      bundle,
    };

    expect(verifyHistoricalAuthorizationEvidenceResponse(response, selection, anchor).trustedAtTime).toBe(true);
    expect(() => verifyHistoricalAuthorizationEvidenceResponse(response, {
      ...selection, resourceId: `${selection.resourceId}:other`,
    }, anchor)).toThrow(/scope mismatch/u);
    expect(() => verifyHistoricalAuthorizationEvidenceResponse({
      ...response, trustedAtTime: false,
    }, selection, anchor)).toThrow(/decision mismatch/u);
    expect(() => verifyHistoricalAuthorizationEvidenceResponse({
      ...response,
      entry: { authorization: { ...authorization, evidenceHash: `0x${"0".repeat(64)}` } },
    }, selection, anchor)).toThrow(/entry mismatch/u);
    expect(() => verifyHistoricalAuthorizationEvidenceResponse({
      ...response,
      epoch: { ...bundle.epoch, maintainerSignatures: [{
        ...bundle.epoch.maintainerSignatures[0]!, keyId: "did:midnight:substituted#key-1",
      }] },
    }, selection, anchor)).toThrow(/response epoch mismatch/u);
    expect(() => verifyTrustRegistryEvidenceBundle({
      ...bundle,
      authorization: { ...authorization, policyId: "policy:substituted" },
    }, anchor)).toThrow(/policy ID does not match/u);
    const wrongRoot = { ...bundle.epoch, stateRoot: `0x${"0".repeat(64)}` };
    expect(() => verifyHistoricalAuthorizationEvidenceResponse({
      ...response, epoch: wrongRoot, bundle: { ...bundle, epoch: wrongRoot },
    }, selection, anchor)).toThrow(/state root mismatch/u);
    const signature = bundle.epoch.maintainerSignatures[0]!;
    const wrongSignature = `${signature.signature.slice(0, -1)}${signature.signature.endsWith("a") ? "b" : "a"}`;
    const wrongSignerEpoch = {
      ...bundle.epoch,
      maintainerSignatures: [{ ...signature, signature: wrongSignature }],
    };
    expect(() => verifyHistoricalAuthorizationEvidenceResponse({
      ...response, epoch: wrongSignerEpoch, bundle: { ...bundle, epoch: wrongSignerEpoch },
    }, selection, anchor)).toThrow(/signature/u);
  });

  it("verifies an exact-scope recognition claim and rejects registry substitution", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("historical-native-recognition");
    const recognition = createRecognitionScenarioFixture("gaia-x");
    harness.authorizeRecognition(recognition);
    const bundle = harness.evaluateCurrentRecognitionDecision(recognition);
    if (bundle.recognition === undefined) throw new Error("expected recognition bundle");
    const record = bundle.recognition;
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    const epochRecord = client.getEpochCommitmentById(bundle.epoch.epochId);
    const maintainer = client.getMaintainerRecordByKeyId(epochRecord.maintainerKeyId);
    const anchor = {
      epochRecord,
      maintainerPublicKey: maintainer.publicKey as JubjubPoint,
      registryIdCommitment: bytes32Commitment(harness.registryId),
    };
    const selection = {
      recognizedAuthorityDid: record.recognizedAuthorityDid,
      recognizedRegistryId: record.recognizedRegistryId,
      scopeResourceType: record.scope.resourceType,
      scopeResourceId: record.scope.resourceId,
      at: bundle.epoch.validFrom,
    };
    const response = {
      evaluatedAt: selection.at,
      statusAtTime: "active",
      trustedAtTime: true,
      epoch: bundle.epoch,
      entry: { recognition: record },
      bundle,
    };

    expect(verifyHistoricalRecognitionEvidenceResponse(response, selection, anchor).trustedAtTime).toBe(true);
    expect(() => verifyHistoricalRecognitionEvidenceResponse(response, {
      ...selection, recognizedRegistryId: "registry:substituted",
    }, anchor)).toThrow(/scope mismatch/u);
    expect(() => verifyHistoricalRecognitionEvidenceResponse({
      ...response,
      bundle: {
        ...bundle,
        recognition: {
          ...record,
          scope: { ...record.scope, context: { purpose: "other" } },
        },
      },
    }, selection, anchor)).toThrow(/scope mismatch/u);
  });
});
