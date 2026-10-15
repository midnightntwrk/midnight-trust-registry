import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import { describe, expect, it } from "vitest";

import {
  bytes32Commitment,
  verifyHistoricalAuthorizationEvidenceFromApi,
  verifyHistoricalAuthorizationEvidenceResponse,
  verifyHistoricalRecognitionEvidenceFromApi,
  verifyHistoricalRecognitionEvidenceResponse,
  verifyTrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-client";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";

import { createIssuerScenarioFixture, createRecognitionScenarioFixture } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("historical native evidence responses", () => {
  it("verifies an archived issuer claim against an independent signed epoch anchor", async () => {
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
    }, selection, anchor)).not.toThrow();
    expect(() => verifyHistoricalAuthorizationEvidenceResponse({
      ...response,
      entry: { authorization: { ...authorization, policyId: "policy:substituted" } },
    }, selection, anchor)).toThrow(/entry mismatch/u);
    expect(() => verifyHistoricalAuthorizationEvidenceResponse({
      ...response,
      bundle: { ...bundle, authorization: { ...authorization, evidenceHash: `0x${"0".repeat(64)}` } },
    }, selection, anchor)).toThrow();
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

    const fetchImpl: typeof fetch = async (input, init) => {
      expect(String(input)).toBe("https://registry.example/v1/authorizations/evaluate/evidence");
      expect(init).toMatchObject({
        method: "POST", cache: "no-store", redirect: "error", body: JSON.stringify(selection),
      });
      return new Response(JSON.stringify(response), { status: 200 });
    };
    expect((await verifyHistoricalAuthorizationEvidenceFromApi(
      "https://registry.example", selection, anchor, fetchImpl,
    )).trustedAtTime).toBe(true);
    await expect(verifyHistoricalAuthorizationEvidenceFromApi(
      "https://registry.example", selection, { ...anchor, epochRecord: {
        ...epochRecord, stateRoot: new Uint8Array(32),
      } }, fetchImpl,
    )).rejects.toThrow(/state root mismatch/u);
    await expect(verifyHistoricalAuthorizationEvidenceFromApi(
      "http://registry.example", selection, anchor, fetchImpl,
    )).rejects.toThrow(/HTTPS or loopback/u);
    await expect(verifyHistoricalAuthorizationEvidenceFromApi(
      "https://registry.example", selection, anchor,
      async () => new Response("{}", { status: 424 }),
    )).rejects.toThrow(/unavailable \(424\)/u);
    await expect(verifyHistoricalAuthorizationEvidenceFromApi(
      "https://registry.example", selection, anchor,
      async () => new Response("{}", { status: 404 }),
    )).rejects.toThrow(/unavailable \(404\)/u);
    await expect(verifyHistoricalAuthorizationEvidenceFromApi(
      "https://registry.example", selection, anchor,
      async (_input, init) => {
        expect(init?.redirect).toBe("error");
        return new Response(null, { status: 302, headers: { location: "https://other.example" } });
      },
    )).rejects.toThrow(/unavailable \(302\)/u);
  });

  it("verifies an exact-scope recognition claim and rejects registry substitution", async () => {
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
    expect(() => verifyHistoricalRecognitionEvidenceResponse({
      ...response,
      entry: { recognition: { ...record, evidenceHash: `0x${"0".repeat(64)}` } },
    }, selection, anchor)).not.toThrow();
    expect(() => verifyHistoricalRecognitionEvidenceResponse({
      ...response,
      entry: { recognition: { ...record, policyId: "policy:substituted" } },
    }, selection, anchor)).toThrow(/entry mismatch/u);
    expect(() => verifyHistoricalRecognitionEvidenceResponse({
      ...response,
      bundle: { ...bundle, recognition: { ...record, evidenceHash: `0x${"0".repeat(64)}` } },
    }, selection, anchor)).toThrow();
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
    const fetchImpl: typeof fetch = async (input, init) => {
      expect(String(input)).toBe("http://127.0.0.1:4400/v1/recognitions/evaluate/evidence");
      expect(init).toMatchObject({ method: "POST", cache: "no-store", redirect: "error" });
      return new Response(JSON.stringify(response), { status: 200 });
    };
    expect((await verifyHistoricalRecognitionEvidenceFromApi(
      "http://127.0.0.1:4400", selection, anchor, fetchImpl,
    )).trustedAtTime).toBe(true);
    await expect(verifyHistoricalRecognitionEvidenceFromApi(
      "http://registry.example", selection, anchor, fetchImpl,
    )).rejects.toThrow(/HTTPS or loopback/u);
  });
});
