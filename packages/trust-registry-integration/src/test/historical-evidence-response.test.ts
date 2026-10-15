import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import type { Ledger } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import {
  bytes32Commitment,
  defaultSequenceToTimestamp,
  verifyHistoricalAuthorizationEvidenceFromApi,
  verifyHistoricalAuthorizationEvidenceResponse,
  verifyHistoricalRecognitionEvidenceFromApi,
  verifyHistoricalRecognitionEvidenceResponse,
  verifyTrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-client";
import { resolveCompactHistoricalEpochAnchor } from "../compact-historical-anchor.js";
import { createIssuerScenarioFixture, createRecognitionScenarioFixture } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("historical native evidence responses", () => {
  it("rejects substituted finalized Compact format, policy, and publication signer", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("historical-anchor-ledger");
    const issuer = createIssuerScenarioFixture("historical-anchor-ledger");
    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);
    const ledger = harness.simulator.getLedger();
    const epoch = ledger.epochCommitmentRecords.lookup(bytes32Commitment(bundle.epoch.epochId));
    const signer = ledger.maintainerRecords.lookup(epoch.maintainerKeyId);
    const input = {
      ledger, registryId: harness.registryId, epochId: bundle.epoch.epochId,
      policyVersion: bundle.policy.version, sequenceToTimestamp: defaultSequenceToTimestamp,
      expectedNetworkId: harness.registryDid.split(":")[2]!,
      contractAddress: Buffer.from(harness.simulator.contractAddress, "hex"),
    };
    expect(() => resolveCompactHistoricalEpochAnchor({
      ...input, contractAddress: new Uint8Array(31),
    })).toThrow(/Contract address is missing or malformed/u);
    expect(() => resolveCompactHistoricalEpochAnchor({
      ...input, contractAddress: new Uint8Array(32),
    })).toThrow(/Contract address is missing or malformed/u);
    expect(() => resolveCompactHistoricalEpochAnchor({
      ...input, ledger: { ...ledger, deploymentNetworkIdCommitment: new Uint8Array(31) } as Ledger,
    })).toThrow(/Deployment network ID commitment is missing or malformed/u);
    expect(() => resolveCompactHistoricalEpochAnchor({
      ...input, ledger: { ...ledger, deploymentNetworkIdCommitment: new Uint8Array(32) } as Ledger,
    })).toThrow(/Deployment network ID commitment is missing or malformed/u);
    expect(() => resolveCompactHistoricalEpochAnchor({
      ...input, expectedNetworkId: "preview",
    })).toThrow(/Historical network ID does not match/u);
    expect(() => resolveCompactHistoricalEpochAnchor({
      ...input, ledger: { ...ledger, contractVersion: 2n } as Ledger,
    })).toThrow(/Unsupported trust registry format/u);
    expect(() => resolveCompactHistoricalEpochAnchor({
      ...input, ledger: {
        ...ledger,
        governancePolicyCommitmentsByVersion: {
          member: () => true, lookup: () => new Uint8Array(32),
        },
      } as unknown as Ledger,
    })).toThrow(/policy root/u);
    expect(() => resolveCompactHistoricalEpochAnchor({
      ...input, ledger: {
        ...ledger,
        maintainerRecords: {
          member: () => true,
          lookup: () => ({ ...signer, keyId: new Uint8Array(32) }),
        },
      } as unknown as Ledger,
    })).toThrow(/publication signer/u);
    expect(() => resolveCompactHistoricalEpochAnchor({
      ...input, ledger: {
        ...ledger,
        maintainerRecords: {
          member: () => true,
          lookup: () => ({ ...signer, joinedAtSequence: epoch.publishedAtSequence + 1n }),
        },
      } as unknown as Ledger,
    })).toThrow(/publication signer/u);
  });

  it("verifies an archived issuer claim against an independent signed epoch anchor", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("historical-native-issuer");
    const issuer = createIssuerScenarioFixture("degree");
    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);
    if (bundle.authorization === undefined) throw new Error("expected issuer bundle");
    const authorization = bundle.authorization;
    const anchorInput = {
      ledger: harness.simulator.getLedger(), registryId: harness.registryId,
      epochId: bundle.epoch.epochId, policyVersion: bundle.policy.version,
      sequenceToTimestamp: defaultSequenceToTimestamp,
      expectedNetworkId: harness.registryDid.split(":")[2]!,
      contractAddress: Buffer.from(harness.simulator.contractAddress, "hex"),
    };
    const anchor = resolveCompactHistoricalEpochAnchor(anchorInput);
    expect(anchor.networkIdCommitment).toEqual(anchorInput.ledger.deploymentNetworkIdCommitment);
    expect(anchor.contractAddress).toEqual(Uint8Array.from(anchorInput.contractAddress));
    const { epochRecord } = anchor;
    expect(() => resolveCompactHistoricalEpochAnchor({
      ...anchorInput, registryId: `${harness.registryId}:other`,
    })).toThrow(/registry ID/u);
    expect(() => resolveCompactHistoricalEpochAnchor({
      ...anchorInput, epochId: `${bundle.epoch.epochId}:other`,
    })).toThrow(/epoch is absent/u);
    expect(() => resolveCompactHistoricalEpochAnchor({
      ...anchorInput, policyVersion: "v2",
    })).toThrow(/policy root/u);
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
    expect(() => verifyHistoricalAuthorizationEvidenceResponse(response, selection,
      resolveCompactHistoricalEpochAnchor({
        ...anchorInput, contractAddress: Uint8Array.from({ length: 32 }, () => 1),
      }))).toThrow(/signature/u);
    expect(() => verifyHistoricalAuthorizationEvidenceResponse(response, selection,
      resolveCompactHistoricalEpochAnchor({
        ...anchorInput,
        expectedNetworkId: "different-network",
        ledger: {
          ...anchorInput.ledger,
          deploymentNetworkIdCommitment: bytes32Commitment("different-network"),
        } as Ledger,
      }))).toThrow(/signature/u);
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
    harness.suspendIssuer(issuer);
    const laterBundle = harness.buildIssuerHistoricalEvidence(issuer);
    const laterAnchor = resolveCompactHistoricalEpochAnchor({
      ledger: harness.simulator.getLedger(), registryId: harness.registryId,
      epochId: laterBundle.epoch.epochId, policyVersion: laterBundle.policy.version,
      sequenceToTimestamp: defaultSequenceToTimestamp,
      expectedNetworkId: harness.registryDid.split(":")[2]!,
      contractAddress: Buffer.from(harness.simulator.contractAddress, "hex"),
    });
    expect(() => verifyHistoricalAuthorizationEvidenceResponse(response, selection, laterAnchor))
      .toThrow(/Epoch id mismatch/u);
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
    const anchor = resolveCompactHistoricalEpochAnchor({
      ledger: harness.simulator.getLedger(), registryId: harness.registryId,
      epochId: bundle.epoch.epochId, policyVersion: bundle.policy.version,
      sequenceToTimestamp: defaultSequenceToTimestamp,
      expectedNetworkId: harness.registryDid.split(":")[2]!,
      contractAddress: Buffer.from(harness.simulator.contractAddress, "hex"),
    });
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
