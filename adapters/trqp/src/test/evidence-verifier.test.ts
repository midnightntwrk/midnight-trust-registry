import { describe, expect, it } from "vitest";

import { defaultSequenceToTimestamp } from "@midnight-ntwrk/trust-registry-client";
import {
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  resolveCompactHistoricalEpochAnchor,
} from "@midnight-ntwrk/trust-registry-integration";

import {
  verifyTrqpAuthorizationEvidenceFromApi,
  verifyTrqpRecognitionEvidenceFromApi,
} from "../evidence-http.js";
import {
  verifyTrqpAuthorizationEvidenceResponse,
  verifyTrqpRecognitionEvidenceResponse,
} from "../evidence-verifier.js";

describe("independent TRQP evidence verification", () => {
  it("accepts an issuer grant and rejects substituted tuple, time, decision, and anchor", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("trqp-verified-issuer");
    const issuer = createIssuerScenarioFixture("trqp-verified-issuer");
    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);
    const at = bundle.epoch.validFrom;
    const request = {
      entity_id: issuer.subjectDid,
      authority_id: harness.registryDid,
      action: "issue",
      resource: issuer.resourceId,
      context: { time: at },
    };
    const response = {
      ...request,
      time_requested: at,
      time_evaluated: at,
      authorized: true,
      bundle,
    };
    const anchor = resolveCompactHistoricalEpochAnchor({
      ledger: harness.simulator.getLedger(), registryId: harness.registryId,
      epochId: bundle.epoch.epochId, policyVersion: bundle.policy.version,
      sequenceToTimestamp: defaultSequenceToTimestamp,
    });
    expect(verifyTrqpAuthorizationEvidenceResponse(response, request, harness.registryDid, anchor))
      .toMatchObject({ authorized: true, statusAtTime: "active" });
    const fetchImpl: typeof fetch = async (input, init) => {
      expect(String(input)).toBe("http://127.0.0.1:4400/v1/trqp/authorizations/evidence");
      expect(init).toMatchObject({ method: "POST", cache: "no-store", redirect: "error" });
      expect(JSON.parse(String(init?.body))).toEqual(request);
      return new Response(JSON.stringify(response), { status: 200 });
    };
    expect((await verifyTrqpAuthorizationEvidenceFromApi(
      "http://127.0.0.1:4400", request, harness.registryDid, anchor, fetchImpl,
    )).authorized).toBe(true);
    await expect(verifyTrqpAuthorizationEvidenceFromApi(
      "http://registry.example", request, harness.registryDid, anchor, fetchImpl,
    )).rejects.toThrow(/HTTPS or loopback/u);
    await expect(verifyTrqpAuthorizationEvidenceFromApi(
      "https://registry.example", { ...request, authority_id: `${harness.registryDid}:other` },
      harness.registryDid, anchor, async () => { throw new Error("must not fetch"); },
    )).rejects.toThrow(/trusted configuration/u);
    await expect(verifyTrqpAuthorizationEvidenceFromApi(
      "https://registry.example", request, harness.registryDid, anchor,
      async () => new Response("{}", { status: 424 }),
    )).rejects.toThrow(/unavailable \(424\)/u);
    await expect(verifyTrqpAuthorizationEvidenceFromApi(
      "https://registry.example", request, harness.registryDid, anchor,
      async () => new Response(null, { status: 302, headers: { location: "https://other.example" } }),
    )).rejects.toThrow(/unavailable \(302\)/u);
    expect(() => verifyTrqpAuthorizationEvidenceResponse(response, {
      ...request, resource: `${request.resource}:other`,
    }, harness.registryDid, anchor)).toThrow(/trusted request/u);
    expect(() => verifyTrqpAuthorizationEvidenceResponse({
      ...response, resource: `${request.resource}:other`,
    }, { ...request, resource: `${request.resource}:other` }, harness.registryDid, anchor))
      .toThrow(/resource mismatch/u);
    expect(() => verifyTrqpAuthorizationEvidenceResponse({
      ...response, authorized: false,
    }, request, harness.registryDid, anchor)).toThrow(/decision/u);
    expect(() => verifyTrqpAuthorizationEvidenceResponse({
      ...response, time_evaluated: "2026-05-22T00:00:00Z",
    }, request, harness.registryDid, anchor)).toThrow(/trusted request/u);
    expect(() => verifyTrqpAuthorizationEvidenceResponse(response, {
      ...request, context: {},
    }, harness.registryDid, anchor)).toThrow(/explicit request time/u);
    expect(() => verifyTrqpAuthorizationEvidenceResponse(response, request,
      `${harness.registryDid}:other`, anchor)).toThrow(/trusted request/u);
    expect(() => verifyTrqpAuthorizationEvidenceResponse(response, request, harness.registryDid, {
      ...anchor, epochRecord: { ...anchor.epochRecord, stateRoot: new Uint8Array(32) },
    })).toThrow(/state root mismatch/u);

    harness.suspendIssuer(issuer);
    const suspended = harness.buildIssuerHistoricalEvidence(issuer);
    const suspendedAt = suspended.epoch.validFrom;
    const deniedRequest = { ...request, context: { time: suspendedAt } };
    const deniedResponse = {
      ...deniedRequest, time_requested: suspendedAt, time_evaluated: suspendedAt,
      authorized: false, bundle: suspended,
    };
    const deniedAnchor = resolveCompactHistoricalEpochAnchor({
      ledger: harness.simulator.getLedger(), registryId: harness.registryId,
      epochId: suspended.epoch.epochId, policyVersion: suspended.policy.version,
      sequenceToTimestamp: defaultSequenceToTimestamp,
    });
    expect(verifyTrqpAuthorizationEvidenceResponse(deniedResponse, deniedRequest,
      harness.registryDid, deniedAnchor)).toMatchObject({ authorized: false, statusAtTime: "suspended" });
    expect(() => verifyTrqpAuthorizationEvidenceResponse(deniedResponse, deniedRequest,
      harness.registryDid, anchor)).toThrow(/Epoch id mismatch/u);
  });

  it("verifies an exact verifier request rather than promoting it to issuer authority", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("trqp-verified-verifier");
    const verifier = createVerifierScenarioFixture("trqp-verified-verifier");
    harness.authorizeVerifier(verifier);
    const bundle = harness.evaluateCurrentVerifierDecision(verifier);
    const at = bundle.epoch.validFrom;
    const request = {
      entity_id: verifier.subjectDid, authority_id: harness.registryDid,
      action: "verify", resource: verifier.scopeResourceId, context: { time: at },
    };
    const response = {
      ...request, time_requested: at, time_evaluated: at, authorized: true, bundle,
    };
    const anchor = resolveCompactHistoricalEpochAnchor({
      ledger: harness.simulator.getLedger(), registryId: harness.registryId,
      epochId: bundle.epoch.epochId, policyVersion: bundle.policy.version,
      sequenceToTimestamp: defaultSequenceToTimestamp,
    });
    expect(verifyTrqpAuthorizationEvidenceResponse(response, request,
      harness.registryDid, anchor).authorized).toBe(true);
    expect(() => verifyTrqpAuthorizationEvidenceResponse({
      ...response, action: "issue",
    }, { ...request, action: "issue" }, harness.registryDid, anchor)).toThrow(/evidence role/u);
  });

  it("requires exact recognition context and never turns it into a local grant", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("trqp-verified-recognition");
    const recognition = createRecognitionScenarioFixture("trqp-verified-recognition");
    harness.authorizeRecognition(recognition);
    const bundle = harness.evaluateCurrentRecognitionDecision(recognition);
    const record = bundle.recognition!;
    const at = bundle.epoch.validFrom;
    const request = {
      entity_id: recognition.recognizedAuthorityDid,
      authority_id: harness.registryDid,
      action: record.scope.resourceType,
      resource: record.scope.resourceId,
      context: {
        time: at,
        recognized_registry_id: record.recognizedRegistryId,
        ...(record.scope.context === undefined ? {} : { scope_context: record.scope.context }),
      },
    };
    const response = {
      ...request, time_requested: at, time_evaluated: at, recognized: true, bundle,
    };
    const anchor = resolveCompactHistoricalEpochAnchor({
      ledger: harness.simulator.getLedger(), registryId: harness.registryId,
      epochId: bundle.epoch.epochId, policyVersion: bundle.policy.version,
      sequenceToTimestamp: defaultSequenceToTimestamp,
    });
    expect(verifyTrqpRecognitionEvidenceResponse(response, request,
      harness.registryDid, anchor).recognized).toBe(true);
    expect((await verifyTrqpRecognitionEvidenceFromApi(
      "https://registry.example", request, harness.registryDid, anchor,
      async (input, init) => {
        expect(String(input)).toBe("https://registry.example/v1/trqp/recognitions/evidence");
        expect(init).toMatchObject({ method: "POST", cache: "no-store", redirect: "error" });
        return new Response(JSON.stringify(response), { status: 200 });
      },
    )).recognized).toBe(true);
    await expect(verifyTrqpRecognitionEvidenceFromApi(
      "https://registry.example", { ...request, context: { time: at } },
      harness.registryDid, anchor, async () => { throw new Error("must not fetch"); },
    )).rejects.toThrow(/explicit time and external registry/u);
    expect(() => verifyTrqpRecognitionEvidenceResponse({
      ...response, resource: `${request.resource}:other`,
    }, { ...request, resource: `${request.resource}:other` }, harness.registryDid, anchor))
      .toThrow(/scope mismatch/u);
    expect(() => verifyTrqpRecognitionEvidenceResponse(response, {
      ...request,
      context: { ...request.context, recognized_registry_id: `${record.recognizedRegistryId}:other` },
    }, harness.registryDid, anchor)).toThrow(/trusted request/u);
    expect(() => verifyTrqpRecognitionEvidenceResponse(response, {
      ...request, context: { time: at },
    }, harness.registryDid, anchor)).toThrow(/trusted request/u);
    expect(() => verifyTrqpAuthorizationEvidenceResponse(response, {
      entity_id: request.entity_id, authority_id: request.authority_id,
      action: "issue", resource: request.resource, context: { time: at },
    }, harness.registryDid, anchor)).toThrow();
  });
});
