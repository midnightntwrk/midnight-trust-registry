import { describe, expect, it } from "vitest";

import type {
  RegistryRecord,
  TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  evaluateAuthorizationRecordAtTime,
  evaluateRecognitionRecordAtTime,
} from "@midnight-ntwrk/trust-registry-client";

import {
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  type IssuerScenarioFixture,
  type RecognitionScenarioFixture,
  type VerifierScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";
import {
  TrustRegistryTrqpAdapter,
  type TrqpAdapterResult,
  type TrqpAuthorizationDecision,
  type TrqpAuthorizationEvidenceResponse,
  type TrqpAuthorizationRequest,
  type TrqpAuthorizationResponse,
  type TrqpProblemDetails,
  type TrqpRecognitionEvidenceResponse,
  type TrqpRecognitionDecision,
  type TrqpRecognitionRequest,
  type TrqpRecognitionResponse,
  type TrqpRegistryMetadataResponse,
  type TrustRegistryTrqpSource,
} from "../index.js";

const FIXED_TIME = "2026-05-21T00:00:00Z";

class LocalSimulatorTrqpSource implements TrustRegistryTrqpSource {
  constructor(
    private readonly harness: LocalTrustRegistryIntegrationHarness,
    private readonly fixtures: {
      issuers?: IssuerScenarioFixture[];
      verifiers?: VerifierScenarioFixture[];
      recognitions?: RecognitionScenarioFixture[];
    } = {},
  ) {}

  getRegistryRecord(authorityId: string): RegistryRecord | null {
    return authorityId === this.harness.registryDid
      ? this.harness.registryRecord
      : null;
  }

  getAuthorizationDecision(
    request: TrqpAuthorizationRequest,
    evaluatedAt: string,
  ): TrqpAuthorizationDecision | null {
    if (request.authority_id !== this.harness.registryDid) {
      return null;
    }

    if (request.action === "issue") {
      const fixture = this.fixtures.issuers?.find((candidate) =>
        candidate.subjectDid === request.entity_id
        && candidate.resourceId === request.resource
      );

      if (fixture === undefined) {
        return null;
      }

      return this.authorizationDecision(this.resolveCurrentOrHistorical(
        () => this.harness.evaluateCurrentIssuerDecision(fixture),
        () => this.harness.buildIssuerHistoricalEvidence(fixture),
      ), evaluatedAt);
    }

    if (request.action === "verify") {
      const fixture = this.fixtures.verifiers?.find((candidate) =>
        candidate.subjectDid === request.entity_id
        && candidate.scopeResourceId === request.resource
      );

      if (fixture === undefined) {
        return null;
      }

      return this.authorizationDecision(this.resolveCurrentOrHistorical(
        () => this.harness.evaluateCurrentVerifierDecision(fixture),
        () => this.harness.buildVerifierHistoricalEvidence(fixture),
      ), evaluatedAt);
    }

    return null;
  }

  getRecognitionDecision(
    request: TrqpRecognitionRequest,
    evaluatedAt: string,
  ): TrqpRecognitionDecision | null {
    if (request.authority_id !== this.harness.registryDid) {
      return null;
    }

    const recognizedRegistryId =
      typeof request.context?.recognized_registry_id === "string"
        ? request.context.recognized_registry_id
        : undefined;

    const fixture = this.fixtures.recognitions?.find((candidate) =>
      candidate.recognizedAuthorityDid === request.entity_id
      && candidate.scopeResourceType === request.action
      && candidate.scopeResourceId === request.resource
      && (
        recognizedRegistryId === undefined
        || candidate.recognizedRegistryId === recognizedRegistryId
      )
    );

    if (fixture === undefined) {
      return null;
    }

    return this.recognitionDecision(this.resolveCurrentOrHistorical(
      () => this.harness.evaluateCurrentRecognitionDecision(fixture),
      () => this.harness.buildRecognitionHistoricalEvidence(fixture),
    ), evaluatedAt);
  }

  private authorizationDecision(bundle: TrustRegistryEvidenceBundle, time: string): TrqpAuthorizationDecision {
    const authorization = bundle.authorization;
    if (authorization === undefined) throw new Error("expected authorization evidence");
    const evaluation = evaluateAuthorizationRecordAtTime(authorization, time);
    return {
      bundle,
      statusAtTime: evaluation.statusAtTime,
      trustedAtTime: evaluation.trustedAtTime,
    };
  }

  private recognitionDecision(bundle: TrustRegistryEvidenceBundle, time: string): TrqpRecognitionDecision {
    const recognition = bundle.recognition;
    if (recognition === undefined) throw new Error("expected recognition evidence");
    const evaluation = evaluateRecognitionRecordAtTime(recognition, time);
    return {
      bundle,
      statusAtTime: evaluation.statusAtTime,
      trustedAtTime: evaluation.trustedAtTime,
    };
  }

  private resolveCurrentOrHistorical(
    current: () => TrustRegistryEvidenceBundle,
    historical: () => TrustRegistryEvidenceBundle,
  ): TrustRegistryEvidenceBundle {
    try {
      return current();
    } catch (error) {
      if (error instanceof Error && /not active/i.test(error.message)) {
        return historical();
      }
      throw error;
    }
  }
}

const expectOk = <T>(result: TrqpAdapterResult<T>): T => {
  expect(result.ok).toBe(true);
  if (!result.ok) {
    throw new Error(result.problem.detail ?? result.problem.title);
  }
  return result.value;
};

const expectProblem = <T>(result: TrqpAdapterResult<T>): TrqpProblemDetails => {
  expect(result.ok).toBe(false);
  if (result.ok) {
    throw new Error("expected a problem-details response");
  }
  return result.problem;
};

describe("trust registry TRQP adapter", () => {
  it("uses one off-ledger clock instant for an untimed decision", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("source-time");
    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);
    const source: TrustRegistryTrqpSource = {
      getRegistryRecord: () => harness.registryRecord,
      getAuthorizationDecision: () => ({
        bundle,
        statusAtTime: "active",
        trustedAtTime: true,
      }),
      getRecognitionDecision: () => null,
    };
    const adapter = new TrustRegistryTrqpAdapter(source, { clock: () => FIXED_TIME });
    const response = expectOk(await adapter.queryAuthorization({
      entity_id: issuer.subjectDid,
      authority_id: harness.registryDid,
      action: "issue",
      resource: issuer.resourceId,
    }));
    expect(response.time_evaluated).toBe(FIXED_TIME);
    expect(response.time_requested).toBeUndefined();
  }, 20_000);

  it("maps active issuer and verifier authorization into TRQP responses", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("degree");
    const verifier = createVerifierScenarioFixture("admissions");

    harness.authorizeIssuer(issuer);
    harness.authorizeVerifier(verifier);
    const issuerAt = harness.evaluateCurrentIssuerDecision(issuer).epoch.validFrom;
    const verifierAt = harness.evaluateCurrentVerifierDecision(verifier).epoch.validFrom;

    const adapter = new TrustRegistryTrqpAdapter(
      new LocalSimulatorTrqpSource(harness, {
        issuers: [issuer],
        verifiers: [verifier],
      }),
      {
        clock: () => FIXED_TIME,
      },
    );

    const issuerResponse = expectOk<TrqpAuthorizationResponse>(
      await adapter.queryAuthorization({
        entity_id: issuer.subjectDid,
        authority_id: harness.registryDid,
        action: "issue",
        resource: issuer.resourceId,
        context: { time: issuerAt },
      }),
    );
    expect(issuerResponse.authorized).toBe(true);
    expect(issuerResponse.time_requested).toBe(issuerAt);
    expect(issuerResponse.authority_id).toBe(harness.registryDid);
    expect(issuerResponse.message).toMatch(/active/i);
    expect(issuerResponse.message).toMatch(/snapshot projection, not proof/);

    const verifierResponse = expectOk<TrqpAuthorizationResponse>(
      await adapter.queryAuthorization({
        entity_id: verifier.subjectDid,
        authority_id: harness.registryDid,
        action: "verify",
        resource: verifier.scopeResourceId,
        context: {
          time: verifierAt,
        },
      }),
    );
    expect(verifierResponse.authorized).toBe(true);
    expect(verifierResponse.resource).toBe(verifier.scopeResourceId);
  }, 15_000);

  it("maps revoked authorization into a negative TRQP decision and preserves evidence", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("passport");

    harness.authorizeIssuer(issuer);
    harness.revokeIssuer(issuer);
    const revokedAt = harness.buildIssuerHistoricalEvidence(issuer).epoch.validFrom;

    const adapter = new TrustRegistryTrqpAdapter(
      new LocalSimulatorTrqpSource(harness, {
        issuers: [issuer],
      }),
      {
        clock: () => revokedAt,
      },
    );

    const response = expectOk<TrqpAuthorizationResponse>(
      await adapter.queryAuthorization({
        entity_id: issuer.subjectDid,
        authority_id: harness.registryDid,
        action: "issue",
        resource: issuer.resourceId,
      }),
    );
    expect(response.authorized).toBe(false);
    expect(response.message).toMatch(/revoked/i);

    const evidence = expectOk<TrqpAuthorizationEvidenceResponse>(
      await adapter.getAuthorizationEvidence({
        entity_id: issuer.subjectDid,
        authority_id: harness.registryDid,
        action: "issue",
        resource: issuer.resourceId,
      }),
    );
    expect(evidence.bundle.authorization?.status).toBe("revoked");
    expect(evidence.message).toMatch(/verify its anchor and proof independently/);

    const activeFrom = evidence.bundle.authorization?.activeFrom;
    if (activeFrom === undefined) throw new Error("expected an activation timestamp");
    const historical = expectProblem(
      await adapter.getAuthorizationEvidence({
        entity_id: issuer.subjectDid,
        authority_id: harness.registryDid,
        action: "issue",
        resource: issuer.resourceId,
        context: { time: activeFrom },
      }),
    );
    expect(historical.status).toBe(424);
    expect(historical.type).toMatch(/epoch-evidence-unavailable$/);
  });

  it("evaluates recognition at the requested time instead of its latest status", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("historical-recognition");
    harness.authorizeRecognition(recognition);
    harness.revokeRecognition(recognition);
    const revokedAt = harness.buildRecognitionHistoricalEvidence(recognition).epoch.validFrom;
    const adapter = new TrustRegistryTrqpAdapter(
      new LocalSimulatorTrqpSource(harness, { recognitions: [recognition] }),
      { clock: () => revokedAt },
    );
    const request = {
      entity_id: recognition.recognizedAuthorityDid,
      authority_id: harness.registryDid,
      action: recognition.scopeResourceType,
      resource: recognition.scopeResourceId,
      context: { recognized_registry_id: recognition.recognizedRegistryId },
    };
    const latest = expectOk<TrqpRecognitionEvidenceResponse>(await adapter.getRecognitionEvidence(request));
    expect(latest.recognized).toBe(false);
    const activeFrom = latest.bundle.recognition?.effectiveFrom;
    if (activeFrom === undefined) throw new Error("expected an effective timestamp");
    const historical = expectProblem(
      await adapter.getRecognitionEvidence({ ...request, context: { ...request.context, time: activeFrom } }),
    );
    expect(historical.status).toBe(424);
  });

  it("maps recognition plus registry metadata into TRQP-friendly responses", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("gaia-x");

    harness.authorizeRecognition(recognition);
    const at = harness.evaluateCurrentRecognitionDecision(recognition).epoch.validFrom;

    const adapter = new TrustRegistryTrqpAdapter(
      new LocalSimulatorTrqpSource(harness, {
        recognitions: [recognition],
      }),
      {
        clock: () => FIXED_TIME,
      },
    );

    const metadata = expectOk<TrqpRegistryMetadataResponse>(
      await adapter.getRegistryMetadata(harness.registryDid),
    );
    expect(metadata.registry_id).toBe(harness.registryId);
    expect(metadata.registry_did).toBe(harness.registryDid);
    expect(metadata.service_endpoint).toBe(harness.registryRecord.serviceEndpoint);

    const response = expectOk<TrqpRecognitionResponse>(
      await adapter.queryRecognition({
        entity_id: recognition.recognizedAuthorityDid,
        authority_id: harness.registryDid,
        action: recognition.scopeResourceType,
        resource: recognition.scopeResourceId,
        context: {
          time: at,
          recognized_registry_id: recognition.recognizedRegistryId,
        },
      }),
    );
    expect(response.recognized).toBe(true);
    expect(response.message).toMatch(/active/i);

    const evidence = expectOk<TrqpRecognitionEvidenceResponse>(
      await adapter.getRecognitionEvidence({
        entity_id: recognition.recognizedAuthorityDid,
        authority_id: harness.registryDid,
        action: recognition.scopeResourceType,
        resource: recognition.scopeResourceId,
        context: {
          time: at,
          recognized_registry_id: recognition.recognizedRegistryId,
        },
      }),
    );
    expect(evidence.bundle.recognition?.recognizedRegistryId).toBe(
      recognition.recognizedRegistryId,
    );
  });

  it("rejects a source that attaches another issuer's evidence to an authorization request", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const requested = createIssuerScenarioFixture("requested-issuer");
    const substituted = createIssuerScenarioFixture("substituted-issuer");
    harness.authorizeIssuer(requested);
    harness.authorizeIssuer(substituted);
    const bundle = harness.evaluateCurrentIssuerDecision(substituted);
    const source: TrustRegistryTrqpSource = {
      getRegistryRecord: () => harness.registryRecord,
      getAuthorizationDecision: () => ({ bundle, statusAtTime: "active", trustedAtTime: true }),
      getRecognitionDecision: () => null,
    };
    const adapter = new TrustRegistryTrqpAdapter(source);
    const request = {
      entity_id: substituted.subjectDid,
      authority_id: harness.registryDid,
      action: "issue",
      resource: substituted.resourceId,
      context: { time: bundle.epoch.validFrom },
    };
    for (const mismatch of [
      { ...request, entity_id: requested.subjectDid },
      { ...request, action: "verify" },
      { ...request, resource: requested.resourceId },
      { ...request, authority_id: "did:midnight:other" },
    ]) {
      const problem = expectProblem(await adapter.getAuthorizationEvidence(mismatch));
      expect(problem.status).toBe(500);
      expect(problem.type).toMatch(/invalid-source-data$/u);
    }
    const otherRegistry = new LocalTrustRegistryIntegrationHarness("other-registry");
    otherRegistry.authorizeIssuer(substituted);
    const crossRegistry = new TrustRegistryTrqpAdapter({
      ...source,
      getAuthorizationDecision: () => ({
        bundle: otherRegistry.evaluateCurrentIssuerDecision(substituted),
        statusAtTime: "active",
        trustedAtTime: true,
      }),
    });
    const crossRegistryProblem = expectProblem(await crossRegistry.getAuthorizationEvidence(request));
    expect(crossRegistryProblem.status).toBe(500);
    expect(crossRegistryProblem.type).toMatch(/invalid-source-data$/u);
  });

  it("rejects recognition evidence for a different external registry", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("requested-recognition");
    harness.authorizeRecognition(recognition);
    const bundle = harness.evaluateCurrentRecognitionDecision(recognition);
    const source: TrustRegistryTrqpSource = {
      getRegistryRecord: () => harness.registryRecord,
      getAuthorizationDecision: () => null,
      getRecognitionDecision: () => ({ bundle, statusAtTime: "active", trustedAtTime: true }),
    };
    const adapter = new TrustRegistryTrqpAdapter(source);
    const request = {
      entity_id: recognition.recognizedAuthorityDid,
      authority_id: harness.registryDid,
      action: recognition.scopeResourceType,
      resource: recognition.scopeResourceId,
      context: { time: bundle.epoch.validFrom, recognized_registry_id: recognition.recognizedRegistryId },
    };
    for (const mismatch of [
      { ...request, entity_id: "did:midnight:other" },
      { ...request, action: "other-action" },
      { ...request, resource: "resource:other" },
      { ...request, context: { ...request.context, recognized_registry_id: "registry:external:other:v1" } },
    ]) {
      const problem = expectProblem(await adapter.getRecognitionEvidence(mismatch));
      expect(problem.status).toBe(500);
      expect(problem.type).toMatch(/invalid-source-data$/u);
    }
  });

  it("rejects issuer evidence with a substituted epoch, policy, or lifecycle decision", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("inconsistent-evidence");
    harness.authorizeIssuer(issuer);
    const bundle = harness.evaluateCurrentIssuerDecision(issuer);
    const request = {
      entity_id: issuer.subjectDid,
      authority_id: harness.registryDid,
      action: "issue",
      resource: issuer.resourceId,
      context: { time: bundle.epoch.validFrom },
    };
    const decisions: TrqpAuthorizationDecision[] = [
      { bundle: { ...bundle, epoch: { ...bundle.epoch, registryId: "registry:other:trusted" } },
        statusAtTime: "active", trustedAtTime: true },
      { bundle: { ...bundle, epoch: { ...bundle.epoch, policyRoot: `0x${"ab".repeat(32)}` } },
        statusAtTime: "active", trustedAtTime: true },
      { bundle: { ...bundle, policy: { ...bundle.policy, policyId: `${bundle.policy.policyId}:other` } },
        statusAtTime: "active", trustedAtTime: true },
      { bundle, statusAtTime: "revoked", trustedAtTime: false },
      { bundle, statusAtTime: "active", trustedAtTime: false },
    ];
    for (const decision of decisions) {
      const adapter = new TrustRegistryTrqpAdapter({
        getRegistryRecord: () => harness.registryRecord,
        getAuthorizationDecision: () => decision,
        getRecognitionDecision: () => null,
      });
      const problem = expectProblem(await adapter.getAuthorizationEvidence(request));
      expect(problem.status).toBe(500);
      expect(problem.type).toMatch(/invalid-source-data$/u);
    }
  });

  it("rejects recognition evidence with a substituted policy or lifecycle decision", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("inconsistent-evidence");
    harness.authorizeRecognition(recognition);
    const bundle = harness.evaluateCurrentRecognitionDecision(recognition);
    const request = {
      entity_id: recognition.recognizedAuthorityDid,
      authority_id: harness.registryDid,
      action: recognition.scopeResourceType,
      resource: recognition.scopeResourceId,
      context: { time: bundle.epoch.validFrom, recognized_registry_id: recognition.recognizedRegistryId },
    };
    const decisions: TrqpRecognitionDecision[] = [
      { bundle: { ...bundle, epoch: { ...bundle.epoch, policyRoot: `0x${"cd".repeat(32)}` } },
        statusAtTime: "active", trustedAtTime: true },
      { bundle, statusAtTime: "suspended", trustedAtTime: false },
    ];
    for (const decision of decisions) {
      const adapter = new TrustRegistryTrqpAdapter({
        getRegistryRecord: () => harness.registryRecord,
        getAuthorizationDecision: () => null,
        getRecognitionDecision: () => decision,
      });
      const problem = expectProblem(await adapter.getRecognitionEvidence(request));
      expect(problem.status).toBe(500);
      expect(problem.type).toMatch(/invalid-source-data$/u);
    }
  });

  it("reports out-of-epoch evidence before contradictory source lifecycle decisions", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("out-of-epoch-issuer");
    const recognition = createRecognitionScenarioFixture("out-of-epoch-recognition");
    harness.authorizeIssuer(issuer);
    harness.authorizeRecognition(recognition);
    const authorizationBundle = harness.evaluateCurrentIssuerDecision(issuer);
    const recognitionBundle = harness.evaluateCurrentRecognitionDecision(recognition);
    const adapter = new TrustRegistryTrqpAdapter({
      getRegistryRecord: () => harness.registryRecord,
      getAuthorizationDecision: () => ({
        bundle: authorizationBundle, statusAtTime: "revoked", trustedAtTime: false,
      }),
      getRecognitionDecision: () => ({
        bundle: recognitionBundle, statusAtTime: "suspended", trustedAtTime: false,
      }),
    });
    const outside = (until: string) => new Date(Date.parse(until) + 1000).toISOString();
    const authorizationProblem = expectProblem(await adapter.getAuthorizationEvidence({
      entity_id: issuer.subjectDid,
      authority_id: harness.registryDid,
      action: "issue",
      resource: issuer.resourceId,
      context: { time: outside(authorizationBundle.epoch.validUntil) },
    }));
    expect(authorizationProblem.status).toBe(424);
    const recognitionProblem = expectProblem(await adapter.getRecognitionEvidence({
      entity_id: recognition.recognizedAuthorityDid,
      authority_id: harness.registryDid,
      action: recognition.scopeResourceType,
      resource: recognition.scopeResourceId,
      context: {
        time: outside(recognitionBundle.epoch.validUntil),
        recognized_registry_id: recognition.recognizedRegistryId,
      },
    }));
    expect(recognitionProblem.status).toBe(424);
  });

  it("compares equivalent offsets and sub-millisecond epoch boundaries without Date truncation", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("fractional-epoch-issuer");
    const recognition = createRecognitionScenarioFixture("fractional-epoch-recognition");
    harness.authorizeIssuer(issuer);
    harness.authorizeRecognition(recognition);
    const authorizationBundle = harness.evaluateCurrentIssuerDecision(issuer);
    const recognitionBundle = harness.evaluateCurrentRecognitionDecision(recognition);
    const adapter = new TrustRegistryTrqpAdapter({
      getRegistryRecord: () => harness.registryRecord,
      getAuthorizationDecision: () => ({
        bundle: authorizationBundle, statusAtTime: "active", trustedAtTime: true,
      }),
      getRecognitionDecision: () => ({
        bundle: recognitionBundle, statusAtTime: "active", trustedAtTime: true,
      }),
    });
    const equivalentOffset = (instant: string) =>
      new Date(Date.parse(instant) + 60 * 60 * 1000).toISOString().replace(/Z$/u, "+01:00");
    const justAfter = (instant: string) => {
      expect(instant).toMatch(/\.000Z$/u);
      return instant.replace(/\.000Z$/u, ".0000000001Z");
    };
    const issuerRequest = {
      entity_id: issuer.subjectDid, authority_id: harness.registryDid,
      action: "issue" as const, resource: issuer.resourceId,
    };
    const recognitionRequest = {
      entity_id: recognition.recognizedAuthorityDid, authority_id: harness.registryDid,
      action: recognition.scopeResourceType, resource: recognition.scopeResourceId,
      context: { recognized_registry_id: recognition.recognizedRegistryId },
    };
    expect((await adapter.getAuthorizationEvidence({
      ...issuerRequest, context: { time: equivalentOffset(authorizationBundle.epoch.validFrom) },
    })).ok).toBe(true);
    expect((await adapter.getRecognitionEvidence({
      ...recognitionRequest,
      context: { ...recognitionRequest.context,
        time: equivalentOffset(recognitionBundle.epoch.validFrom) },
    })).ok).toBe(true);
    const issuerProblem = expectProblem(await adapter.getAuthorizationEvidence({
      ...issuerRequest, context: { time: justAfter(authorizationBundle.epoch.validUntil) },
    }));
    expect(issuerProblem.status).toBe(424);
    const recognitionProblem = expectProblem(await adapter.getRecognitionEvidence({
      ...recognitionRequest,
      context: { ...recognitionRequest.context,
        time: justAfter(recognitionBundle.epoch.validUntil) },
    }));
    expect(recognitionProblem.status).toBe(424);
  });

  it("returns problem details for unknown authorities or unmatched tuples", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("eidas");

    harness.authorizeRecognition(recognition);

    const adapter = new TrustRegistryTrqpAdapter(
      new LocalSimulatorTrqpSource(harness, {
        recognitions: [recognition],
      }),
      {
        clock: () => FIXED_TIME,
      },
    );

    const unknownAuthority = expectProblem(
      await adapter.queryAuthorization({
        entity_id: "did:midnight:unknown",
        authority_id: "did:midnight:other",
        action: "issue",
        resource: "credential-family:missing:v1",
      }),
    );
    expect(unknownAuthority.status).toBe(404);
    expect(unknownAuthority.title).toMatch(/not found/i);

    const unmatchedRecognition = expectProblem(
      await adapter.queryRecognition({
        entity_id: recognition.recognizedAuthorityDid,
        authority_id: harness.registryDid,
        action: recognition.scopeResourceType,
        resource: recognition.scopeResourceId,
        context: {
          recognized_registry_id: "registry:external:other:v1",
        },
      }),
    );
    expect(unmatchedRecognition.status).toBe(404);
    expect(unmatchedRecognition.detail).toMatch(/recognition statement/i);
  });
});
