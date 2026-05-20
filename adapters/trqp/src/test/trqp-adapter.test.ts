import { describe, expect, it } from "vitest";

import type {
  RegistryRecord,
  TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  type IssuerScenarioFixture,
  type RecognitionScenarioFixture,
  type VerifierScenarioFixture,
} from "../../../../packages/trust-registry-integration/src/index.js";
import {
  TrustRegistryTrqpAdapter,
  type TrqpAdapterResult,
  type TrqpAuthorizationEvidenceResponse,
  type TrqpAuthorizationRequest,
  type TrqpAuthorizationResponse,
  type TrqpProblemDetails,
  type TrqpRecognitionEvidenceResponse,
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

  getAuthorizationBundle(
    request: TrqpAuthorizationRequest,
  ): TrustRegistryEvidenceBundle | null {
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

      return this.resolveCurrentOrHistorical(
        () => this.harness.evaluateCurrentIssuerDecision(fixture),
        () => this.harness.buildIssuerHistoricalEvidence(fixture),
      );
    }

    if (request.action === "verify") {
      const fixture = this.fixtures.verifiers?.find((candidate) =>
        candidate.subjectDid === request.entity_id
        && candidate.scopeResourceId === request.resource
      );

      if (fixture === undefined) {
        return null;
      }

      return this.resolveCurrentOrHistorical(
        () => this.harness.evaluateCurrentVerifierDecision(fixture),
        () => this.harness.buildVerifierHistoricalEvidence(fixture),
      );
    }

    return null;
  }

  getRecognitionBundle(
    request: TrqpRecognitionRequest,
  ): TrustRegistryEvidenceBundle | null {
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

    return this.resolveCurrentOrHistorical(
      () => this.harness.evaluateCurrentRecognitionDecision(fixture),
      () => this.harness.buildRecognitionHistoricalEvidence(fixture),
    );
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
  it("maps active issuer and verifier authorization into TRQP responses", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("degree");
    const verifier = createVerifierScenarioFixture("admissions");

    harness.authorizeIssuer(issuer);
    harness.authorizeVerifier(verifier);

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
        context: {
          time: FIXED_TIME,
        },
      }),
    );
    expect(issuerResponse.authorized).toBe(true);
    expect(issuerResponse.time_requested).toBe(FIXED_TIME);
    expect(issuerResponse.authority_id).toBe(harness.registryDid);
    expect(issuerResponse.message).toMatch(/active/i);

    const verifierResponse = expectOk<TrqpAuthorizationResponse>(
      await adapter.queryAuthorization({
        entity_id: verifier.subjectDid,
        authority_id: harness.registryDid,
        action: "verify",
        resource: verifier.scopeResourceId,
        context: {
          time: FIXED_TIME,
        },
      }),
    );
    expect(verifierResponse.authorized).toBe(true);
    expect(verifierResponse.resource).toBe(verifier.scopeResourceId);
  });

  it("maps revoked authorization into a negative TRQP decision and preserves evidence", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const issuer = createIssuerScenarioFixture("passport");

    harness.authorizeIssuer(issuer);
    harness.revokeIssuer(issuer);

    const adapter = new TrustRegistryTrqpAdapter(
      new LocalSimulatorTrqpSource(harness, {
        issuers: [issuer],
      }),
      {
        clock: () => FIXED_TIME,
      },
    );

    const response = expectOk<TrqpAuthorizationResponse>(
      await adapter.queryAuthorization({
        entity_id: issuer.subjectDid,
        authority_id: harness.registryDid,
        action: "issue",
        resource: issuer.resourceId,
        context: {
          time: FIXED_TIME,
        },
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
        context: {
          time: FIXED_TIME,
        },
      }),
    );
    expect(evidence.bundle.authorization?.status).toBe("revoked");
  });

  it("maps recognition plus registry metadata into TRQP-friendly responses", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness();
    const recognition = createRecognitionScenarioFixture("gaia-x");

    harness.authorizeRecognition(recognition);

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
          time: FIXED_TIME,
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
          time: FIXED_TIME,
          recognized_registry_id: recognition.recognizedRegistryId,
        },
      }),
    );
    expect(evidence.bundle.recognition?.recognizedRegistryId).toBe(
      recognition.recognizedRegistryId,
    );
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
