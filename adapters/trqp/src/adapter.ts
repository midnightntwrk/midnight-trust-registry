import {
  RegistryRecordSchema,
  TrustRegistryEvidenceBundleSchema,
  type AuthorizationRecord,
  type RecognitionRecord,
  type RegistryRecord,
  type TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  TrqpAuthorizationEvidenceResponseSchema,
  TrqpAuthorizationRequestSchema,
  TrqpAuthorizationResponseSchema,
  TrqpProblemDetailsSchema,
  TrqpRecognitionEvidenceResponseSchema,
  TrqpRecognitionRequestSchema,
  TrqpRecognitionResponseSchema,
  TrqpRegistryMetadataResponseSchema,
  type TrqpAuthorizationEvidenceResponse,
  type TrqpAuthorizationRequest,
  type TrqpAuthorizationResponse,
  type TrqpContext,
  type TrqpProblemDetails,
  type TrqpRecognitionEvidenceResponse,
  type TrqpRecognitionRequest,
  type TrqpRecognitionResponse,
  type TrqpRegistryMetadataResponse,
} from "./schemas.js";

type MaybePromise<T> = T | Promise<T>;

const DEFAULT_PROBLEM_BASE =
  "https://midnight.network/problems/trqp";

export type TrqpAdapterResult<T> =
  | {
      ok: true;
      value: T;
    }
  | {
      ok: false;
      problem: TrqpProblemDetails;
    };

export type TrqpAuthorizationDecision = {
  bundle: TrustRegistryEvidenceBundle;
  statusAtTime: AuthorizationRecord["status"] | null;
  trustedAtTime: boolean;
};

export type TrqpRecognitionDecision = {
  bundle: TrustRegistryEvidenceBundle;
  statusAtTime: RecognitionRecord["status"] | null;
  trustedAtTime: boolean;
};

export type TrustRegistryTrqpSource = {
  getRegistryRecord(authorityId: string): MaybePromise<RegistryRecord | null>;
  getAuthorizationDecision(
    request: TrqpAuthorizationRequest,
  ): MaybePromise<TrqpAuthorizationDecision | null>;
  getRecognitionDecision(
    request: TrqpRecognitionRequest,
  ): MaybePromise<TrqpRecognitionDecision | null>;
};

export type TrustRegistryTrqpAdapterOptions = {
  clock?: () => string;
  problemBaseUri?: string;
};

const normalizeProblem = (
  problem: TrqpProblemDetails,
): TrqpProblemDetails => TrqpProblemDetailsSchema.parse(problem);

const notFoundProblem = (
  problemBaseUri: string,
  detail: string,
): TrqpProblemDetails => normalizeProblem({
  type: `${problemBaseUri}/not-found`,
  title: "trust statement not found",
  status: 404,
  detail,
});

const invalidSourceProblem = (
  problemBaseUri: string,
  detail: string,
): TrqpProblemDetails => normalizeProblem({
  type: `${problemBaseUri}/invalid-source-data`,
  title: "invalid trust-registry source data",
  status: 500,
  detail,
});

const describeAuthorizationMessage = (
  status: string,
  trusted: boolean,
): string => {
  return trusted
    ? "Authorization is active for the requested scope at the evaluation time."
    : `Authorization is not trusted at the evaluation time (status: ${status}).`;
};

const describeRecognitionMessage = (
  status: string,
  trusted: boolean,
): string => {
  return trusted
    ? "Recognition is active for the requested scope at the evaluation time."
    : `Recognition is not trusted at the evaluation time (status: ${status}).`;
};

const timeRequestedFor = (
  context: TrqpContext | undefined,
): string | undefined => context?.time;

const timeEvaluatedFor = (
  context: TrqpContext | undefined,
  clock: () => string,
): string => context?.time ?? clock();

export class TrustRegistryTrqpAdapter {
  private readonly clock: () => string;
  private readonly problemBaseUri: string;

  constructor(
    private readonly source: TrustRegistryTrqpSource,
    options: TrustRegistryTrqpAdapterOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date().toISOString());
    this.problemBaseUri = options.problemBaseUri ?? DEFAULT_PROBLEM_BASE;
  }

  async getRegistryMetadata(
    authorityIdInput: string,
  ): Promise<TrqpAdapterResult<TrqpRegistryMetadataResponse>> {
    const authorityId = authorityIdInput.trim();
    const record = await this.source.getRegistryRecord(authorityId);

    if (record === null) {
      return {
        ok: false,
        problem: notFoundProblem(
          this.problemBaseUri,
          `No registry metadata exists for authority_id ${authorityId}.`,
        ),
      };
    }

    const parsedRecord = RegistryRecordSchema.parse(record);
    return {
      ok: true,
      value: TrqpRegistryMetadataResponseSchema.parse({
        authority_id: parsedRecord.registryDid,
        registry_id: parsedRecord.registryId,
        registry_did: parsedRecord.registryDid,
        name: parsedRecord.name,
        description: parsedRecord.description,
        status: parsedRecord.status,
        policy_uri: parsedRecord.policyUri,
        service_endpoint: parsedRecord.serviceEndpoint,
        logo_uri: parsedRecord.logoUri,
        controller_dids: parsedRecord.controllerDids,
        maintainer_dids: parsedRecord.maintainerDids,
        created_at: parsedRecord.createdAt,
        updated_at: parsedRecord.updatedAt,
      }),
    };
  }

  async queryAuthorization(
    requestInput: TrqpAuthorizationRequest,
  ): Promise<TrqpAdapterResult<TrqpAuthorizationResponse>> {
    const request = TrqpAuthorizationRequestSchema.parse(requestInput);
    const decisionResult = await this.resolveAuthorizationDecision(request);

    if (!decisionResult.ok) {
      return decisionResult;
    }

    const decision = decisionResult.value;
    const evaluatedAt = timeEvaluatedFor(request.context, this.clock);
    const authorized = decision.trustedAtTime;

    return {
      ok: true,
      value: TrqpAuthorizationResponseSchema.parse({
        entity_id: request.entity_id,
        authority_id: request.authority_id,
        action: request.action,
        resource: request.resource,
        time_requested: timeRequestedFor(request.context),
        time_evaluated: evaluatedAt,
        authorized,
        message: describeAuthorizationMessage(decision.statusAtTime ?? "not yet proposed", authorized),
        context: request.context,
      }),
    };
  }

  async getAuthorizationEvidence(
    requestInput: TrqpAuthorizationRequest,
  ): Promise<TrqpAdapterResult<TrqpAuthorizationEvidenceResponse>> {
    const request = TrqpAuthorizationRequestSchema.parse(requestInput);
    const decisionResult = await this.resolveAuthorizationDecision(request);

    if (!decisionResult.ok) {
      return decisionResult;
    }

    const decision = decisionResult.value;
    const evaluatedAt = timeEvaluatedFor(request.context, this.clock);
    const authorized = decision.trustedAtTime;
    return {
      ok: true,
      value: TrqpAuthorizationEvidenceResponseSchema.parse({
        entity_id: request.entity_id,
        authority_id: request.authority_id,
        action: request.action,
        resource: request.resource,
        time_requested: timeRequestedFor(request.context),
        time_evaluated: evaluatedAt,
        authorized,
        message: describeAuthorizationMessage(decision.statusAtTime ?? "not yet proposed", authorized),
        context: request.context,
        bundle: decision.bundle,
      }),
    };
  }

  async queryRecognition(
    requestInput: TrqpRecognitionRequest,
  ): Promise<TrqpAdapterResult<TrqpRecognitionResponse>> {
    const request = TrqpRecognitionRequestSchema.parse(requestInput);
    const decisionResult = await this.resolveRecognitionDecision(request);

    if (!decisionResult.ok) {
      return decisionResult;
    }

    const decision = decisionResult.value;
    const evaluatedAt = timeEvaluatedFor(request.context, this.clock);
    const recognized = decision.trustedAtTime;

    return {
      ok: true,
      value: TrqpRecognitionResponseSchema.parse({
        entity_id: request.entity_id,
        authority_id: request.authority_id,
        action: request.action,
        resource: request.resource,
        time_requested: timeRequestedFor(request.context),
        time_evaluated: evaluatedAt,
        recognized,
        message: describeRecognitionMessage(decision.statusAtTime ?? "not yet proposed", recognized),
        context: request.context,
      }),
    };
  }

  async getRecognitionEvidence(
    requestInput: TrqpRecognitionRequest,
  ): Promise<TrqpAdapterResult<TrqpRecognitionEvidenceResponse>> {
    const request = TrqpRecognitionRequestSchema.parse(requestInput);
    const decisionResult = await this.resolveRecognitionDecision(request);

    if (!decisionResult.ok) {
      return decisionResult;
    }

    const decision = decisionResult.value;
    const evaluatedAt = timeEvaluatedFor(request.context, this.clock);
    const recognized = decision.trustedAtTime;
    return {
      ok: true,
      value: TrqpRecognitionEvidenceResponseSchema.parse({
        entity_id: request.entity_id,
        authority_id: request.authority_id,
        action: request.action,
        resource: request.resource,
        time_requested: timeRequestedFor(request.context),
        time_evaluated: evaluatedAt,
        recognized,
        message: describeRecognitionMessage(decision.statusAtTime ?? "not yet proposed", recognized),
        context: request.context,
        bundle: decision.bundle,
      }),
    };
  }

  private async resolveAuthorizationDecision(
    request: TrqpAuthorizationRequest,
  ): Promise<TrqpAdapterResult<TrqpAuthorizationDecision>> {
    const record = await this.source.getRegistryRecord(request.authority_id);

    if (record === null) {
      return {
        ok: false,
        problem: notFoundProblem(
          this.problemBaseUri,
          `No authority record exists for authority_id ${request.authority_id}.`,
        ),
      };
    }

    const decision = await this.source.getAuthorizationDecision(request);
    if (decision === null) {
      return {
        ok: false,
        problem: notFoundProblem(
          this.problemBaseUri,
          `No authorization statement matched (${request.entity_id}, ${request.action}, ${request.resource}) under authority ${request.authority_id}.`,
        ),
      };
    }

    const parsedBundle = TrustRegistryEvidenceBundleSchema.parse(decision.bundle);
    if (parsedBundle.authorization === undefined) {
      return {
        ok: false,
        problem: invalidSourceProblem(
          this.problemBaseUri,
          "Authorization query resolved to a bundle without an authorization statement.",
        ),
      };
    }
    if (decision.trustedAtTime && decision.statusAtTime !== "active") {
      return {
        ok: false,
        problem: invalidSourceProblem(this.problemBaseUri, "Trusted authorization must be active at the evaluation time."),
      };
    }

    return {
      ok: true,
      value: { ...decision, bundle: parsedBundle },
    };
  }

  private async resolveRecognitionDecision(
    request: TrqpRecognitionRequest,
  ): Promise<TrqpAdapterResult<TrqpRecognitionDecision>> {
    const record = await this.source.getRegistryRecord(request.authority_id);

    if (record === null) {
      return {
        ok: false,
        problem: notFoundProblem(
          this.problemBaseUri,
          `No authority record exists for authority_id ${request.authority_id}.`,
        ),
      };
    }

    const decision = await this.source.getRecognitionDecision(request);
    if (decision === null) {
      return {
        ok: false,
        problem: notFoundProblem(
          this.problemBaseUri,
          `No recognition statement matched (${request.entity_id}, ${request.action}, ${request.resource}) under authority ${request.authority_id}.`,
        ),
      };
    }

    const parsedBundle = TrustRegistryEvidenceBundleSchema.parse(decision.bundle);
    if (parsedBundle.recognition === undefined) {
      return {
        ok: false,
        problem: invalidSourceProblem(
          this.problemBaseUri,
          "Recognition query resolved to a bundle without a recognition statement.",
        ),
      };
    }
    if (decision.trustedAtTime && decision.statusAtTime !== "active") {
      return {
        ok: false,
        problem: invalidSourceProblem(this.problemBaseUri, "Trusted recognition must be active at the evaluation time."),
      };
    }

    return {
      ok: true,
      value: { ...decision, bundle: parsedBundle },
    };
  }
}
