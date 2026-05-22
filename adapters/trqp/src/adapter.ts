import {
  RegistryRecordSchema,
  TrustRegistryEvidenceBundleSchema,
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

export type TrustRegistryTrqpSource = {
  getRegistryRecord(authorityId: string): MaybePromise<RegistryRecord | null>;
  getAuthorizationBundle(
    request: TrqpAuthorizationRequest,
  ): MaybePromise<TrustRegistryEvidenceBundle | null>;
  getRecognitionBundle(
    request: TrqpRecognitionRequest,
  ): MaybePromise<TrustRegistryEvidenceBundle | null>;
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
  bundle: TrustRegistryEvidenceBundle,
): string => {
  const role = bundle.authorization?.role ?? "entity";
  const status = bundle.authorization?.status ?? "missing";

  return status === "active"
    ? `${role} authorization is active for the requested scope.`
    : `${role} authorization exists but is ${status}.`;
};

const describeRecognitionMessage = (
  bundle: TrustRegistryEvidenceBundle,
): string => {
  const status = bundle.recognition?.status ?? "missing";

  return status === "active"
    ? "Recognition is active for the requested scope."
    : `Recognition exists but is ${status}.`;
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
    const bundleResult = await this.resolveAuthorizationBundle(request);

    if (!bundleResult.ok) {
      return bundleResult;
    }

    const bundle = bundleResult.value;

    return {
      ok: true,
      value: TrqpAuthorizationResponseSchema.parse({
        entity_id: request.entity_id,
        authority_id: request.authority_id,
        action: request.action,
        resource: request.resource,
        time_requested: timeRequestedFor(request.context),
        time_evaluated: timeEvaluatedFor(request.context, this.clock),
        authorized: bundle.authorization?.status === "active",
        message: describeAuthorizationMessage(bundle),
        context: request.context,
      }),
    };
  }

  async getAuthorizationEvidence(
    requestInput: TrqpAuthorizationRequest,
  ): Promise<TrqpAdapterResult<TrqpAuthorizationEvidenceResponse>> {
    const request = TrqpAuthorizationRequestSchema.parse(requestInput);
    const bundleResult = await this.resolveAuthorizationBundle(request);

    if (!bundleResult.ok) {
      return bundleResult;
    }

    const bundle = bundleResult.value;
    return {
      ok: true,
      value: TrqpAuthorizationEvidenceResponseSchema.parse({
        entity_id: request.entity_id,
        authority_id: request.authority_id,
        action: request.action,
        resource: request.resource,
        time_requested: timeRequestedFor(request.context),
        time_evaluated: timeEvaluatedFor(request.context, this.clock),
        authorized: bundle.authorization?.status === "active",
        message: describeAuthorizationMessage(bundle),
        context: request.context,
        bundle,
      }),
    };
  }

  async queryRecognition(
    requestInput: TrqpRecognitionRequest,
  ): Promise<TrqpAdapterResult<TrqpRecognitionResponse>> {
    const request = TrqpRecognitionRequestSchema.parse(requestInput);
    const bundleResult = await this.resolveRecognitionBundle(request);

    if (!bundleResult.ok) {
      return bundleResult;
    }

    const bundle = bundleResult.value;

    return {
      ok: true,
      value: TrqpRecognitionResponseSchema.parse({
        entity_id: request.entity_id,
        authority_id: request.authority_id,
        action: request.action,
        resource: request.resource,
        time_requested: timeRequestedFor(request.context),
        time_evaluated: timeEvaluatedFor(request.context, this.clock),
        recognized: bundle.recognition?.status === "active",
        message: describeRecognitionMessage(bundle),
        context: request.context,
      }),
    };
  }

  async getRecognitionEvidence(
    requestInput: TrqpRecognitionRequest,
  ): Promise<TrqpAdapterResult<TrqpRecognitionEvidenceResponse>> {
    const request = TrqpRecognitionRequestSchema.parse(requestInput);
    const bundleResult = await this.resolveRecognitionBundle(request);

    if (!bundleResult.ok) {
      return bundleResult;
    }

    const bundle = bundleResult.value;
    return {
      ok: true,
      value: TrqpRecognitionEvidenceResponseSchema.parse({
        entity_id: request.entity_id,
        authority_id: request.authority_id,
        action: request.action,
        resource: request.resource,
        time_requested: timeRequestedFor(request.context),
        time_evaluated: timeEvaluatedFor(request.context, this.clock),
        recognized: bundle.recognition?.status === "active",
        message: describeRecognitionMessage(bundle),
        context: request.context,
        bundle,
      }),
    };
  }

  private async resolveAuthorizationBundle(
    request: TrqpAuthorizationRequest,
  ): Promise<TrqpAdapterResult<TrustRegistryEvidenceBundle>> {
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

    const bundle = await this.source.getAuthorizationBundle(request);
    if (bundle === null) {
      return {
        ok: false,
        problem: notFoundProblem(
          this.problemBaseUri,
          `No authorization statement matched (${request.entity_id}, ${request.action}, ${request.resource}) under authority ${request.authority_id}.`,
        ),
      };
    }

    const parsedBundle = TrustRegistryEvidenceBundleSchema.parse(bundle);
    if (parsedBundle.authorization === undefined) {
      return {
        ok: false,
        problem: invalidSourceProblem(
          this.problemBaseUri,
          "Authorization query resolved to a bundle without an authorization statement.",
        ),
      };
    }

    return {
      ok: true,
      value: parsedBundle,
    };
  }

  private async resolveRecognitionBundle(
    request: TrqpRecognitionRequest,
  ): Promise<TrqpAdapterResult<TrustRegistryEvidenceBundle>> {
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

    const bundle = await this.source.getRecognitionBundle(request);
    if (bundle === null) {
      return {
        ok: false,
        problem: notFoundProblem(
          this.problemBaseUri,
          `No recognition statement matched (${request.entity_id}, ${request.action}, ${request.resource}) under authority ${request.authority_id}.`,
        ),
      };
    }

    const parsedBundle = TrustRegistryEvidenceBundleSchema.parse(bundle);
    if (parsedBundle.recognition === undefined) {
      return {
        ok: false,
        problem: invalidSourceProblem(
          this.problemBaseUri,
          "Recognition query resolved to a bundle without a recognition statement.",
        ),
      };
    }

    return {
      ok: true,
      value: parsedBundle,
    };
  }
}
