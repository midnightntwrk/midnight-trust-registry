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
  bundle?: TrustRegistryEvidenceBundle;
  statusAtTime: AuthorizationRecord["status"] | null;
  trustedAtTime: boolean;
};

export type TrqpRecognitionDecision = {
  bundle?: TrustRegistryEvidenceBundle;
  statusAtTime: RecognitionRecord["status"] | null;
  trustedAtTime: boolean;
};

export type TrustRegistryTrqpSource = {
  getRegistryRecord(authorityId: string): MaybePromise<RegistryRecord | null>;
  getAuthorizationDecision(
    request: TrqpAuthorizationRequest,
    evaluatedAt: string,
  ): MaybePromise<TrqpAuthorizationDecision | null>;
  getRecognitionDecision(
    request: TrqpRecognitionRequest,
    evaluatedAt: string,
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

const evidenceUnavailableProblem = (
  problemBaseUri: string,
): TrqpProblemDetails => normalizeProblem({
  type: `${problemBaseUri}/epoch-evidence-unavailable`,
  title: "epoch evidence unavailable",
  status: 424,
  detail: "The trust statement exists, but no epoch-bound evidence is available for the evaluation time.",
});

const describeAuthorizationMessage = (
  status: string,
  trusted: boolean,
  historical: boolean,
  withEvidence = false,
): string => {
  const when = historical ? "at the requested time" : "at the source evaluation time";
  const qualification = withEvidence
    ? "evidence bundle attached; verify its anchor and proof independently"
    : "this is a snapshot projection, not proof";
  return trusted
    ? `Authorization is active for the requested scope ${when}; ${qualification}.`
    : `Authorization is not trusted ${when} (status: ${status}); ${qualification}.`;
};

const describeRecognitionMessage = (
  status: string,
  trusted: boolean,
  historical: boolean,
  withEvidence = false,
): string => {
  const when = historical ? "at the requested time" : "at the source evaluation time";
  const qualification = withEvidence
    ? "evidence bundle attached; verify its anchor and proof independently"
    : "this is a snapshot projection, not proof";
  return trusted
    ? `Recognition is active for the requested scope ${when}; ${qualification}.`
    : `Recognition is not trusted ${when} (status: ${status}); ${qualification}.`;
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
    const evaluatedAt = timeEvaluatedFor(request.context, this.clock);
    const decisionResult = await this.resolveAuthorizationDecision(request, evaluatedAt, false);

    if (!decisionResult.ok) {
      return decisionResult;
    }

    const decision = decisionResult.value;
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
        message: describeAuthorizationMessage(decision.statusAtTime ?? "not yet proposed", authorized, request.context?.time !== undefined),
        context: request.context,
      }),
    };
  }

  async getAuthorizationEvidence(
    requestInput: TrqpAuthorizationRequest,
  ): Promise<TrqpAdapterResult<TrqpAuthorizationEvidenceResponse>> {
    const request = TrqpAuthorizationRequestSchema.parse(requestInput);
    const evaluatedAt = timeEvaluatedFor(request.context, this.clock);
    const decisionResult = await this.resolveAuthorizationDecision(request, evaluatedAt, true);

    if (!decisionResult.ok) {
      return decisionResult;
    }

    const decision = decisionResult.value;
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
        message: describeAuthorizationMessage(decision.statusAtTime ?? "not yet proposed", authorized, request.context?.time !== undefined, true),
        context: request.context,
        bundle: decision.bundle,
      }),
    };
  }

  async queryRecognition(
    requestInput: TrqpRecognitionRequest,
  ): Promise<TrqpAdapterResult<TrqpRecognitionResponse>> {
    const request = TrqpRecognitionRequestSchema.parse(requestInput);
    const evaluatedAt = timeEvaluatedFor(request.context, this.clock);
    const decisionResult = await this.resolveRecognitionDecision(request, evaluatedAt, false);

    if (!decisionResult.ok) {
      return decisionResult;
    }

    const decision = decisionResult.value;
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
        message: describeRecognitionMessage(decision.statusAtTime ?? "not yet proposed", recognized, request.context?.time !== undefined),
        context: request.context,
      }),
    };
  }

  async getRecognitionEvidence(
    requestInput: TrqpRecognitionRequest,
  ): Promise<TrqpAdapterResult<TrqpRecognitionEvidenceResponse>> {
    const request = TrqpRecognitionRequestSchema.parse(requestInput);
    const evaluatedAt = timeEvaluatedFor(request.context, this.clock);
    const decisionResult = await this.resolveRecognitionDecision(request, evaluatedAt, true);

    if (!decisionResult.ok) {
      return decisionResult;
    }

    const decision = decisionResult.value;
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
        message: describeRecognitionMessage(decision.statusAtTime ?? "not yet proposed", recognized, request.context?.time !== undefined, true),
        context: request.context,
        bundle: decision.bundle,
      }),
    };
  }

  private async resolveAuthorizationDecision(
    request: TrqpAuthorizationRequest,
    evaluatedAt: string,
    requireEvidence: boolean,
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

    const decision = await this.source.getAuthorizationDecision(request, evaluatedAt);
    if (decision === null) {
      return {
        ok: false,
        problem: notFoundProblem(
          this.problemBaseUri,
          `No authorization statement matched (${request.entity_id}, ${request.action}, ${request.resource}) under authority ${request.authority_id}.`,
        ),
      };
    }
    if (requireEvidence && decision.bundle === undefined) {
      return { ok: false, problem: evidenceUnavailableProblem(this.problemBaseUri) };
    }
    const parsedBundle = !requireEvidence || decision.bundle === undefined
      ? undefined
      : TrustRegistryEvidenceBundleSchema.parse(decision.bundle);
    if (parsedBundle !== undefined && parsedBundle.authorization === undefined) {
      return {
        ok: false,
        problem: invalidSourceProblem(
          this.problemBaseUri,
          "Authorization query resolved to a bundle without an authorization statement.",
        ),
      };
    }
    if (requireEvidence && parsedBundle !== undefined) {
      const instant = Date.parse(evaluatedAt);
      if (instant < Date.parse(parsedBundle.epoch.validFrom)
        || instant > Date.parse(parsedBundle.epoch.validUntil)) {
        return { ok: false, problem: evidenceUnavailableProblem(this.problemBaseUri) };
      }
    }
    if (decision.trustedAtTime && decision.statusAtTime !== "active") {
      return {
        ok: false,
        problem: invalidSourceProblem(this.problemBaseUri, "Trusted authorization must be active at the evaluation time."),
      };
    }

    return {
      ok: true,
      value: { ...decision, ...(parsedBundle === undefined ? {} : { bundle: parsedBundle }) },
    };
  }

  private async resolveRecognitionDecision(
    request: TrqpRecognitionRequest,
    evaluatedAt: string,
    requireEvidence: boolean,
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

    const decision = await this.source.getRecognitionDecision(request, evaluatedAt);
    if (decision === null) {
      return {
        ok: false,
        problem: notFoundProblem(
          this.problemBaseUri,
          `No recognition statement matched (${request.entity_id}, ${request.action}, ${request.resource}) under authority ${request.authority_id}.`,
        ),
      };
    }
    if (requireEvidence && decision.bundle === undefined) {
      return { ok: false, problem: evidenceUnavailableProblem(this.problemBaseUri) };
    }
    const parsedBundle = !requireEvidence || decision.bundle === undefined
      ? undefined
      : TrustRegistryEvidenceBundleSchema.parse(decision.bundle);
    if (parsedBundle !== undefined && parsedBundle.recognition === undefined) {
      return {
        ok: false,
        problem: invalidSourceProblem(
          this.problemBaseUri,
          "Recognition query resolved to a bundle without a recognition statement.",
        ),
      };
    }
    if (requireEvidence && parsedBundle !== undefined) {
      const instant = Date.parse(evaluatedAt);
      if (instant < Date.parse(parsedBundle.epoch.validFrom)
        || instant > Date.parse(parsedBundle.epoch.validUntil)) {
        return { ok: false, problem: evidenceUnavailableProblem(this.problemBaseUri) };
      }
    }
    if (decision.trustedAtTime && decision.statusAtTime !== "active") {
      return {
        ok: false,
        problem: invalidSourceProblem(this.problemBaseUri, "Trusted recognition must be active at the evaluation time."),
      };
    }

    return {
      ok: true,
      value: { ...decision, ...(parsedBundle === undefined ? {} : { bundle: parsedBundle }) },
    };
  }
}
