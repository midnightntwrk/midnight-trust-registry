import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { z, ZodError } from "zod";

import { TrustRegistryOperatorWorkspaceOperationSchema } from "@midnight-ntwrk/trust-registry-cli";
import { MutationIntentSchema, MutationIntentSignatureSchema, SignedPendingApplicationSchema } from "@midnight-ntwrk/trust-registry-domain";

import {
  TrustRegistryTrqpAdapter,
  TrqpAuthorizationRequestSchema,
  TrqpRecognitionRequestSchema,
} from "@midnight-ntwrk/trust-registry-trqp-adapter";

import {
  applyMutationOperation,
  applySignedMutationOperation,
  evaluateAuthorizationEntryAtTimestamp,
  evaluateRecognitionEntryAtTimestamp,
  createTrqpSourceFromStateSource,
  getAuthorizationEntryById,
  getRecognitionEntryById,
  isMutableStateSource,
  listAuthorizationEntries,
  listRecognitionEntries,
  loadEpochAtTimestamp,
  loadCurrentEpoch,
  loadEpochById,
  loadRegistryRecord,
  loadRegistrySummary,
  resolveAuthorizationEntry,
  resolveRecognitionEntry,
  type TrustRegistryApiMutationResult,
  type TrustRegistryApiStateSource,
  WorkspaceMutationLockedError,
} from "./source.js";
import { MutationIntentDidResolutionUnavailableError, verifyMutationIntentDidSignature } from "./mutation-intent-verifier.js";
import {
  decodeGovernedMembershipSigners,
  GovernedMembershipActionReceiptSchema,
  GovernedMembershipActionRejectedError,
  GovernedMembershipActionSchema,
  GovernedMembershipRoleSchema,
  GovernedMembershipSignatureRequestSchema,
  sameGovernedMembershipAction,
  serializeGovernedMembershipAction,
  type GovernedMembershipActionPort,
} from "./governed-membership-actions.js";
import {
  decodeIssuerEvidenceVerifierSignature,
  GovernedIssuerProposalObservationSchema,
  GovernedIssuerProposalPrepareRequestSchema,
  GovernedIssuerProposalRejectedError,
  GovernedIssuerProposalSubmitRequestSchema,
  sameGovernedIssuerProposal,
  serializeGovernedIssuerProposal,
  type GovernedIssuerProposalPort,
} from "./governed-issuer-proposals.js";
import {
  decodeVerifierEvidenceVerifierSignature,
  GovernedVerifierProposalPrepareRequestSchema,
  GovernedVerifierProposalRejectedError,
  GovernedVerifierProposalSubmitRequestSchema,
  sameGovernedVerifierProposal,
  serializeGovernedVerifierProposal,
  type GovernedVerifierProposalPort,
} from "./governed-verifier-proposals.js";
import {
  decodeAuditorEvidenceVerifierSignature,
  GovernedAuditorProposalPrepareRequestSchema,
  GovernedAuditorProposalRejectedError,
  GovernedAuditorProposalSubmitRequestSchema,
  sameGovernedAuditorProposal,
  serializeGovernedAuditorProposal,
  type GovernedAuditorProposalPort,
} from "./governed-auditor-proposals.js";
import {
  decodeMaintainerEvidenceVerifierSignature,
  GovernedMaintainerProposalPrepareRequestSchema,
  GovernedMaintainerProposalRejectedError,
  GovernedMaintainerProposalSubmitRequestSchema,
  sameGovernedMaintainerProposal,
  serializeGovernedMaintainerProposal,
  type GovernedMaintainerProposalPort,
} from "./governed-maintainer-proposals.js";
import {
  ApplicationVpHttpError,
  createApplicationVpHttpService,
  type ApplicationVpHttpPort,
} from "./application-vp-http.js";
import {
  PendingApplicationRegistrationRejectedError,
  type PendingApplicationRegistrationPort,
} from "./pending-application-registration.js";
import {
  assertProposalAdmission,
  type ProposalAdmissionPort,
} from "./proposal-admission.js";
import { MutationIntentOperationMismatchError } from "./mutation-intent-preflight.js";
import { MutationIntentActorRejectedError, MutationNonceAlreadyUsedError } from "./signed-mutation-state.js";
import { computeOperatorWorkspaceCommitment } from "./workspace-commitment.js";
import {
  TrustRegistryApiApplicationActionSchema,
  TrustRegistryApiApplicationMutationResponseSchema,
  TrustRegistryApiApplicationSubmitRequestSchema,
  TrustRegistryApiApplicationTargetSchema,
  TrustRegistryApiAuthorizationEvaluationResponseSchema,
  TrustRegistryApiAuthorizationListQuerySchema,
  TrustRegistryApiAuthorizationListResponseSchema,
  TrustRegistryApiAuthorizationResponseSchema,
  TrustRegistryApiEpochResponseSchema,
  TrustRegistryApiEpochPublishRequestSchema,
  TrustRegistryApiEvaluateAuthorizationRequestSchema,
  TrustRegistryApiEvaluateRecognitionRequestSchema,
  TrustRegistryApiEvidenceResponseSchema,
  TrustRegistryApiHealthResponseSchema,
  TrustRegistryApiMutationContextSchema,
  TrustRegistryApiProblemDetailsSchema,
  TrustRegistryApiRecognitionEvaluationResponseSchema,
  TrustRegistryApiRecognitionListQuerySchema,
  TrustRegistryApiRecognitionListResponseSchema,
  TrustRegistryApiRecognitionResponseSchema,
  TrustRegistryApiRegistryResponseSchema,
  TrustRegistryApiResolveAuthorizationRequestSchema,
  TrustRegistryApiResolveRecognitionRequestSchema,
  TrustRegistryApiSummarySchema,
  TrustRegistryApiAuthorizationRoleSchema,
  TimestampSchema,
  type TrustRegistryApiProblemDetails,
} from "./schemas.js";

const DEFAULT_PROBLEM_BASE = "https://midnight.network/problems/trust-registry-api";
const MAX_REQUEST_BODY_BYTES = 1024 * 1024;

class HttpProblem extends Error {
  constructor(
    readonly problem: TrustRegistryApiProblemDetails,
  ) {
    super(problem.detail ?? problem.title);
  }
}

export type TrustRegistryApiServerOptions = {
  source: TrustRegistryApiStateSource;
  clock?: () => string;
  problemBaseUri?: string;
  mutationDidResolver?: Parameters<typeof verifyMutationIntentDidSignature>[2];
  allowUnsafeDemoMutations?: boolean;
  governedMembershipActions?: GovernedMembershipActionPort;
  governedIssuerProposals?: GovernedIssuerProposalPort;
  governedVerifierProposals?: GovernedVerifierProposalPort;
  governedAuditorProposals?: GovernedAuditorProposalPort;
  governedMaintainerProposals?: GovernedMaintainerProposalPort;
  applicationVp?: ApplicationVpHttpPort;
  proposalAdmission?: ProposalAdmissionPort;
  pendingApplicationRegistration?: PendingApplicationRegistrationPort;
  authorizePendingApplicationRegistration?: (request: IncomingMessage) => Promise<void>;
  nonApiGetHandler?: (request: IncomingMessage, response: ServerResponse) => Promise<void>;
};

const SignedMutationRequestSchema = z.strictObject({
  intent: MutationIntentSchema,
  signature: MutationIntentSignatureSchema,
  operation: TrustRegistryOperatorWorkspaceOperationSchema,
});

const jsonProblem = (
  problemBaseUri: string,
  typeSlug: string,
  status: number,
  title: string,
  detail?: string,
): HttpProblem =>
  new HttpProblem(
    TrustRegistryApiProblemDetailsSchema.parse({
      type: `${problemBaseUri}/${typeSlug}`,
      title,
      status,
      detail,
    }),
  );

const readRequestBody = async (
  request: IncomingMessage,
  problemBaseUri: string,
): Promise<string> =>
  new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    let settled = false;
    request.on("data", (chunk) => {
      if (settled) {
        return;
      }
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalSize += buffer.byteLength;
      if (totalSize > MAX_REQUEST_BODY_BYTES) {
        settled = true;
        reject(
          jsonProblem(
            problemBaseUri,
            "payload-too-large",
            413,
            "payload too large",
            `Request body exceeds ${MAX_REQUEST_BODY_BYTES.toString()} bytes.`,
          ),
        );
        request.destroy();
        return;
      }
      chunks.push(buffer);
    });
    request.on("end", () => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    request.on("error", (error) => {
      if (settled) {
        return;
      }
      settled = true;
      reject(error);
    });
  });

const parseJsonBody = async <T>(
  request: IncomingMessage,
  parse: (value: unknown) => T,
  problemBaseUri: string,
): Promise<T> => {
  const raw = await readRequestBody(request, problemBaseUri);
  const payload = raw.length === 0 ? {} : JSON.parse(raw);
  return parse(payload);
};

const writeJson = (
  response: ServerResponse,
  status: number,
  payload: unknown,
  publicCors = true,
): void => {
  response.statusCode = status;
  if (publicCors) setCorsHeaders(response);
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.end(`${JSON.stringify(payload, null, 2)}\n`);
};

const setCorsHeaders = (
  response: ServerResponse,
): void => {
  response.setHeader("access-control-allow-origin", "*");
  response.setHeader("access-control-allow-headers", "content-type");
  response.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
};

const writeNoContent = (
  response: ServerResponse,
  publicCors = true,
): void => {
  response.statusCode = 204;
  if (publicCors) setCorsHeaders(response);
  response.end();
};

const asProblem = (
  error: unknown,
  problemBaseUri: string,
): TrustRegistryApiProblemDetails => {
  if (error instanceof HttpProblem) {
    return error.problem;
  }
  if (error instanceof SyntaxError) {
    return TrustRegistryApiProblemDetailsSchema.parse({
      type: `${problemBaseUri}/invalid-json`,
      title: "invalid json",
      status: 400,
      detail: error.message,
    });
  }
  if (error instanceof ZodError) {
    return TrustRegistryApiProblemDetailsSchema.parse({
      type: `${problemBaseUri}/invalid-request`,
      title: "invalid request",
      status: 400,
      detail: error.issues.map((issue) => issue.message).join("; "),
    });
  }

  return TrustRegistryApiProblemDetailsSchema.parse({
    type: `${problemBaseUri}/internal-error`,
    title: "internal error",
    status: 500,
    detail: error instanceof Error ? error.message : String(error),
  });
};

const routeSegments = (pathname: string): string[] =>
  pathname
    .split("/")
    .filter((segment) => segment.length > 0)
    .map((segment) => decodeURIComponent(segment));

const buildMutationResponse = (
  result: TrustRegistryApiMutationResult,
): Record<string, unknown> => ({
  sourceMode: "workspace",
  workspaceVersion: result.workspace.workspaceVersion,
  workspaceUpdatedAt: result.workspace.updatedAt,
  snapshotGeneratedAt: result.workspace.snapshot.generatedAt,
  currentEpochId: result.workspace.snapshot.currentEpoch.epochId,
  operation: result.operation,
  ...(result.record.recordKind === "authorization"
    ? {
        recordKind: "authorization",
        entry: result.record.entry,
      }
    : result.record.recordKind === "recognition"
      ? {
          recordKind: "recognition",
          entry: result.record.entry,
        }
      : {
          recordKind: "epoch",
          epoch: result.record.epoch,
        }),
});

const requireAuthorizationEntry = async (
  source: TrustRegistryApiStateSource,
  roleInput: string,
  authorizationId: string,
  problemBaseUri: string,
) => {
  const role = TrustRegistryApiAuthorizationRoleSchema.parse(roleInput);
  const entry = await getAuthorizationEntryById(source, role, authorizationId);
  if (entry === null) {
    throw jsonProblem(
      problemBaseUri,
      "authorization-not-found",
      404,
      "authorization not found",
      `No ${role} authorization exists for id ${authorizationId}.`,
    );
  }

  return TrustRegistryApiAuthorizationResponseSchema.parse(entry);
};

const requireRecognitionEntry = async (
  source: TrustRegistryApiStateSource,
  recognitionId: string,
  problemBaseUri: string,
) => {
  const entry = await getRecognitionEntryById(source, recognitionId);
  if (entry === null) {
    throw jsonProblem(
      problemBaseUri,
      "recognition-not-found",
      404,
      "recognition not found",
      `No recognition exists for id ${recognitionId}.`,
    );
  }

  return TrustRegistryApiRecognitionResponseSchema.parse(entry);
};

const requireMutableSource = (
  source: TrustRegistryApiStateSource,
  problemBaseUri: string,
) => {
  if (!isMutableStateSource(source)) {
    throw jsonProblem(
      problemBaseUri,
      "workspace-source-required",
      409,
      "workspace source required",
      "This route requires a mutable operator workspace source.",
    );
  }

  return source;
};

const parseApplicationTarget = (
  targetInput: string,
  problemBaseUri: string,
) => {
  const parsed = TrustRegistryApiApplicationTargetSchema.safeParse(targetInput);
  if (!parsed.success) {
    throw jsonProblem(
      problemBaseUri,
      "invalid-path-parameter",
      400,
      "invalid path parameter",
      `Unsupported application target: ${targetInput}.`,
    );
  }

  return parsed.data;
};

const parseApplicationAction = (
  actionInput: string,
  problemBaseUri: string,
) => {
  const parsed = TrustRegistryApiApplicationActionSchema.safeParse(actionInput);
  if (!parsed.success) {
    throw jsonProblem(
      problemBaseUri,
      "invalid-path-parameter",
      400,
      "invalid path parameter",
      `Unsupported application action: ${actionInput}.`,
    );
  }

  return parsed.data;
};

const parseApplicationIdentifier = (
  idInput: string,
  problemBaseUri: string,
) => {
  const parsed = z.string().trim().min(1).safeParse(idInput);
  if (!parsed.success) {
    throw jsonProblem(
      problemBaseUri,
      "invalid-path-parameter",
      400,
      "invalid path parameter",
      "Application identifier must be a non-empty string.",
    );
  }

  return parsed.data;
};

const parseTimestampQueryParameter = (
  value: string | null,
  name: string,
  problemBaseUri: string,
) => {
  if (value === null) {
    throw jsonProblem(
      problemBaseUri,
      "invalid-request",
      400,
      "invalid request",
      `Query parameter ${name} is required.`,
    );
  }

  const parsed = TimestampSchema.safeParse(value);
  if (!parsed.success) {
    throw jsonProblem(
      problemBaseUri,
      "invalid-request",
      400,
      "invalid request",
      `Query parameter ${name} must be an RFC 3339 timestamp with offset.`,
    );
  }

  return parsed.data;
};

const mapMutationError = (
  error: unknown,
  problemBaseUri: string,
): never => {
  if (error instanceof HttpProblem) {
    throw error;
  }
  if (error instanceof MutationIntentDidResolutionUnavailableError) {
    throw jsonProblem(problemBaseUri, "did-resolution-unavailable", 503, "did resolution unavailable");
  }
  if (error instanceof MutationIntentActorRejectedError) {
    const status = error.reason === "invalid-signature" ? 401
      : ["stale-epoch", "stale-workspace"].includes(error.reason) ? 409 : 403;
    throw jsonProblem(problemBaseUri, "signed-intent-rejected", status, "signed intent rejected", error.reason);
  }
  if (error instanceof MutationNonceAlreadyUsedError) {
    throw jsonProblem(problemBaseUri, "mutation-replay", 409, "mutation replay", error.message);
  }
  if (error instanceof WorkspaceMutationLockedError) {
    throw jsonProblem(problemBaseUri, "workspace-locked", 409, "workspace locked", error.message);
  }
  if (error instanceof MutationIntentOperationMismatchError) {
    throw jsonProblem(problemBaseUri, "signed-operation-mismatch", 403, "signed operation mismatch", error.message);
  }
  if (error instanceof Error) {
    if (["issuer", "verifier", "auditor"].some((role) =>
      error.message.startsWith(`unknown ${role} authorization:`))) {
      throw jsonProblem(
        problemBaseUri,
        "authorization-not-found",
        404,
        "authorization not found",
        error.message,
      );
    }
    if (error.message.startsWith("unknown recognition:")) {
      throw jsonProblem(
        problemBaseUri,
        "recognition-not-found",
        404,
        "recognition not found",
        error.message,
      );
    }
    if (["issuer", "verifier", "auditor", "recognition"].some((role) =>
      error.message.startsWith(`${role} label already submitted:`))) {
      throw jsonProblem(
        problemBaseUri,
        "duplicate-application",
        409,
        "duplicate application",
        error.message,
      );
    }
  }

  throw error;
};

const requireUnsafeDemoMutations = (
  options: TrustRegistryApiServerOptions,
  problemBaseUri: string,
): void => {
  if (!options.allowUnsafeDemoMutations) {
    throw jsonProblem(problemBaseUri, "signed-mutation-required", 403,
      "signed mutation required", "Use POST /v1/mutations with a DID-signed intent.");
  }
};

const requireGovernedMembershipActions = (
  options: TrustRegistryApiServerOptions,
  problemBaseUri: string,
): GovernedMembershipActionPort => {
  if (options.governedMembershipActions === undefined) {
    throw jsonProblem(problemBaseUri, "governed-membership-unavailable", 503,
      "governed membership unavailable", "A Compact-backed membership action port is not configured.");
  }
  return options.governedMembershipActions;
};

const mapGovernedMembershipError = (error: unknown, problemBaseUri: string): never => {
  if (error instanceof GovernedMembershipActionRejectedError) {
    const unknown = error.reason === "unknown-authorization";
    throw jsonProblem(problemBaseUri, unknown ? "authorization-not-found" : "governed-action-rejected",
      unknown ? 404 : 403, unknown ? "authorization not found" : "governed action rejected");
  }
  throw error;
};

const mapGovernedIssuerProposalError = (error: unknown, problemBaseUri: string): never => {
  if (error instanceof GovernedIssuerProposalRejectedError) {
    const unknown = error.reason === "unknown-authorization";
    throw jsonProblem(problemBaseUri, unknown ? "authorization-not-found" : "governed-proposal-rejected",
      unknown ? 404 : 403, unknown ? "authorization not found" : "governed proposal rejected",
      error.reason);
  }
  throw error;
};

const mapGovernedVerifierProposalError = (error: unknown, problemBaseUri: string): never => {
  if (error instanceof GovernedVerifierProposalRejectedError) {
    const unknown = error.reason === "unknown-authorization";
    throw jsonProblem(problemBaseUri, unknown ? "authorization-not-found" : "governed-proposal-rejected",
      unknown ? 404 : 403, unknown ? "authorization not found" : "governed proposal rejected",
      error.reason);
  }
  throw error;
};

const mapGovernedAuditorProposalError = (error: unknown, problemBaseUri: string): never => {
  if (error instanceof GovernedAuditorProposalRejectedError) {
    const unknown = error.reason === "unknown-authorization";
    throw jsonProblem(problemBaseUri, unknown ? "authorization-not-found" : "governed-proposal-rejected",
      unknown ? 404 : 403, unknown ? "authorization not found" : "governed proposal rejected",
      error.reason);
  }
  throw error;
};

const mapGovernedMaintainerProposalError = (error: unknown, problemBaseUri: string): never => {
  if (error instanceof GovernedMaintainerProposalRejectedError) {
    const unknown = error.reason === "unknown-maintainer";
    throw jsonProblem(problemBaseUri, unknown ? "maintainer-not-found" : "governed-proposal-rejected",
      unknown ? 404 : 403, unknown ? "maintainer not found" : "governed proposal rejected",
      error.reason);
  }
  throw error;
};

const performMutation = async (
  source: ReturnType<typeof requireMutableSource>,
  operation: Parameters<typeof applyMutationOperation>[1],
  problemBaseUri: string,
): Promise<TrustRegistryApiMutationResult> => {
  try {
    return await applyMutationOperation(source, operation);
  } catch (error) {
    return mapMutationError(error, problemBaseUri);
  }
};

export const createTrustRegistryApiServer = (
  options: TrustRegistryApiServerOptions,
): Server => {
  if (options.applicationVp !== undefined
    && (options.governedIssuerProposals !== undefined || options.governedVerifierProposals !== undefined
      || options.governedAuditorProposals !== undefined || options.governedMaintainerProposals !== undefined)
    && options.proposalAdmission === undefined) {
    throw new Error("Combined VP intake and governed proposals require an accepted-application admission port");
  }
  const problemBaseUri = options.problemBaseUri ?? DEFAULT_PROBLEM_BASE;
  const trqpAdapter = new TrustRegistryTrqpAdapter(
    createTrqpSourceFromStateSource(options.source),
    {
      ...(options.clock === undefined ? {} : { clock: options.clock }),
      problemBaseUri: `${problemBaseUri}/trqp`,
    },
  );
  const applicationVp = options.applicationVp === undefined ? undefined
    : createApplicationVpHttpService(options.applicationVp, () => Date.parse(options.clock?.() ?? new Date().toISOString()));

  const requireProposalAdmission = async (
    role: "issuer" | "verifier" | "auditor" | "maintainer",
    authorizationId: string,
    evidence: Parameters<typeof assertProposalAdmission>[3],
  ): Promise<void> => {
    if (options.proposalAdmission === undefined) return;
    try {
      await assertProposalAdmission(options.proposalAdmission, role, authorizationId, evidence);
    } catch {
      throw jsonProblem(problemBaseUri, "unadmitted-proposal", 403,
        "unadmitted proposal", "The proposal has no matching accepted application VP receipt.");
    }
  };

  return createServer(async (request, response) => {
    let privateApplicantRoute = false;
    try {
      const method = request.method ?? "GET";
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      const segments = routeSegments(url.pathname);
      privateApplicantRoute = segments[0] === "v1" && (
        (segments.length === 4 && segments[1] === "application-evidence"
          && (segments[3] === "binding" || segments[3] === "challenges" || segments[3] === "submissions"))
        || (segments.length === 2 && segments[1] === "pending-applications")
      );

      if (method === "OPTIONS") {
        writeNoContent(response, !privateApplicantRoute);
        return;
      }

      if (method === "GET" && segments.length === 1 && segments[0] === "health") {
        const summary = await loadRegistrySummary(options.source);
        writeJson(
          response,
          200,
          TrustRegistryApiHealthResponseSchema.parse({
            status: "ok",
            sourceMode: options.source.mode,
            generatedAt: summary.generatedAt,
            registryId: summary.registryId,
          }),
        );
        return;
      }

      if (method === "GET" && segments.length === 2 && segments[0] === "v1" && segments[1] === "registry") {
        writeJson(
          response,
          200,
          TrustRegistryApiRegistryResponseSchema.parse(
            await loadRegistryRecord(options.source),
          ),
        );
        return;
      }

      if (method === "GET" && segments.length === 3 && segments[0] === "v1"
        && segments[1] === "registry" && segments[2] === "mutation-context") {
        const workspace = await requireMutableSource(options.source, problemBaseUri).loadWorkspace();
        response.setHeader("cache-control", "no-store");
        writeJson(response, 200, TrustRegistryApiMutationContextSchema.parse({
          registryId: workspace.snapshot.registry.registryId,
          expectedEpochId: workspace.snapshot.currentEpoch.epochId,
          expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(workspace),
        }));
        return;
      }

      if (method === "POST" && segments.length === 2 && segments[0] === "v1"
        && segments[1] === "pending-applications") {
        response.setHeader("cache-control", "no-store");
        const port = options.pendingApplicationRegistration;
        if (port === undefined) {
          throw jsonProblem(problemBaseUri, "pending-application-unavailable", 503, "pending application unavailable");
        }
        if (options.authorizePendingApplicationRegistration !== undefined) {
          try {
            await options.authorizePendingApplicationRegistration(request);
          } catch {
            throw jsonProblem(problemBaseUri, "pending-application-forbidden", 403, "pending application forbidden");
          }
        }
        const requestBody = await parseJsonBody(request, (value) => SignedPendingApplicationSchema.parse(value), problemBaseUri);
        try {
          const record = await port.register(requestBody, new Date(options.clock?.() ?? new Date().toISOString()));
          writeJson(response, 201, record, false);
          return;
        } catch (error) {
          if (error instanceof PendingApplicationRegistrationRejectedError) {
            const status = error.reason === "invalid-signature" ? 401
              : error.reason.startsWith("duplicate-") || error.reason === "nonce-used"
                || error.reason === "stale-epoch" || error.reason === "stale-workspace"
                || error.reason === "expired" || error.reason === "not-yet-valid" ? 409 : 403;
            throw jsonProblem(problemBaseUri, `pending-application-${error.reason}`, status,
              "pending application rejected");
          }
          if (error instanceof MutationIntentDidResolutionUnavailableError) {
            throw jsonProblem(problemBaseUri, "did-resolution-unavailable", 503, "DID resolution unavailable");
          }
          throw error;
        }
      }

      if ((method === "POST" || method === "GET") && segments.length === 4 && segments[0] === "v1"
        && segments[1] === "application-evidence"
        && (segments[3] === "challenges" || segments[3] === "submissions" || segments[3] === "binding")
        && (method === "GET") === (segments[3] === "binding")) {
        response.setHeader("cache-control", "no-store");
        if (applicationVp === undefined || options.applicationVp === undefined) {
          throw jsonProblem(problemBaseUri, "application-vp-unavailable", 503, "application VP unavailable");
        }
        try {
          await options.applicationVp.authorizeRequest(segments[2]!, request);
        } catch {
          throw jsonProblem(problemBaseUri, "application-vp-forbidden", 403, "application VP forbidden");
        }
        try {
          if (segments[3] === "binding") {
            writeJson(response, 200, await applicationVp.binding(segments[2]!), false);
            return;
          }
          const raw = await readRequestBody(request, problemBaseUri);
          let body: unknown;
          try {
            body = JSON.parse(raw);
          } catch {
            throw new ApplicationVpHttpError("invalid-request");
          }
          const result = segments[3] === "challenges"
            ? await applicationVp.issue(segments[2]!, body)
            : await applicationVp.submit(segments[2]!, body);
          writeJson(response, segments[3] === "challenges" ? 201 : 202, result, false);
          return;
        } catch (error) {
          if (error instanceof HttpProblem) throw error;
          const reason = error instanceof ApplicationVpHttpError ? error.reason : "rejected";
          const status = reason === "invalid-request" ? 400 : reason === "not-found" ? 404
            : reason === "stale-policy" || reason === "invalid-challenge" ? 409 : 403;
          throw jsonProblem(problemBaseUri, `application-vp-${reason}`, status, `application VP ${reason}`);
        }
      }

      if (
        method === "POST"
        && segments.length === 6
        && segments[0] === "v1"
        && segments[1] === "governed"
        && segments[2] === "issuer"
        && segments[4] === "proposal"
        && (segments[5] === "prepare" || segments[5] === "submit" || segments[5] === "resolve")
      ) {
        const port = options.governedIssuerProposals;
        if (port === undefined) {
          throw jsonProblem(problemBaseUri, "governed-proposal-unavailable", 503,
            "governed proposal unavailable", "A Compact-backed issuer proposal port is not configured.");
        }
        const authorizationId = parseApplicationIdentifier(segments[3]!, problemBaseUri);
        response.setHeader("cache-control", "no-store");
        if (segments[5] === "resolve") {
          const body = await parseJsonBody(request,
            (value) => GovernedIssuerProposalPrepareRequestSchema.parse(value), problemBaseUri);
          await requireProposalAdmission("issuer", authorizationId, body.evidence);
          if (port.resolve === undefined) {
            throw jsonProblem(problemBaseUri, "governed-proposal-resolution-unavailable", 503,
              "governed proposal resolution unavailable");
          }
          let observed;
          try {
            observed = await port.resolve(authorizationId);
          } catch (error) {
            return mapGovernedIssuerProposalError(error, problemBaseUri);
          }
          if (observed === null) {
            writeJson(response, 200, { state: "not-observed" });
            return;
          }
          const record = GovernedIssuerProposalObservationSchema.parse(observed);
          if (record.evidenceCommitment !== body.evidence.commitment) {
            throw jsonProblem(problemBaseUri, "proposal-evidence-mismatch", 409,
              "proposal evidence mismatch", "The ledger proposal belongs to another evidence commitment.");
          }
          writeJson(response, 200, { state: "observed", eventHash: record.eventHash });
          return;
        }
        if (segments[5] === "prepare") {
          const body = await parseJsonBody(request,
            (value) => GovernedIssuerProposalPrepareRequestSchema.parse(value), problemBaseUri);
          await requireProposalAdmission("issuer", authorizationId, body.evidence);
          try {
            writeJson(response, 200, serializeGovernedIssuerProposal(
              await port.prepare(authorizationId, body.evidence),
            ));
            return;
          } catch (error) {
            return mapGovernedIssuerProposalError(error, problemBaseUri);
          }
        }
        const body = await parseJsonBody(request,
          (value) => GovernedIssuerProposalSubmitRequestSchema.parse(value), problemBaseUri);
        await requireProposalAdmission("issuer", authorizationId, body.evidence);
        let prepared;
        try {
          prepared = serializeGovernedIssuerProposal(await port.prepare(authorizationId, body.evidence));
        } catch (error) {
          return mapGovernedIssuerProposalError(error, problemBaseUri);
        }
        if (!sameGovernedIssuerProposal(prepared, body.prepared)) {
          throw jsonProblem(problemBaseUri, "stale-governed-proposal", 409,
            "stale governed proposal", "The signed proposal context no longer matches current ledger state.");
        }
        let signers;
        let evidenceVerifierSignature;
        try {
          signers = decodeGovernedMembershipSigners(body);
          evidenceVerifierSignature = decodeIssuerEvidenceVerifierSignature(body.evidenceVerifierSignature);
        } catch {
          throw jsonProblem(problemBaseUri, "invalid-governed-signature", 400,
            "invalid governed signature");
        }
        try {
          const receipt = GovernedMembershipActionReceiptSchema.parse(
            await port.execute(authorizationId, body.evidence, signers, evidenceVerifierSignature),
          );
          writeJson(response, 202, receipt);
          return;
        } catch (error) {
          return mapGovernedIssuerProposalError(error, problemBaseUri);
        }
      }

      if (
        method === "POST"
        && segments.length === 6
        && segments[0] === "v1"
        && segments[1] === "governed"
        && segments[2] === "verifier"
        && segments[4] === "proposal"
        && (segments[5] === "prepare" || segments[5] === "submit")
      ) {
        const port = options.governedVerifierProposals;
        if (port === undefined) {
          throw jsonProblem(problemBaseUri, "governed-proposal-unavailable", 503,
            "governed proposal unavailable", "A Compact-backed verifier proposal port is not configured.");
        }
        const authorizationId = parseApplicationIdentifier(segments[3]!, problemBaseUri);
        response.setHeader("cache-control", "no-store");
        if (segments[5] === "prepare") {
          const body = await parseJsonBody(request,
            (value) => GovernedVerifierProposalPrepareRequestSchema.parse(value), problemBaseUri);
          await requireProposalAdmission("verifier", authorizationId, body.evidence);
          try {
            writeJson(response, 200, serializeGovernedVerifierProposal(
              await port.prepare(authorizationId, body.evidence),
            ));
            return;
          } catch (error) {
            return mapGovernedVerifierProposalError(error, problemBaseUri);
          }
        }
        const body = await parseJsonBody(request,
          (value) => GovernedVerifierProposalSubmitRequestSchema.parse(value), problemBaseUri);
        await requireProposalAdmission("verifier", authorizationId, body.evidence);
        let prepared;
        try {
          prepared = serializeGovernedVerifierProposal(await port.prepare(authorizationId, body.evidence));
        } catch (error) {
          return mapGovernedVerifierProposalError(error, problemBaseUri);
        }
        if (!sameGovernedVerifierProposal(prepared, body.prepared)) {
          throw jsonProblem(problemBaseUri, "stale-governed-proposal", 409,
            "stale governed proposal", "The signed proposal context no longer matches current ledger state.");
        }
        let signers;
        let evidenceVerifierSignature;
        try {
          signers = decodeGovernedMembershipSigners(body);
          evidenceVerifierSignature = decodeVerifierEvidenceVerifierSignature(body.evidenceVerifierSignature);
        } catch {
          throw jsonProblem(problemBaseUri, "invalid-governed-signature", 400,
            "invalid governed signature");
        }
        try {
          const receipt = GovernedMembershipActionReceiptSchema.parse(
            await port.execute(authorizationId, body.evidence, signers, evidenceVerifierSignature),
          );
          writeJson(response, 202, receipt);
          return;
        } catch (error) {
          return mapGovernedVerifierProposalError(error, problemBaseUri);
        }
      }

      if (
        method === "POST"
        && segments.length === 6
        && segments[0] === "v1"
        && segments[1] === "governed"
        && segments[2] === "auditor"
        && segments[4] === "proposal"
        && (segments[5] === "prepare" || segments[5] === "submit")
      ) {
        const port = options.governedAuditorProposals;
        if (port === undefined) {
          throw jsonProblem(problemBaseUri, "governed-proposal-unavailable", 503,
            "governed proposal unavailable", "A Compact-backed auditor proposal port is not configured.");
        }
        const authorizationId = parseApplicationIdentifier(segments[3]!, problemBaseUri);
        response.setHeader("cache-control", "no-store");
        if (segments[5] === "prepare") {
          const body = await parseJsonBody(request,
            (value) => GovernedAuditorProposalPrepareRequestSchema.parse(value), problemBaseUri);
          await requireProposalAdmission("auditor", authorizationId, body.evidence);
          try {
            writeJson(response, 200, serializeGovernedAuditorProposal(
              await port.prepare(authorizationId, body.evidence),
            ));
            return;
          } catch (error) {
            return mapGovernedAuditorProposalError(error, problemBaseUri);
          }
        }
        const body = await parseJsonBody(request,
          (value) => GovernedAuditorProposalSubmitRequestSchema.parse(value), problemBaseUri);
        await requireProposalAdmission("auditor", authorizationId, body.evidence);
        let prepared;
        try {
          prepared = serializeGovernedAuditorProposal(await port.prepare(authorizationId, body.evidence));
        } catch (error) {
          return mapGovernedAuditorProposalError(error, problemBaseUri);
        }
        if (!sameGovernedAuditorProposal(prepared, body.prepared)) {
          throw jsonProblem(problemBaseUri, "stale-governed-proposal", 409,
            "stale governed proposal", "The signed proposal context no longer matches current ledger state.");
        }
        let signers;
        let evidenceVerifierSignature;
        try {
          signers = decodeGovernedMembershipSigners(body);
          evidenceVerifierSignature = decodeAuditorEvidenceVerifierSignature(body.evidenceVerifierSignature);
        } catch {
          throw jsonProblem(problemBaseUri, "invalid-governed-signature", 400,
            "invalid governed signature");
        }
        try {
          const receipt = GovernedMembershipActionReceiptSchema.parse(
            await port.execute(authorizationId, body.evidence, signers, evidenceVerifierSignature),
          );
          writeJson(response, 202, receipt);
          return;
        } catch (error) {
          return mapGovernedAuditorProposalError(error, problemBaseUri);
        }
      }

      if (
        method === "POST"
        && segments.length === 6
        && segments[0] === "v1"
        && segments[1] === "governed"
        && segments[2] === "maintainer"
        && segments[4] === "proposal"
        && (segments[5] === "prepare" || segments[5] === "submit")
      ) {
        const port = options.governedMaintainerProposals;
        if (port === undefined) {
          throw jsonProblem(problemBaseUri, "governed-proposal-unavailable", 503,
            "governed proposal unavailable", "A Compact-backed maintainer proposal port is not configured.");
        }
        const maintainerId = parseApplicationIdentifier(segments[3]!, problemBaseUri);
        response.setHeader("cache-control", "no-store");
        if (segments[5] === "prepare") {
          const body = await parseJsonBody(request,
            (value) => GovernedMaintainerProposalPrepareRequestSchema.parse(value), problemBaseUri);
          await requireProposalAdmission("maintainer", maintainerId, body.evidence);
          try {
            writeJson(response, 200, serializeGovernedMaintainerProposal(
              await port.prepare(maintainerId, body.evidence),
            ));
            return;
          } catch (error) {
            return mapGovernedMaintainerProposalError(error, problemBaseUri);
          }
        }
        const body = await parseJsonBody(request,
          (value) => GovernedMaintainerProposalSubmitRequestSchema.parse(value), problemBaseUri);
        await requireProposalAdmission("maintainer", maintainerId, body.evidence);
        let prepared;
        try {
          prepared = serializeGovernedMaintainerProposal(await port.prepare(maintainerId, body.evidence));
        } catch (error) {
          return mapGovernedMaintainerProposalError(error, problemBaseUri);
        }
        if (!sameGovernedMaintainerProposal(prepared, body.prepared)) {
          throw jsonProblem(problemBaseUri, "stale-governed-proposal", 409,
            "stale governed proposal", "The signed proposal context no longer matches current ledger state.");
        }
        let signers;
        let evidenceVerifierSignature;
        try {
          signers = decodeGovernedMembershipSigners(body);
          evidenceVerifierSignature = decodeMaintainerEvidenceVerifierSignature(body.evidenceVerifierSignature);
        } catch {
          throw jsonProblem(problemBaseUri, "invalid-governed-signature", 400,
            "invalid governed signature");
        }
        try {
          const receipt = GovernedMembershipActionReceiptSchema.parse(
            await port.execute(maintainerId, body.evidence, signers, evidenceVerifierSignature),
          );
          writeJson(response, 202, receipt);
          return;
        } catch (error) {
          return mapGovernedMaintainerProposalError(error, problemBaseUri);
        }
      }

      if (
        (method === "GET" || method === "POST")
        && segments.length === 6
        && segments[0] === "v1"
        && segments[1] === "governed"
        && segments[4] === "actions"
      ) {
        const port = requireGovernedMembershipActions(options, problemBaseUri);
        const role = GovernedMembershipRoleSchema.parse(segments[2]);
        const authorizationId = parseApplicationIdentifier(segments[3]!, problemBaseUri);
        const action = GovernedMembershipActionSchema.parse(segments[5]);
        let prepared;
        try {
          prepared = serializeGovernedMembershipAction(await port.prepare(role, authorizationId, action));
        } catch (error) {
          return mapGovernedMembershipError(error, problemBaseUri);
        }
        response.setHeader("cache-control", "no-store");
        if (method === "GET") {
          writeJson(response, 200, prepared);
          return;
        }
        const body = await parseJsonBody(request,
          (value) => GovernedMembershipSignatureRequestSchema.parse(value), problemBaseUri);
        if (!sameGovernedMembershipAction(prepared, body.prepared)) {
          throw jsonProblem(problemBaseUri, "stale-governed-action", 409,
            "stale governed action", "The signed action context no longer matches current ledger state.");
        }
        let signers;
        try {
          signers = decodeGovernedMembershipSigners(body);
        } catch {
          throw jsonProblem(problemBaseUri, "invalid-governed-signature", 400,
            "invalid governed signature");
        }
        let receipt;
        try {
          receipt = GovernedMembershipActionReceiptSchema.parse(
            await port.execute(role, authorizationId, action, signers),
          );
        } catch (error) {
          return mapGovernedMembershipError(error, problemBaseUri);
        }
        writeJson(response, 202, receipt);
        return;
      }

      if (
        method === "GET"
        && segments.length === 3
        && segments[0] === "v1"
        && segments[1] === "registry"
        && segments[2] === "summary"
      ) {
        writeJson(
          response,
          200,
          TrustRegistryApiSummarySchema.parse(
            await loadRegistrySummary(options.source),
          ),
        );
        return;
      }

      if (
        method === "GET"
        && segments.length === 3
        && segments[0] === "v1"
        && segments[1] === "epochs"
        && segments[2] === "current"
      ) {
        writeJson(
          response,
          200,
          TrustRegistryApiEpochResponseSchema.parse(
            await loadCurrentEpoch(options.source),
          ),
        );
        return;
      }

      if (
        method === "GET"
        && segments.length === 3
        && segments[0] === "v1"
        && segments[1] === "epochs"
        && segments[2] === "resolve"
      ) {
        const evaluatedAt = parseTimestampQueryParameter(
          url.searchParams.get("at"),
          "at",
          problemBaseUri,
        );
        const epoch = await loadEpochAtTimestamp(options.source, evaluatedAt);
        if (epoch === null) {
          throw jsonProblem(
            problemBaseUri,
            "epoch-not-found",
            404,
            "epoch not found",
            `No epoch covers ${evaluatedAt}.`,
          );
        }
        writeJson(response, 200, TrustRegistryApiEpochResponseSchema.parse(epoch));
        return;
      }

      if (method === "GET" && segments.length === 3 && segments[0] === "v1" && segments[1] === "epochs") {
        const epoch = await loadEpochById(options.source, segments[2]!);
        if (epoch === null) {
          throw jsonProblem(
            problemBaseUri,
            "epoch-not-found",
            404,
            "epoch not found",
            `No epoch exists for id ${segments[2]}.`,
          );
        }
        writeJson(response, 200, TrustRegistryApiEpochResponseSchema.parse(epoch));
        return;
      }

      if (
        method === "POST"
        && segments.length === 2
        && segments[0] === "v1"
        && segments[1] === "mutations"
      ) {
        const source = requireMutableSource(options.source, problemBaseUri);
        if (options.mutationDidResolver === undefined) {
          throw jsonProblem(problemBaseUri, "did-resolver-required", 503,
            "did resolver required", "Signed mutations need a configured Midnight DID resolver.");
        }
        const body = await parseJsonBody(request, (value) => SignedMutationRequestSchema.parse(value), problemBaseUri);
        let result: TrustRegistryApiMutationResult;
        try {
          result = await applySignedMutationOperation(
            source, body, () => new Date(options.clock?.() ?? Date.now()), options.mutationDidResolver,
          );
        } catch (error) {
          return mapMutationError(error, problemBaseUri);
        }
        writeJson(response, body.operation.operation === "submit" ? 201 : 200,
          TrustRegistryApiApplicationMutationResponseSchema.parse(buildMutationResponse(result)));
        return;
      }

      if (
        method === "POST"
        && segments.length === 2
        && segments[0] === "v1"
        && segments[1] === "applications"
      ) {
        requireUnsafeDemoMutations(options, problemBaseUri);
        const source = requireMutableSource(options.source, problemBaseUri);
        const body = await parseJsonBody(
          request,
          (value) => TrustRegistryApiApplicationSubmitRequestSchema.parse(value),
          problemBaseUri,
        );
        const result = await performMutation(source, {
          operation: "submit",
          target: body.target,
          label: body.label,
        }, problemBaseUri);
        writeJson(
          response,
          201,
          TrustRegistryApiApplicationMutationResponseSchema.parse({
            ...buildMutationResponse(result),
          }),
        );
        return;
      }

      if (
        method === "POST"
        && segments.length === 5
        && segments[0] === "v1"
        && segments[1] === "applications"
      ) {
        requireUnsafeDemoMutations(options, problemBaseUri);
        const source = requireMutableSource(options.source, problemBaseUri);
        const target = parseApplicationTarget(segments[2]!, problemBaseUri);
        const id = parseApplicationIdentifier(segments[3]!, problemBaseUri);
        const action = parseApplicationAction(segments[4]!, problemBaseUri);
        const result = await performMutation(source, {
          operation: action,
          target,
          id,
        }, problemBaseUri);
        writeJson(
          response,
          200,
          TrustRegistryApiApplicationMutationResponseSchema.parse({
            ...buildMutationResponse(result),
          }),
        );
        return;
      }

      if (
        method === "POST"
        && segments.length === 3
        && segments[0] === "v1"
        && segments[1] === "epochs"
        && segments[2] === "publish"
      ) {
        requireUnsafeDemoMutations(options, problemBaseUri);
        const source = requireMutableSource(options.source, problemBaseUri);
        const body = await parseJsonBody(
          request,
          (value) => TrustRegistryApiEpochPublishRequestSchema.parse(value),
          problemBaseUri,
        );
        const result = await performMutation(source, {
          operation: "publish-epoch",
          ...(body.label === undefined ? {} : { label: body.label }),
        }, problemBaseUri);
        writeJson(
          response,
          200,
          TrustRegistryApiApplicationMutationResponseSchema.parse({
            ...buildMutationResponse(result),
          }),
        );
        return;
      }

      if (
        method === "POST"
        && segments.length === 3
        && segments[0] === "v1"
        && segments[1] === "authorizations"
        && segments[2] === "evaluate"
      ) {
        const body = await parseJsonBody(
          request,
          (value) => TrustRegistryApiEvaluateAuthorizationRequestSchema.parse(value),
          problemBaseUri,
        );
        const evaluation = await evaluateAuthorizationEntryAtTimestamp(
          options.source,
          body,
          body.at,
        );
        if (evaluation === null) {
          throw jsonProblem(
            problemBaseUri,
            "authorization-not-found",
            404,
            "authorization not found",
            "No authorization matches the requested scope and timestamp.",
          );
        }
        writeJson(
          response,
          200,
          TrustRegistryApiAuthorizationEvaluationResponseSchema.parse(evaluation),
        );
        return;
      }

      if (
        method === "POST"
        && segments.length === 3
        && segments[0] === "v1"
        && segments[1] === "authorizations"
        && segments[2] === "resolve"
      ) {
        const body = await parseJsonBody(
          request,
          (value) => TrustRegistryApiResolveAuthorizationRequestSchema.parse(value),
          problemBaseUri,
        );
        const entry = await resolveAuthorizationEntry(options.source, body);
        if (entry === null) {
          throw jsonProblem(
            problemBaseUri,
            "authorization-not-found",
            404,
            "authorization not found",
            "No authorization matches the requested scope.",
          );
        }
        writeJson(response, 200, TrustRegistryApiAuthorizationResponseSchema.parse(entry));
        return;
      }

      if (
        method === "GET"
        && segments.length === 3
        && segments[0] === "v1"
        && segments[1] === "authorizations"
      ) {
        const role = TrustRegistryApiAuthorizationRoleSchema.parse(segments[2]);
        const query = TrustRegistryApiAuthorizationListQuerySchema.parse(
          Object.fromEntries(url.searchParams),
        );
        const entries = await listAuthorizationEntries(options.source, role, query);
        writeJson(
          response,
          200,
          TrustRegistryApiAuthorizationListResponseSchema.parse({
            role,
            total: entries.length,
            entries,
          }),
        );
        return;
      }

      if (
        method === "GET"
        && segments.length === 4
        && segments[0] === "v1"
        && segments[1] === "authorizations"
      ) {
        writeJson(
          response,
          200,
          await requireAuthorizationEntry(
            options.source,
            segments[2]!,
            segments[3]!,
            problemBaseUri,
          ),
        );
        return;
      }

      if (
        method === "GET"
        && segments.length === 5
        && segments[0] === "v1"
        && segments[1] === "authorizations"
        && segments[4] === "evidence"
      ) {
        const entry = await requireAuthorizationEntry(
          options.source,
          segments[2]!,
          segments[3]!,
          problemBaseUri,
        );
        writeJson(
          response,
          200,
          TrustRegistryApiEvidenceResponseSchema.parse(entry.evidence),
        );
        return;
      }

      if (
        method === "POST"
        && segments.length === 3
        && segments[0] === "v1"
        && segments[1] === "recognitions"
        && segments[2] === "evaluate"
      ) {
        const body = await parseJsonBody(
          request,
          (value) => TrustRegistryApiEvaluateRecognitionRequestSchema.parse(value),
          problemBaseUri,
        );
        const evaluation = await evaluateRecognitionEntryAtTimestamp(
          options.source,
          body,
          body.at,
        );
        if (evaluation === null) {
          throw jsonProblem(
            problemBaseUri,
            "recognition-not-found",
            404,
            "recognition not found",
            "No recognition matches the requested scope and timestamp.",
          );
        }
        writeJson(
          response,
          200,
          TrustRegistryApiRecognitionEvaluationResponseSchema.parse(evaluation),
        );
        return;
      }

      if (
        method === "POST"
        && segments.length === 3
        && segments[0] === "v1"
        && segments[1] === "recognitions"
        && segments[2] === "resolve"
      ) {
        const body = await parseJsonBody(
          request,
          (value) => TrustRegistryApiResolveRecognitionRequestSchema.parse(value),
          problemBaseUri,
        );
        const entry = await resolveRecognitionEntry(options.source, body);
        if (entry === null) {
          throw jsonProblem(
            problemBaseUri,
            "recognition-not-found",
            404,
            "recognition not found",
            "No recognition matches the requested scope.",
          );
        }
        writeJson(response, 200, TrustRegistryApiRecognitionResponseSchema.parse(entry));
        return;
      }

      if (
        method === "GET"
        && segments.length === 2
        && segments[0] === "v1"
        && segments[1] === "recognitions"
      ) {
        const query = TrustRegistryApiRecognitionListQuerySchema.parse(
          Object.fromEntries(url.searchParams),
        );
        const entries = await listRecognitionEntries(options.source, query);
        writeJson(
          response,
          200,
          TrustRegistryApiRecognitionListResponseSchema.parse({
            total: entries.length,
            entries,
          }),
        );
        return;
      }

      if (
        method === "GET"
        && segments.length === 3
        && segments[0] === "v1"
        && segments[1] === "recognitions"
      ) {
        writeJson(
          response,
          200,
          await requireRecognitionEntry(
            options.source,
            segments[2]!,
            problemBaseUri,
          ),
        );
        return;
      }

      if (
        method === "GET"
        && segments.length === 4
        && segments[0] === "v1"
        && segments[1] === "recognitions"
        && segments[3] === "evidence"
      ) {
        const entry = await requireRecognitionEntry(
          options.source,
          segments[2]!,
          problemBaseUri,
        );
        writeJson(
          response,
          200,
          TrustRegistryApiEvidenceResponseSchema.parse(entry.evidence),
        );
        return;
      }

      if (
        method === "GET"
        && segments.length === 4
        && segments[0] === "v1"
        && segments[1] === "trqp"
        && segments[2] === "metadata"
      ) {
        const result = await trqpAdapter.getRegistryMetadata(segments[3]!);
        if (!result.ok) {
          writeJson(response, result.problem.status, result.problem);
          return;
        }
        writeJson(response, 200, result.value);
        return;
      }

      if (
        method === "POST"
        && segments.length === 4
        && segments[0] === "v1"
        && segments[1] === "trqp"
        && segments[2] === "authorizations"
      ) {
        const body = await parseJsonBody(
          request,
          (value) => TrqpAuthorizationRequestSchema.parse(value),
          problemBaseUri,
        );
        const result = segments[3] === "query"
          ? await trqpAdapter.queryAuthorization(body)
          : segments[3] === "evidence"
            ? await trqpAdapter.getAuthorizationEvidence(body)
            : null;
        if (result === null) {
          throw jsonProblem(
            problemBaseUri,
            "route-not-found",
            404,
            "route not found",
            `Unknown authorization route ${url.pathname}.`,
          );
        }
        if (!result.ok) {
          writeJson(response, result.problem.status, result.problem);
          return;
        }
        writeJson(response, 200, result.value);
        return;
      }

      if (
        method === "POST"
        && segments.length === 4
        && segments[0] === "v1"
        && segments[1] === "trqp"
        && segments[2] === "recognitions"
      ) {
        const body = await parseJsonBody(
          request,
          (value) => TrqpRecognitionRequestSchema.parse(value),
          problemBaseUri,
        );
        const result = segments[3] === "query"
          ? await trqpAdapter.queryRecognition(body)
          : segments[3] === "evidence"
            ? await trqpAdapter.getRecognitionEvidence(body)
            : null;
        if (result === null) {
          throw jsonProblem(
            problemBaseUri,
            "route-not-found",
            404,
            "route not found",
            `Unknown recognition route ${url.pathname}.`,
          );
        }
        if (!result.ok) {
          writeJson(response, result.problem.status, result.problem);
          return;
        }
        writeJson(response, 200, result.value);
        return;
      }

      if (method === "GET" && segments[0] !== "v1" && options.nonApiGetHandler !== undefined) {
        await options.nonApiGetHandler(request, response);
        return;
      }

      throw jsonProblem(
        problemBaseUri,
        "route-not-found",
        404,
        "route not found",
        `No trust-registry API route matches ${method} ${url.pathname}.`,
      );
    } catch (error) {
      const problem = privateApplicantRoute && !(error instanceof HttpProblem)
        ? jsonProblem(problemBaseUri, "private-request-rejected",
          error instanceof SyntaxError || error instanceof ZodError ? 400 : 500,
          "private request rejected").problem
        : asProblem(error, problemBaseUri);
      writeJson(response, problem.status, problem, !privateApplicantRoute);
    }
  });
};
