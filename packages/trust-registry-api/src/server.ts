import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { z, ZodError } from "zod";

import { DecisionEvidenceSchema, SignedPendingApplicationSchema } from "@midnight-ntwrk/trust-registry-domain";
import { encodeCompactActionKind } from "@midnight-ntwrk/trust-registry-contract";
import { EvidenceVerifierDidResolutionUnavailableError } from "@midnight-ntwrk/trust-registry-integration";

import {
  TrustRegistryTrqpAdapter,
  TrqpAuthorizationRequestSchema,
  TrqpRecognitionRequestSchema,
} from "@midnight-ntwrk/trust-registry-trqp-adapter";

import {
  applyMutationOperation,
  applySignedMutationOperation,
  evaluateAuthorizationEntryAtTimestamp,
  evaluateAuthorizationEvidenceAtTimestamp,
  evaluateRecognitionEntryAtTimestamp,
  evaluateRecognitionEvidenceAtTimestamp,
  createTrqpSourceFromStateSource,
  CurrentLedgerSelectionAmbiguousError,
  CurrentLedgerSelectionUnavailableError,
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
  hasValidProposalSignerBundle,
  GovernedMembershipActionReceiptSchema,
  GovernedMembershipActionRejectedError,
  GovernedMembershipActionSchema,
  GovernedMembershipRoleSchema,
  GovernedMembershipSignatureRequestSchema,
  sameGovernedMembershipAction,
  serializeGovernedMembershipAction,
  type GovernedMembershipActionReceipt,
  type GovernedMembershipActionPort,
} from "./governed-membership-actions.js";
import {
  GovernedEpochPrepareRequestSchema,
  GovernedEpochPublicationReceiptSchema,
  GovernedEpochPublicationRejectedError,
  GovernedEpochPublishRequestSchema,
  sameGovernedEpochPublication,
  serializeGovernedEpochPublication,
  type GovernedEpochPublicationPort,
} from "./governed-epoch-publication.js";
import {
  GovernedEvidenceVerifierPrepareRequestSchema,
  GovernedEvidenceVerifierRotationPrepareRequestSchema,
  GovernedEvidenceVerifierRotationSubmitRequestSchema,
  GovernedEvidenceVerifierStatusPrepareRequestSchema,
  GovernedEvidenceVerifierStatusSubmitRequestSchema,
  GovernedEvidenceVerifierSubmitRequestSchema,
  GovernedMaintainerRecoveryPrepareRequestSchema,
  GovernedMaintainerRecoverySubmitRequestSchema,
  GovernedPolicyActionReceiptSchema,
  GovernedPolicyActionRejectedError,
  PreparedGovernedEvidenceVerifierRotationSchema,
  PreparedGovernedEvidenceVerifierStatusSchema,
  GovernedThresholdPrepareRequestSchema,
  GovernedThresholdSubmitRequestSchema,
  sameGovernedPolicyAction,
  serializeGovernedPolicyAction,
  type GovernedPolicyActionPort,
  type GovernedEvidenceVerifierTransitionInput,
} from "./governed-policy-actions.js";
import {
  decodeIssuerEvidenceVerifierSignature,
  GovernedIssuerProposalPrepareRequestSchema,
  GovernedIssuerProposalRejectedError,
  GovernedIssuerProposalSubmitRequestSchema,
  sameGovernedIssuerProposal,
  serializeGovernedIssuerProposal,
  type GovernedIssuerProposalPort,
} from "./governed-issuer-proposals.js";
import {
  decodeRecognitionEvidenceVerifierSignature,
  GovernedRecognitionProposalPrepareRequestSchema,
  GovernedRecognitionProposalRejectedError,
  GovernedRecognitionProposalSubmitRequestSchema,
  sameGovernedRecognitionProposal,
  serializeGovernedRecognitionProposal,
  type GovernedRecognitionProposalPort,
} from "./governed-recognition-proposals.js";
import { withRecognitionProposalAdmission } from "./recognition-proposal-admission.js";
import { RecognitionAdmissionReceiptSchema, type RecognitionAdmissionReceipt } from "./file-recognition-admission.js";
import {
  recognitionAuthorityChallengeBindingHash,
  recognitionAuthorityChallengeIdentityHash,
  RecognitionAuthorityChallengeBindingSchema,
  type RecognitionAuthorityChallengeBinding,
} from "./recognition-authority-challenges.js";
import {
  GovernedProposalObservationSchema,
  GovernedProposalResolveRequestSchema,
  type GovernedProposalObservation,
} from "./governed-proposal-observation.js";
import {
  resolveCompactProposalEvidenceSnapshot,
  type FinalizedProposalLedgerReader,
  type ProposalRole,
} from "./compact-proposal-observation.js";
import {
  assertCurrentProposalQuorum,
  InvalidProposalQuorumError,
  StaleProposalQuorumContextError,
} from "./governed-proposal-quorum-preflight.js";
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
  RecognitionAccreditationAuthorizationDeniedError,
  RecognitionAccreditationHttpError,
  createRecognitionAccreditationHttpService,
  type RecognitionAccreditationHttpPort,
} from "./recognition-accreditation-http.js";
import {
  PendingApplicationRegistrationRejectedError,
  type PendingApplicationRegistrationPort,
} from "./pending-application-registration.js";
import {
  assertProposalAdmission,
  type ProposalAdmissionPort,
} from "./proposal-admission.js";
import {
  InvalidProposalSubmissionJournalError,
  ProposalSubmissionAlreadyPendingError,
  ProposalSubmissionBlockedByReservationError,
  ProposalSubmissionCapacityError,
  ProposalSubmissionConflictError,
  ProposalSubmissionContextRequiredError,
  ProposalSubmissionOutcomeUnknownError,
  type GovernedProposalSubmissionRole,
  type ProposalSubmissionJournal,
  type ProposalReservationContext,
} from "./proposal-submission-journal.js";
import { MutationIntentOperationMismatchError } from "./mutation-intent-preflight.js";
import { MutationActorNonceCapacityExceededError, MutationIntentActorRejectedError, MutationNonceAlreadyUsedError, MutationNonceCapacityExceededError, MutationNonceClockRollbackError } from "./signed-mutation-state.js";
import { LocalLedgerSourceUnavailableError } from "./local-ledger-source.js";
import { computeOperatorWorkspaceCommitment } from "./workspace-commitment.js";
import {
  TrustRegistryApiApplicationActionSchema,
  TrustRegistryApiApplicationMutationResponseSchema,
  TrustRegistryApiApplicationSubmitRequestSchema,
  TrustRegistryApiApplicationTargetSchema,
  TrustRegistryApiAuthorizationEvaluationResponseSchema,
  TrustRegistryApiAuthorizationEvidenceEvaluationResponseSchema,
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
  TrustRegistryApiSignedMutationRequestSchema,
  TrustRegistryApiProblemDetailsSchema,
  TrustRegistryApiRecognitionEvaluationResponseSchema,
  TrustRegistryApiRecognitionEvidenceEvaluationResponseSchema,
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
const RECOVER_MAINTAINER_ACTION_KIND = `0x${Buffer.from(encodeCompactActionKind("tr:maintainer:recover")).toString("hex")}`;
const EVIDENCE_VERIFIER_ACTION_KINDS = {
  rotate: `0x${Buffer.from(encodeCompactActionKind("tr:evidence-verifier:rotate")).toString("hex")}`,
  suspend: `0x${Buffer.from(encodeCompactActionKind("tr:evidence-verifier:suspend")).toString("hex")}`,
  revoke: `0x${Buffer.from(encodeCompactActionKind("tr:evidence-verifier:revoke")).toString("hex")}`,
} as const;
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
  /** Digest of the signed local plan bytes verified when this server started. */
  localPlanSha256?: string;
  corsPolicy?: "public" | "none";
  clock?: () => string;
  problemBaseUri?: string;
  mutationDidResolver?: Parameters<typeof verifyMutationIntentDidSignature>[2];
  allowUnsafeDemoMutations?: boolean;
  governedMembershipActions?: GovernedMembershipActionPort;
  governedEpochPublication?: GovernedEpochPublicationPort;
  governedPolicyActions?: GovernedPolicyActionPort;
  governedIssuerProposals?: GovernedIssuerProposalPort;
  governedRecognitionProposals?: GovernedRecognitionProposalPort;
  governedVerifierProposals?: GovernedVerifierProposalPort;
  governedAuditorProposals?: GovernedAuditorProposalPort;
  governedMaintainerProposals?: GovernedMaintainerProposalPort;
  applicationVp?: ApplicationVpHttpPort;
  recognitionAccreditation?: RecognitionAccreditationHttpPort;
  /** Read from a trusted finalized source; clients must authenticate epoch and DID anchors independently. */
  readDecisionEvidence?: (role: "issuer" | "verifier", authorizationId: string) => Promise<unknown | null>;
  /** Optional read-only proposal audit source; this server does not establish ledger finality. */
  readFinalizedProposalLedger?: FinalizedProposalLedgerReader;
  proposalAdmission?: ProposalAdmissionPort;
  /** Required for a durable VP/accreditation-to-Compact handoff; persist before submission. */
  proposalSubmissionJournal?: ProposalSubmissionJournal;
  pendingApplicationRegistration?: PendingApplicationRegistrationPort;
  authorizePendingApplicationRegistration?: (request: IncomingMessage) => Promise<void>;
  nonApiGetHandler?: (request: IncomingMessage, response: ServerResponse) => Promise<void>;
};

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
  if (corsDisabledResponses.has(response)) return;
  response.setHeader("access-control-allow-origin", "*");
  response.setHeader("access-control-allow-headers", "content-type");
  response.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
};

const corsDisabledResponses = new WeakSet<ServerResponse>();

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
  if (error instanceof LocalLedgerSourceUnavailableError) {
    return TrustRegistryApiProblemDetailsSchema.parse({
      type: `${problemBaseUri}/local-ledger-unavailable`,
      title: "local ledger unavailable",
      status: 503,
    });
  }
  if (error instanceof CurrentLedgerSelectionUnavailableError) {
    return TrustRegistryApiProblemDetailsSchema.parse({
      type: `${problemBaseUri}/local-ledger-unavailable`,
      title: "local ledger unavailable",
      status: 503,
    });
  }
  if (error instanceof CurrentLedgerSelectionAmbiguousError) {
    return TrustRegistryApiProblemDetailsSchema.parse({
      type: `${problemBaseUri}/ambiguous-current-scope`,
      title: "ambiguous current scope",
      status: 409,
    });
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
  if (error instanceof MutationActorNonceCapacityExceededError) {
    throw jsonProblem(problemBaseUri, "mutation-actor-nonce-capacity", 429, "actor mutation nonce capacity exceeded", error.message);
  }
  if (error instanceof MutationNonceCapacityExceededError) {
    throw jsonProblem(problemBaseUri, "mutation-nonce-capacity", 503, "mutation nonce capacity exceeded", error.message);
  }
  if (error instanceof MutationNonceClockRollbackError) {
    throw jsonProblem(problemBaseUri, "mutation-nonce-clock-rollback", 503, "mutation nonce clock moved backwards", error.message);
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

const requireGovernedEpochPublication = (
  options: TrustRegistryApiServerOptions,
  problemBaseUri: string,
): GovernedEpochPublicationPort => {
  if (options.governedEpochPublication === undefined) {
    throw jsonProblem(problemBaseUri, "governed-epoch-unavailable", 503,
      "governed epoch publication unavailable", "A Compact-backed epoch publication port is not configured.");
  }
  return options.governedEpochPublication;
};

const requireGovernedPolicyActions = (
  options: TrustRegistryApiServerOptions,
  problemBaseUri: string,
): GovernedPolicyActionPort => {
  if (options.governedPolicyActions === undefined) {
    throw jsonProblem(problemBaseUri, "governed-policy-unavailable", 503,
      "governed policy actions unavailable", "A Compact-backed policy action port is not configured.");
  }
  return options.governedPolicyActions;
};

const mapGovernedPolicyError = (error: unknown, problemBaseUri: string): never => {
  if (error instanceof EvidenceVerifierDidResolutionUnavailableError) {
    throw jsonProblem(problemBaseUri, "evidence-verifier-did-unavailable", 503,
      "evidence verifier DID resolution unavailable");
  }
  if (error instanceof GovernedPolicyActionRejectedError) {
    throw jsonProblem(problemBaseUri, "governed-policy-rejected", 403,
      "governed policy action rejected");
  }
  throw error;
};

const mapGovernedEpochError = (error: unknown, problemBaseUri: string): never => {
  if (error instanceof GovernedEpochPublicationRejectedError) {
    throw jsonProblem(problemBaseUri, "governed-epoch-rejected", 403,
      "governed epoch publication rejected");
  }
  if (error instanceof WorkspaceMutationLockedError) {
    throw jsonProblem(problemBaseUri, "governance-write-locked", 409,
      "governance write locked");
  }
  throw error;
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

const mapGovernedRecognitionProposalError = (error: unknown, problemBaseUri: string): never => {
  if (error instanceof GovernedRecognitionProposalRejectedError) {
    const unknown = error.reason === "unknown-recognition";
    throw jsonProblem(problemBaseUri, unknown ? "recognition-not-found" : "governed-proposal-rejected",
      unknown ? 404 : 403, unknown ? "recognition not found" : "governed proposal rejected",
      error.reason);
  }
  if (error instanceof WorkspaceMutationLockedError) {
    throw jsonProblem(problemBaseUri, "governance-write-locked", 409, "governance write locked");
  }
  throw jsonProblem(problemBaseUri, "unadmitted-recognition-proposal", 403,
    "unadmitted recognition proposal");
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
  if (options.localPlanSha256 !== undefined
    && (options.source.mode !== "local-ledger"
      || !/^[0-9a-f]{64}$/u.test(options.localPlanSha256))) {
    throw new Error("Startup plan digest requires the local-ledger source and canonical SHA-256");
  }
  if (options.applicationVp !== undefined
    && (options.governedIssuerProposals !== undefined || options.governedVerifierProposals !== undefined
      || options.governedAuditorProposals !== undefined || options.governedMaintainerProposals !== undefined)
    && options.proposalAdmission === undefined) {
    throw new Error("Combined VP intake and governed proposals require an accepted-application admission port");
  }
  if (options.recognitionAccreditation !== undefined && options.governedRecognitionProposals !== undefined
    && (options.recognitionAccreditation.admissionStore === undefined
      || options.recognitionAccreditation.admissionStore !== options.governedRecognitionProposals.admissionStore)) {
    throw new Error("Recognition accreditation and governed proposals require the same admission store");
  }
  const hasMembershipProposalPort = options.governedIssuerProposals !== undefined
    || options.governedVerifierProposals !== undefined
    || options.governedAuditorProposals !== undefined
    || options.governedMaintainerProposals !== undefined;
  if (options.source.mode === "local-ledger") {
    if (options.allowUnsafeDemoMutations === true) {
      throw new Error("Local-ledger mode forbids demo mutations");
    }
    if (options.governedMembershipActions !== undefined
      || options.governedEpochPublication !== undefined
      || options.governedPolicyActions !== undefined) {
      throw new Error("Local-ledger governed actions require a durable submission adapter");
    }
    if ((hasMembershipProposalPort || options.governedRecognitionProposals !== undefined)
      && (options.proposalSubmissionJournal === undefined
        || options.source.readFinalizedProposalLedger === undefined
        || (hasMembershipProposalPort && options.proposalAdmission === undefined)
        || (options.governedRecognitionProposals !== undefined
          && options.recognitionAccreditation === undefined))) {
      throw new Error("Local-ledger proposals require durable submission and finalized observation with admission");
    }
    if (options.proposalSubmissionJournal !== undefined
      && (options.source.localDeploymentBinding === undefined
        || options.proposalSubmissionJournal.assertDeploymentBinding === undefined)) {
      throw new Error("Local-ledger proposal journals require a signed deployment binding check");
    }
  }
  if (options.proposalSubmissionJournal !== undefined
    && ((hasMembershipProposalPort && options.proposalAdmission === undefined)
      || (!hasMembershipProposalPort && (options.governedRecognitionProposals === undefined
        || options.recognitionAccreditation === undefined)))) {
    throw new Error("A proposal submission journal requires matching application or recognition admission");
  }
  if (options.proposalSubmissionJournal !== undefined
    && options.governedRecognitionProposals !== undefined
    && typeof options.governedRecognitionProposals.preflightSubmission !== "function") {
    throw new Error("Journaled recognition proposals require side-effect-free submission preflight");
  }
  if (options.proposalSubmissionJournal !== undefined
    && [options.governedIssuerProposals, options.governedVerifierProposals,
      options.governedAuditorProposals, options.governedMaintainerProposals]
      .some((port) => port !== undefined && typeof port.preflightSubmission !== "function")) {
    throw new Error("Journaled membership proposals require side-effect-free submission preflight");
  }
  const problemBaseUri = options.problemBaseUri ?? DEFAULT_PROBLEM_BASE;
  const requireCompleteHistoricalProjection = (): void => {
    if (options.source.mode === "local-ledger") {
      throw jsonProblem(problemBaseUri, "historical-decisions-out-of-scope", 501,
        "historical decisions are outside the local 0.1.0 profile",
        "Only current finalized authorization and recognition lookups are supported.");
    }
  };
  const trqpAdapter = new TrustRegistryTrqpAdapter(
    createTrqpSourceFromStateSource(options.source),
    {
      ...(options.clock === undefined ? {} : { clock: options.clock }),
      problemBaseUri: `${problemBaseUri}/trqp`,
    },
  );
  const applicationVp = options.applicationVp === undefined ? undefined
    : createApplicationVpHttpService(options.applicationVp, () => Date.parse(options.clock?.() ?? new Date().toISOString()));
  const recognitionAccreditation = options.recognitionAccreditation === undefined ? undefined
    : createRecognitionAccreditationHttpService(
      options.recognitionAccreditation,
      () => Date.parse(options.clock?.() ?? new Date().toISOString()),
    );

  const authorizeRecognitionRequest = async (recognitionId: string, request: IncomingMessage): Promise<void> => {
    if (options.recognitionAccreditation === undefined) {
      throw jsonProblem(problemBaseUri, "recognition-accreditation-unavailable", 503,
        "recognition accreditation unavailable");
    }
    try {
      await options.recognitionAccreditation.authorizeRequest(recognitionId, request);
    } catch (error) {
      if (error instanceof RecognitionAccreditationAuthorizationDeniedError) {
        throw jsonProblem(problemBaseUri, "recognition-accreditation-forbidden", 403,
          "recognition accreditation forbidden");
      }
      throw jsonProblem(problemBaseUri, "recognition-accreditation-unavailable", 503,
        "recognition accreditation unavailable");
    }
  };

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

  const mapSubmissionJournalError = (error: unknown): never => {
    if (error instanceof InvalidProposalSubmissionJournalError) {
      throw jsonProblem(problemBaseUri, "proposal-submission-journal-unavailable", 503,
        "proposal submission journal unavailable");
    }
    if (error instanceof ProposalSubmissionAlreadyPendingError) {
      throw jsonProblem(problemBaseUri, "proposal-submission-uncertain", 409,
        "proposal submission requires reconciliation",
        "An earlier submission may have reached Compact. Resolve against a finalized ledger view; do not retry automatically.");
    }
    if (error instanceof ProposalSubmissionBlockedByReservationError) {
      throw jsonProblem(problemBaseUri, "proposal-submission-blocked", 409,
        "proposal submissions paused for reconciliation",
        "A different proposal has an unresolved reservation. Contact the operator; do not retry automatically.");
    }
    if (error instanceof ProposalSubmissionOutcomeUnknownError) {
      throw jsonProblem(problemBaseUri, "proposal-submission-uncertain", 503,
        "proposal submission outcome unknown",
        "The proposal may have reached Compact. Resolve against a finalized ledger view; do not retry automatically.");
    }
    if (error instanceof ProposalSubmissionConflictError) {
      throw jsonProblem(problemBaseUri, "proposal-submission-conflict", 409,
        "proposal submission conflicts with recorded evidence or event");
    }
    if (error instanceof ProposalSubmissionContextRequiredError) {
      throw jsonProblem(problemBaseUri, "proposal-submission-context-unavailable", 503,
        "proposal submission action context unavailable",
        "No proposal was reserved or submitted; contact the operator.");
    }
    if (error instanceof ProposalSubmissionCapacityError) {
      throw jsonProblem(problemBaseUri, "proposal-submission-capacity", 503,
        "proposal submission journal capacity exhausted",
        "Operator rotation is required; no new proposal was submitted.");
    }
    throw error;
  };

  const executeProposal = async (
    role: GovernedProposalSubmissionRole,
    authorizationId: string,
    evidenceCommitment: string,
    prepared: ProposalReservationContext,
    execute: () => Promise<GovernedMembershipActionReceipt>,
  ): Promise<GovernedMembershipActionReceipt> => {
    if (options.proposalSubmissionJournal === undefined) return execute();
    try {
      await assertJournalMatchesLocalDeployment();
      return await options.proposalSubmissionJournal.executeOnce(
        role, authorizationId, evidenceCommitment, execute,
        { actionSequence: prepared.actionSequence, actionKind: prepared.actionKind,
          actionPayloadHash: prepared.actionPayloadHash },
      );
    } catch (error) {
      return mapSubmissionJournalError(error);
    }
  };

  const assertJournalMatchesLocalDeployment = async (): Promise<void> => {
    if (options.source.mode !== "local-ledger" || options.proposalSubmissionJournal === undefined) return;
    const binding = options.source.localDeploymentBinding;
    const assertBinding = options.proposalSubmissionJournal.assertDeploymentBinding;
    if (binding === undefined || assertBinding === undefined) {
      throw new ProposalSubmissionConflictError();
    }
    try {
      const snapshot = await options.source.loadSnapshot();
      await assertBinding.call(options.proposalSubmissionJournal,
        snapshot.registry.registryId, binding.contractAddress, binding.expectedGenesisHash);
    } catch (error) {
      if (error instanceof ProposalSubmissionConflictError || error instanceof LocalLedgerSourceUnavailableError) {
        throw error;
      }
      throw new InvalidProposalSubmissionJournalError();
    }
  };

  const readLocalFinalizedProposal = async (role: ProposalRole, authorizationId: string) => {
    const reader = options.source.readFinalizedProposalLedger;
    if (options.source.mode !== "local-ledger" || reader === undefined) {
      throw new Error("Deployment-bound finalized proposal reader is unavailable");
    }
    const snapshot = await options.source.loadSnapshot();
    return resolveCompactProposalEvidenceSnapshot(reader, snapshot.registry.registryId, role, authorizationId);
  };

  const requireValidProposalSigners = (
    context: Parameters<typeof hasValidProposalSignerBundle>[0],
    signers: Parameters<typeof hasValidProposalSignerBundle>[1],
  ): void => {
    if (!hasValidProposalSignerBundle(context, signers)) {
      throw jsonProblem(problemBaseUri, "invalid-governed-signature", 403,
        "invalid governed signature", "A maintainer vote does not sign the prepared governed action.");
    }
  };

  const requireCurrentProposalQuorum = async (
    context: Parameters<typeof assertCurrentProposalQuorum>[1],
    signers: Parameters<typeof assertCurrentProposalQuorum>[2],
  ): Promise<void> => {
    if (options.source.mode !== "local-ledger" || options.proposalSubmissionJournal === undefined) return;
    const reader = options.source.readFinalizedProposalLedger;
    if (reader === undefined) {
      throw jsonProblem(problemBaseUri, "governed-proposal-preflight-unavailable", 503,
        "governed proposal preflight unavailable");
    }
    try {
      await assertCurrentProposalQuorum(reader, context, signers);
    } catch (error) {
      if (error instanceof StaleProposalQuorumContextError) {
        throw jsonProblem(problemBaseUri, "stale-governed-proposal", 409,
          "stale governed proposal", "The signed proposal context no longer matches current ledger state.");
      }
      if (error instanceof InvalidProposalQuorumError) {
        throw jsonProblem(problemBaseUri, "invalid-governed-signature", 403,
          "invalid governed signature", "The maintainer signer set is not active for this action threshold.");
      }
      throw jsonProblem(problemBaseUri, "governed-proposal-preflight-unavailable", 503,
        "governed proposal preflight unavailable");
    }
  };

  const resolveProposal = async (
    request: IncomingMessage,
    response: ServerResponse,
    role: "issuer" | "verifier" | "auditor" | "maintainer",
    authorizationId: string,
    resolver: ((id: string) => Promise<GovernedProposalObservation | null>) | undefined,
    mapError: (error: unknown, problemBaseUri: string) => never,
  ): Promise<void> => {
    const body = await parseJsonBody(request,
      (value) => GovernedProposalResolveRequestSchema.parse(value), problemBaseUri);
    await requireProposalAdmission(role, authorizationId, body.evidence);
    if (resolver === undefined && options.source.mode !== "local-ledger") {
      throw jsonProblem(problemBaseUri, "governed-proposal-resolution-unavailable", 503,
        "governed proposal resolution unavailable");
    }
    if (options.source.mode === "local-ledger" && options.proposalSubmissionJournal !== undefined) {
      try {
        await assertJournalMatchesLocalDeployment();
      } catch (error) {
        return mapSubmissionJournalError(error);
      }
    }
    let observed;
    try {
      observed = options.source.mode === "local-ledger"
        ? await readLocalFinalizedProposal(role, authorizationId)
        : await resolver!(authorizationId);
    } catch (error) {
      if (options.source.mode === "local-ledger") {
        throw jsonProblem(problemBaseUri, "governed-proposal-resolution-unavailable", 503,
          "governed proposal resolution unavailable");
      }
      return mapError(error, problemBaseUri);
    }
    if (observed === null) {
      writeJson(response, 200, { state: "not-observed" });
      return;
    }
    const record = GovernedProposalObservationSchema.parse({
      eventHash: observed.eventHash, evidenceCommitment: observed.evidenceCommitment,
    });
    if (record.evidenceCommitment !== body.evidence.commitment) {
      throw jsonProblem(problemBaseUri, "proposal-evidence-mismatch", 409,
        "proposal evidence mismatch", "The ledger proposal belongs to another evidence commitment.");
    }
    if (options.proposalSubmissionJournal !== undefined) {
      try {
        await options.proposalSubmissionJournal.reconcile(role, authorizationId, async () => record);
      } catch (error) {
        return mapSubmissionJournalError(error);
      }
    }
    writeJson(response, 200, { state: "observed", eventHash: record.eventHash });
  };

  return createServer(async (request, response) => {
    if (options.corsPolicy === "none") corsDisabledResponses.add(response);
    if (options.source.mode === "local-ledger") response.setHeader("cache-control", "no-store");
    let privateApplicantRoute = false;
    try {
      const method = request.method ?? "GET";
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      let segments: string[];
      try {
        segments = routeSegments(url.pathname);
      } catch {
        throw jsonProblem(problemBaseUri, "invalid-request-path", 400, "invalid request path");
      }
      privateApplicantRoute = segments[0] === "v1" && (
        (segments.length === 4 && segments[1] === "application-evidence"
          && (segments[3] === "binding" || segments[3] === "challenges"
            || segments[3] === "submissions" || segments[3] === "receipt"))
        || (segments.length === 4 && segments[1] === "recognition-evidence"
          && (segments[3] === "challenges" || segments[3] === "submissions" || segments[3] === "accepted"))
        || (segments.length === 6 && segments[1] === "governed" && segments[2] === "recognition"
          && segments[4] === "proposal" && (segments[5] === "resolve" || segments[5] === "evidence"))
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
            ...(options.localPlanSha256 === undefined ? {} : { localPlanSha256: options.localPlanSha256 }),
          }),
        );
        return;
      }

      if (method === "GET" && segments.length === 6 && segments[0] === "v1"
        && segments[1] === "governed" && segments[4] === "proposal" && segments[5] === "evidence") {
        response.setHeader("cache-control", "no-store");
        const role = segments[2]!;
        if (!["issuer", "verifier", "auditor", "maintainer", "recognition"].includes(role)) {
          throw jsonProblem(problemBaseUri, "invalid-proposal-role", 400, "invalid proposal role");
        }
        if (segments[3]!.length === 0 || segments[3]!.length > 256) {
          throw jsonProblem(problemBaseUri, "invalid-proposal-id", 400, "invalid proposal ID");
        }
        if (role === "recognition") {
          if (options.recognitionAccreditation === undefined) {
            throw jsonProblem(problemBaseUri, "recognition-accreditation-unavailable", 503,
              "recognition accreditation unavailable");
          }
          await authorizeRecognitionRequest(segments[3]!, request);
        }
        const proposalReader = options.source.mode === "local-ledger"
          ? options.source.readFinalizedProposalLedger : options.readFinalizedProposalLedger;
        if (proposalReader === undefined) {
          throw jsonProblem(problemBaseUri, "proposal-evidence-unavailable", 503,
            "proposal evidence unavailable");
        }
        let snapshot;
        try {
          const registry = await loadRegistryRecord(options.source);
          snapshot = await resolveCompactProposalEvidenceSnapshot(
            proposalReader, registry.registryId, role as ProposalRole, segments[3]!,
          );
        } catch {
          throw jsonProblem(problemBaseUri, "proposal-evidence-unavailable", 503,
            "proposal evidence unavailable");
        }
        if (snapshot === null) {
          throw jsonProblem(problemBaseUri, "proposal-evidence-not-found", 404, "proposal evidence not found");
        }
        writeJson(response, 200, snapshot, false);
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

      if (method === "GET" && segments.length === 4 && segments[0] === "v1"
        && segments[1] === "decision-evidence" && (segments[2] === "issuer" || segments[2] === "verifier")) {
        response.setHeader("cache-control", "no-store");
        const authorizationId = parseApplicationIdentifier(segments[3]!, problemBaseUri);
        if (authorizationId.length > 256) {
          throw jsonProblem(problemBaseUri, "invalid-path-parameter", 400, "invalid path parameter");
        }
        if (options.readDecisionEvidence === undefined) {
          throw jsonProblem(problemBaseUri, "decision-evidence-unavailable", 503, "decision evidence unavailable");
        }
        let evidence;
        try {
          const result = await options.readDecisionEvidence(segments[2], authorizationId);
          if (result === null) {
            throw jsonProblem(problemBaseUri, "decision-evidence-not-found", 404, "decision evidence not found");
          }
          evidence = DecisionEvidenceSchema.parse(result);
          const registry = await loadRegistryRecord(options.source);
          if (evidence.role !== segments[2] || evidence.grant.authorizationId !== authorizationId
            || evidence.registry.registryId !== registry.registryId) {
            throw new Error("Decision evidence source returned a different grant or registry");
          }
        } catch (error) {
          if (error instanceof HttpProblem) throw error;
          throw jsonProblem(problemBaseUri, "decision-evidence-unavailable", 503, "decision evidence unavailable");
        }
        writeJson(response, 200, { verification: "client-required", evidence });
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
          evaluatedAt: options.clock?.() ?? new Date().toISOString(),
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

      if (segments.length === 4 && segments[0] === "v1" && segments[1] === "application-evidence"
        && ((method === "GET" && (segments[3] === "binding" || segments[3] === "receipt"))
          || (method === "POST" && (segments[3] === "challenges" || segments[3] === "submissions")))) {
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
          if (segments[3] === "receipt") {
            if (options.applicationVp.resolveAcceptedEvidence === undefined) {
              throw jsonProblem(problemBaseUri, "application-vp-receipt-unavailable", 503,
                "application VP receipt unavailable");
            }
            writeJson(response, 200, await applicationVp.accepted(segments[2]!), false);
            return;
          }
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

      if (method === "GET" && segments.length === 4 && segments[0] === "v1"
        && segments[1] === "recognition-evidence" && segments[3] === "accepted") {
        response.setHeader("cache-control", "no-store");
        if (recognitionAccreditation === undefined || options.recognitionAccreditation === undefined) {
          throw jsonProblem(problemBaseUri, "recognition-accreditation-unavailable", 503,
            "recognition accreditation unavailable");
        }
        await authorizeRecognitionRequest(segments[2]!, request);
        try {
          writeJson(response, 200, await recognitionAccreditation.accepted(segments[2]!), false);
          return;
        } catch (error) {
          const reason = error instanceof RecognitionAccreditationHttpError ? error.reason : "rejected";
          const status = reason === "invalid-request" ? 400 : reason === "not-found" ? 404 : 403;
          throw jsonProblem(problemBaseUri, `recognition-accreditation-${reason}`, status,
            `recognition accreditation ${reason}`);
        }
      }

      if (method === "POST" && segments.length === 4 && segments[0] === "v1"
        && segments[1] === "recognition-evidence"
        && (segments[3] === "challenges" || segments[3] === "submissions")) {
        response.setHeader("cache-control", "no-store");
        if (recognitionAccreditation === undefined || options.recognitionAccreditation === undefined) {
          throw jsonProblem(problemBaseUri, "recognition-accreditation-unavailable", 503,
            "recognition accreditation unavailable");
        }
        await authorizeRecognitionRequest(segments[2]!, request);
        try {
          const raw = await readRequestBody(request, problemBaseUri);
          let body: unknown;
          try {
            body = JSON.parse(raw);
          } catch {
            throw new RecognitionAccreditationHttpError("invalid-request");
          }
          const result = segments[3] === "challenges"
            ? await recognitionAccreditation.issue(segments[2]!, body)
            : await recognitionAccreditation.submit(segments[2]!, body);
          writeJson(response, segments[3] === "challenges" ? 201 : 200, result, false);
          return;
        } catch (error) {
          if (error instanceof HttpProblem) throw error;
          const reason = error instanceof RecognitionAccreditationHttpError ? error.reason : "rejected";
          const status = reason === "invalid-request" ? 400 : reason === "not-found" ? 404 : 403;
          throw jsonProblem(problemBaseUri, `recognition-accreditation-${reason}`, status,
            `recognition accreditation ${reason}`);
        }
      }

      if (method === "POST" && segments.length === 6 && segments[0] === "v1"
        && segments[1] === "governed" && segments[2] === "recognition"
        && segments[4] === "proposal" && segments[5] === "resolve") {
        response.setHeader("cache-control", "no-store");
        const recognitionId = parseApplicationIdentifier(segments[3]!, problemBaseUri);
        const port = options.governedRecognitionProposals;
        if (port === undefined || (port.resolve === undefined && options.source.mode !== "local-ledger")
          || options.recognitionAccreditation === undefined) {
          throw jsonProblem(problemBaseUri, "governed-proposal-resolution-unavailable", 503,
            "governed proposal resolution unavailable");
        }
        await authorizeRecognitionRequest(recognitionId, request);
        const body = await parseJsonBody(request,
          (value) => GovernedRecognitionProposalPrepareRequestSchema.parse(value), problemBaseUri);
        let binding: RecognitionAuthorityChallengeBinding;
        let receipt: RecognitionAdmissionReceipt | null;
        try {
          binding = RecognitionAuthorityChallengeBindingSchema.parse(await port.readBinding(recognitionId));
          receipt = await port.admissionStore.readAccepted(recognitionId);
        } catch {
          throw jsonProblem(problemBaseUri, "governed-proposal-resolution-unavailable", 503,
            "governed proposal resolution unavailable");
        }
        const accepted = receipt === null ? null : RecognitionAdmissionReceiptSchema.safeParse(receipt);
        if (binding.recognitionId !== recognitionId || accepted === null || !accepted.success
          || accepted.data.receiptId !== body.receiptId
          || accepted.data.recognitionId !== recognitionId
          || accepted.data.applicationHash !== recognitionAuthorityChallengeIdentityHash(binding)
          || accepted.data.bindingHash !== recognitionAuthorityChallengeBindingHash(binding)
          || accepted.data.evidenceCommitment !== body.evidenceCommitment) {
          throw jsonProblem(problemBaseUri, "unadmitted-proposal", 403,
            "unadmitted proposal", "The proposal has no matching accepted accreditation receipt.");
        }
        if (options.source.mode === "local-ledger" && options.proposalSubmissionJournal !== undefined) {
          try {
            await assertJournalMatchesLocalDeployment();
          } catch (error) {
            return mapSubmissionJournalError(error);
          }
        }
        let observed;
        try {
          observed = options.source.mode === "local-ledger"
            ? await readLocalFinalizedProposal("recognition", recognitionId)
            : await port.resolve!(recognitionId);
        } catch {
          throw jsonProblem(problemBaseUri, "governed-proposal-resolution-unavailable", 503,
            "governed proposal resolution unavailable");
        }
        if (observed === null) {
          writeJson(response, 200, { state: "not-observed" }, false);
          return;
        }
        const record = GovernedProposalObservationSchema.parse({
          eventHash: observed.eventHash, evidenceCommitment: observed.evidenceCommitment,
        });
        if (record.evidenceCommitment !== body.evidenceCommitment) {
          throw jsonProblem(problemBaseUri, "proposal-evidence-mismatch", 409,
            "proposal evidence mismatch", "The ledger proposal belongs to another evidence commitment.");
        }
        if (options.proposalSubmissionJournal !== undefined) {
          try {
            await options.proposalSubmissionJournal.reconcile("recognition", recognitionId, async () => record);
          } catch (error) {
            return mapSubmissionJournalError(error);
          }
        }
        writeJson(response, 200, { state: "observed", eventHash: record.eventHash }, false);
        return;
      }

      if (
        method === "POST"
        && segments.length === 6
        && segments[0] === "v1"
        && segments[1] === "governed"
        && segments[2] === "recognition"
        && segments[4] === "proposal"
        && (segments[5] === "prepare" || segments[5] === "submit")
      ) {
        const port = options.governedRecognitionProposals;
        if (port === undefined) {
          throw jsonProblem(problemBaseUri, "governed-proposal-unavailable", 503,
            "governed proposal unavailable", "A Compact-backed recognition proposal port is not configured.");
        }
        const recognitionId = parseApplicationIdentifier(segments[3]!, problemBaseUri);
        response.setHeader("cache-control", "no-store");
        const body = await parseJsonBody(request,
          (value) => (segments[5] === "prepare"
            ? GovernedRecognitionProposalPrepareRequestSchema
            : GovernedRecognitionProposalSubmitRequestSchema).parse(value), problemBaseUri);
        try {
          const result = await withRecognitionProposalAdmission({
            recognitionId,
            readBinding: () => port.readBinding(recognitionId),
            receiptId: body.receiptId,
            evidenceCommitment: body.evidenceCommitment,
            governanceWorkspacePath: port.governanceWorkspacePath,
            admissionStore: port.admissionStore,
            readCurrentGovernance: () => port.readCurrentGovernance(),
            execute: async (_receipt, binding) => {
              const current = await port.prepare(binding, body.evidenceCommitment);
              const prepared = serializeGovernedRecognitionProposal(current);
              if (prepared.evidenceHash !== body.evidenceCommitment) {
                throw new GovernedRecognitionProposalRejectedError("invalid-evidence");
              }
              if (segments[5] === "prepare") return prepared;
              const submitted = GovernedRecognitionProposalSubmitRequestSchema.parse(body);
              if (!sameGovernedRecognitionProposal(prepared, submitted.prepared)) {
                throw jsonProblem(problemBaseUri, "stale-governed-proposal", 409,
                  "stale governed proposal", "The signed proposal context no longer matches current ledger state.");
              }
              let signers;
              let evidenceVerifierSignature;
              try {
                signers = decodeGovernedMembershipSigners(submitted);
                evidenceVerifierSignature = decodeRecognitionEvidenceVerifierSignature(submitted.evidenceVerifierSignature);
              } catch {
                throw jsonProblem(problemBaseUri, "invalid-governed-signature", 400,
                  "invalid governed signature");
              }
              requireValidProposalSigners(current, signers);
              await requireCurrentProposalQuorum(current, signers);
              await port.preflightSubmission?.(
                binding, body.evidenceCommitment, signers, evidenceVerifierSignature, current,
              );
              return executeProposal("recognition", recognitionId, body.evidenceCommitment, prepared, async () =>
                GovernedMembershipActionReceiptSchema.parse(await port.execute(
                  binding, body.evidenceCommitment, signers, evidenceVerifierSignature, current,
                )));
            },
            clock: () => Date.parse(options.clock?.() ?? new Date().toISOString()),
          });
          writeJson(response, segments[5] === "prepare" ? 200 : 202, result);
          return;
        } catch (error) {
          if (error instanceof HttpProblem) throw error;
          return mapGovernedRecognitionProposalError(error, problemBaseUri);
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
          await resolveProposal(request, response, "issuer", authorizationId,
            port.resolve?.bind(port), mapGovernedIssuerProposalError);
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
        let signerContext;
        let prepared;
        try {
          signerContext = await port.prepare(authorizationId, body.evidence);
          prepared = serializeGovernedIssuerProposal(signerContext);
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
        requireValidProposalSigners(signerContext, signers);
        try {
          await requireCurrentProposalQuorum(signerContext, signers);
          await port.preflightSubmission?.(authorizationId, body.evidence, signers,
            evidenceVerifierSignature, signerContext);
          const receipt = GovernedMembershipActionReceiptSchema.parse(
            await executeProposal("issuer", authorizationId, body.evidence.commitment, prepared,
              () => port.execute(authorizationId, body.evidence, signers, evidenceVerifierSignature)),
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
        && (segments[5] === "prepare" || segments[5] === "submit" || segments[5] === "resolve")
      ) {
        const port = options.governedVerifierProposals;
        if (port === undefined) {
          throw jsonProblem(problemBaseUri, "governed-proposal-unavailable", 503,
            "governed proposal unavailable", "A Compact-backed verifier proposal port is not configured.");
        }
        const authorizationId = parseApplicationIdentifier(segments[3]!, problemBaseUri);
        response.setHeader("cache-control", "no-store");
        if (segments[5] === "resolve") {
          await resolveProposal(request, response, "verifier", authorizationId,
            port.resolve?.bind(port), mapGovernedVerifierProposalError);
          return;
        }
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
        let signerContext;
        let prepared;
        try {
          signerContext = await port.prepare(authorizationId, body.evidence);
          prepared = serializeGovernedVerifierProposal(signerContext);
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
        requireValidProposalSigners(signerContext, signers);
        try {
          await requireCurrentProposalQuorum(signerContext, signers);
          await port.preflightSubmission?.(authorizationId, body.evidence, signers,
            evidenceVerifierSignature, signerContext);
          const receipt = GovernedMembershipActionReceiptSchema.parse(
            await executeProposal("verifier", authorizationId, body.evidence.commitment, prepared,
              () => port.execute(authorizationId, body.evidence, signers, evidenceVerifierSignature)),
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
        && (segments[5] === "prepare" || segments[5] === "submit" || segments[5] === "resolve")
      ) {
        const port = options.governedAuditorProposals;
        if (port === undefined) {
          throw jsonProblem(problemBaseUri, "governed-proposal-unavailable", 503,
            "governed proposal unavailable", "A Compact-backed auditor proposal port is not configured.");
        }
        const authorizationId = parseApplicationIdentifier(segments[3]!, problemBaseUri);
        response.setHeader("cache-control", "no-store");
        if (segments[5] === "resolve") {
          await resolveProposal(request, response, "auditor", authorizationId,
            port.resolve?.bind(port), mapGovernedAuditorProposalError);
          return;
        }
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
        let signerContext;
        let prepared;
        try {
          signerContext = await port.prepare(authorizationId, body.evidence);
          prepared = serializeGovernedAuditorProposal(signerContext);
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
        requireValidProposalSigners(signerContext, signers);
        try {
          await requireCurrentProposalQuorum(signerContext, signers);
          await port.preflightSubmission?.(authorizationId, body.evidence, signers,
            evidenceVerifierSignature, signerContext);
          const receipt = GovernedMembershipActionReceiptSchema.parse(
            await executeProposal("auditor", authorizationId, body.evidence.commitment, prepared,
              () => port.execute(authorizationId, body.evidence, signers, evidenceVerifierSignature)),
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
        && (segments[5] === "prepare" || segments[5] === "submit" || segments[5] === "resolve")
      ) {
        const port = options.governedMaintainerProposals;
        if (port === undefined) {
          throw jsonProblem(problemBaseUri, "governed-proposal-unavailable", 503,
            "governed proposal unavailable", "A Compact-backed maintainer proposal port is not configured.");
        }
        const maintainerId = parseApplicationIdentifier(segments[3]!, problemBaseUri);
        response.setHeader("cache-control", "no-store");
        if (segments[5] === "resolve") {
          await resolveProposal(request, response, "maintainer", maintainerId,
            port.resolve?.bind(port), mapGovernedMaintainerProposalError);
          return;
        }
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
        let signerContext;
        let prepared;
        try {
          signerContext = await port.prepare(maintainerId, body.evidence);
          prepared = serializeGovernedMaintainerProposal(signerContext);
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
        requireValidProposalSigners(signerContext, signers);
        try {
          await requireCurrentProposalQuorum(signerContext, signers);
          await port.preflightSubmission?.(maintainerId, body.evidence, signers,
            evidenceVerifierSignature, signerContext);
          const receipt = GovernedMembershipActionReceiptSchema.parse(
            await executeProposal("maintainer", maintainerId, body.evidence.commitment, prepared,
              () => port.execute(maintainerId, body.evidence, signers, evidenceVerifierSignature)),
          );
          writeJson(response, 202, receipt);
          return;
        } catch (error) {
          return mapGovernedMaintainerProposalError(error, problemBaseUri);
        }
      }

      if (
        method === "POST"
        && segments.length === 6
        && segments[0] === "v1"
        && segments[1] === "governed"
        && segments[2] === "policy"
        && segments[3] === "evidence-verifier"
        && (segments[4] === "rotate" || segments[4] === "suspend" || segments[4] === "revoke")
        && (segments[5] === "prepare" || segments[5] === "submit")
      ) {
        const port = requireGovernedPolicyActions(options, problemBaseUri);
        if (port.prepareEvidenceVerifierTransition === undefined
          || port.executeEvidenceVerifierTransition === undefined) {
          throw jsonProblem(problemBaseUri, "governed-key-lifecycle-unavailable", 503,
            "governed key lifecycle unavailable", "An authorized evidence-verifier lifecycle port is not configured.");
        }
        const action = segments[4] as "rotate" | "suspend" | "revoke";
        const rotating = action === "rotate";
        const preparing = segments[5] === "prepare";
        const body = await parseJsonBody(request, (value) => rotating
          ? (preparing ? GovernedEvidenceVerifierRotationPrepareRequestSchema
            : GovernedEvidenceVerifierRotationSubmitRequestSchema).parse(value)
          : (preparing ? GovernedEvidenceVerifierStatusPrepareRequestSchema
            : GovernedEvidenceVerifierStatusSubmitRequestSchema).parse(value), problemBaseUri);
        const statusInput = { authorizationId: body.authorizationId, reasonHash: body.reasonHash };
        const input: GovernedEvidenceVerifierTransitionInput = rotating
          ? { action, ...GovernedEvidenceVerifierRotationPrepareRequestSchema.parse({
            ...statusInput,
            newAuthorizationId: "newAuthorizationId" in body ? body.newAuthorizationId : undefined,
            newKeyIdCommitment: "newKeyIdCommitment" in body ? body.newKeyIdCommitment : undefined,
            newPublicKey: "newPublicKey" in body ? body.newPublicKey : undefined,
          }) }
          : { action, ...statusInput };
        let signerContext;
        let current;
        try {
          signerContext = await port.prepareEvidenceVerifierTransition(input);
          const serialized = serializeGovernedPolicyAction(signerContext);
          current = rotating
            ? PreparedGovernedEvidenceVerifierRotationSchema.parse(serialized)
            : PreparedGovernedEvidenceVerifierStatusSchema.parse(serialized);
        } catch (error) {
          if (!preparing && error instanceof GovernedPolicyActionRejectedError) {
            throw jsonProblem(problemBaseUri, "stale-governed-policy", 409,
              "stale governed policy action", "The signed context no longer matches current ledger state.");
          }
          return mapGovernedPolicyError(error, problemBaseUri);
        }
        if (current.authorizationId !== input.authorizationId
          || current.reasonHash !== input.reasonHash
          || current.actionKind !== EVIDENCE_VERIFIER_ACTION_KINDS[action]
          || current.previousLifecycleEventHash === undefined
          || (input.action === "rotate" && (current.newAuthorizationId !== input.newAuthorizationId
            || current.newKeyIdCommitment !== input.newKeyIdCommitment
            || current.newPublicKey?.x !== input.newPublicKey.x
            || current.newPublicKey?.y !== input.newPublicKey.y))
          || (input.action !== "rotate" && (current.newAuthorizationId !== undefined
            || current.newKeyIdCommitment !== undefined || current.newPublicKey !== undefined))) {
          if (!preparing) {
            throw jsonProblem(problemBaseUri, "stale-governed-policy", 409,
              "stale governed policy action", "The key action no longer targets current ledger state.");
          }
          throw jsonProblem(problemBaseUri, "governed-policy-context-mismatch", 502,
            "governed policy context mismatch", "The lifecycle port returned a context for another key action.");
        }
        response.setHeader("cache-control", "no-store");
        if (preparing) {
          writeJson(response, 200, current);
          return;
        }
        const submitted = rotating
          ? GovernedEvidenceVerifierRotationSubmitRequestSchema.parse(body)
          : GovernedEvidenceVerifierStatusSubmitRequestSchema.parse(body);
        if (!sameGovernedPolicyAction(current, submitted.prepared)) {
          throw jsonProblem(problemBaseUri, "stale-governed-policy", 409,
            "stale governed policy action", "The signed context no longer matches current ledger state.");
        }
        let signers;
        try {
          signers = decodeGovernedMembershipSigners(submitted);
        } catch {
          throw jsonProblem(problemBaseUri, "invalid-governed-signature", 400,
            "invalid governed signature");
        }
        requireValidProposalSigners(signerContext, signers);
        try {
          const receipt = GovernedPolicyActionReceiptSchema.parse(
            await port.executeEvidenceVerifierTransition(input, signers),
          );
          writeJson(response, 202, receipt);
          return;
        } catch (error) {
          return mapGovernedPolicyError(error, problemBaseUri);
        }
      }

      if (
        method === "POST"
        && segments.length === 5
        && segments[0] === "v1"
        && segments[1] === "governed"
        && segments[2] === "policy"
        && segments[3] === "maintainer-recovery"
        && (segments[4] === "prepare" || segments[4] === "submit")
      ) {
        const port = requireGovernedPolicyActions(options, problemBaseUri);
        if (port.prepareMaintainerRecovery === undefined || port.executeMaintainerRecovery === undefined) {
          throw jsonProblem(problemBaseUri, "governed-policy-unavailable", 503,
            "governed policy actions unavailable", "An atomic maintainer recovery port is not configured.");
        }
        const preparing = segments[4] === "prepare";
        const body = await parseJsonBody(request, (value) => (preparing
          ? GovernedMaintainerRecoveryPrepareRequestSchema
          : GovernedMaintainerRecoverySubmitRequestSchema).parse(value), problemBaseUri);
        const { maintainerId, evidenceHash, thresholds } = body;
        let signerContext;
        let current;
        try {
          signerContext = await port.prepareMaintainerRecovery(maintainerId, evidenceHash, thresholds);
          current = serializeGovernedPolicyAction(signerContext);
        } catch (error) {
          if (!preparing && error instanceof GovernedPolicyActionRejectedError) {
            throw jsonProblem(problemBaseUri, "stale-governed-policy", 409,
              "stale governed policy action", "The signed context no longer matches current ledger state.");
          }
          return mapGovernedPolicyError(error, problemBaseUri);
        }
        if (current.maintainerId !== maintainerId
          || current.evidenceHash !== evidenceHash
          || current.actionKind !== RECOVER_MAINTAINER_ACTION_KIND
          || current.previousLifecycleEventHash === undefined) {
          throw jsonProblem(problemBaseUri, "governed-policy-context-mismatch", 502,
            "governed policy context mismatch", "The recovery port returned a context for another action or evidence commitment.");
        }
        response.setHeader("cache-control", "no-store");
        if (preparing) {
          writeJson(response, 200, current);
          return;
        }
        const submitted = GovernedMaintainerRecoverySubmitRequestSchema.parse(body);
        if (!sameGovernedPolicyAction(current, submitted.prepared)) {
          throw jsonProblem(problemBaseUri, "stale-governed-policy", 409,
            "stale governed policy action", "The signed context no longer matches current ledger state.");
        }
        let signers;
        try {
          signers = decodeGovernedMembershipSigners(submitted);
        } catch {
          throw jsonProblem(problemBaseUri, "invalid-governed-signature", 400,
            "invalid governed signature");
        }
        requireValidProposalSigners(signerContext, signers);
        try {
          const receipt = GovernedPolicyActionReceiptSchema.parse(
            await port.executeMaintainerRecovery(maintainerId, evidenceHash, thresholds, signers),
          );
          writeJson(response, 202, receipt);
          return;
        } catch (error) {
          return mapGovernedPolicyError(error, problemBaseUri);
        }
      }

      if (
        method === "POST"
        && segments.length === 5
        && segments[0] === "v1"
        && segments[1] === "governed"
        && segments[2] === "policy"
        && (segments[3] === "thresholds" || segments[3] === "evidence-verifier")
        && (segments[4] === "prepare" || segments[4] === "submit")
      ) {
        const port = requireGovernedPolicyActions(options, problemBaseUri);
        const thresholdsAction = segments[3] === "thresholds";
        const preparing = segments[4] === "prepare";
        const body = await parseJsonBody(request, (value) => thresholdsAction
          ? (preparing ? GovernedThresholdPrepareRequestSchema : GovernedThresholdSubmitRequestSchema).parse(value)
          : (preparing ? GovernedEvidenceVerifierPrepareRequestSchema
            : GovernedEvidenceVerifierSubmitRequestSchema).parse(value), problemBaseUri);
        const thresholds = thresholdsAction
          ? (preparing ? GovernedThresholdPrepareRequestSchema
            : GovernedThresholdSubmitRequestSchema).parse(body).thresholds
          : undefined;
        let signerContext;
        let current;
        try {
          signerContext = thresholds === undefined
            ? await port.prepareEvidenceVerifier()
            : await port.prepareThresholds(thresholds);
          current = serializeGovernedPolicyAction(signerContext);
        } catch (error) {
          return mapGovernedPolicyError(error, problemBaseUri);
        }
        response.setHeader("cache-control", "no-store");
        if (preparing) {
          writeJson(response, 200, current);
          return;
        }
        const submitted = thresholdsAction
          ? GovernedThresholdSubmitRequestSchema.parse(body)
          : GovernedEvidenceVerifierSubmitRequestSchema.parse(body);
        if (!sameGovernedPolicyAction(current, submitted.prepared)) {
          throw jsonProblem(problemBaseUri, "stale-governed-policy", 409,
            "stale governed policy action", "The signed context no longer matches current ledger state.");
        }
        let signers;
        try {
          signers = decodeGovernedMembershipSigners(submitted);
        } catch {
          throw jsonProblem(problemBaseUri, "invalid-governed-signature", 400,
            "invalid governed signature");
        }
        requireValidProposalSigners(signerContext, signers);
        try {
          const receipt = GovernedPolicyActionReceiptSchema.parse(thresholds === undefined
            ? await port.executeEvidenceVerifier(signers)
            : await port.executeThresholds(thresholds, signers));
          writeJson(response, 202, receipt);
          return;
        } catch (error) {
          return mapGovernedPolicyError(error, problemBaseUri);
        }
      }

      if (
        method === "POST"
        && segments.length === 4
        && segments[0] === "v1"
        && segments[1] === "governed"
        && segments[2] === "epochs"
        && (segments[3] === "prepare" || segments[3] === "publish")
      ) {
        const port = requireGovernedEpochPublication(options, problemBaseUri);
        if (segments[3] === "prepare") {
          const body = await parseJsonBody(request,
            (value) => GovernedEpochPrepareRequestSchema.parse(value), problemBaseUri);
          try {
            const prepared = serializeGovernedEpochPublication(await port.prepare(body.label));
            response.setHeader("cache-control", "no-store");
            writeJson(response, 200, prepared);
            return;
          } catch (error) {
            return mapGovernedEpochError(error, problemBaseUri);
          }
        }
        const body = await parseJsonBody(request,
          (value) => GovernedEpochPublishRequestSchema.parse(value), problemBaseUri);
        let signerContext;
        let current;
        try {
          signerContext = await port.prepare(body.label);
          current = serializeGovernedEpochPublication(signerContext);
        } catch (error) {
          return mapGovernedEpochError(error, problemBaseUri);
        }
        if (!sameGovernedEpochPublication(current, body.prepared)) {
          throw jsonProblem(problemBaseUri, "stale-governed-epoch", 409,
            "stale governed epoch", "The signed epoch context no longer matches current ledger state.");
        }
        let signers;
        try {
          signers = decodeGovernedMembershipSigners(body);
        } catch {
          throw jsonProblem(problemBaseUri, "invalid-governed-signature", 400,
            "invalid governed signature");
        }
        requireValidProposalSigners(signerContext, signers);
        try {
          const receipt = GovernedEpochPublicationReceiptSchema.parse(
            await port.execute(body.label, signers),
          );
          response.setHeader("cache-control", "no-store");
          writeJson(response, 202, receipt);
          return;
        } catch (error) {
          return mapGovernedEpochError(error, problemBaseUri);
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
        const targetId = parseApplicationIdentifier(segments[3]!, problemBaseUri);
        const action = GovernedMembershipActionSchema.parse(segments[5]);
        let signerContext;
        let prepared;
        try {
          signerContext = await port.prepare(role, targetId, action);
          prepared = serializeGovernedMembershipAction(signerContext, role);
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
        requireValidProposalSigners(signerContext, signers);
        let receipt;
        try {
          receipt = GovernedMembershipActionReceiptSchema.parse(
            await port.execute(role, targetId, action, signers),
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
        requireCompleteHistoricalProjection();
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
        requireCompleteHistoricalProjection();
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
        const body = await parseJsonBody(request, (value) => TrustRegistryApiSignedMutationRequestSchema.parse(value), problemBaseUri);
        if (options.governedRecognitionProposals !== undefined
          && body.operation.operation === "submit" && body.operation.target === "recognition") {
          throw jsonProblem(problemBaseUri, "recognition-proposal-admission-required", 403,
            "recognition proposal admission required",
            "Use the governed recognition proposal route with accepted accreditation evidence.");
        }
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
        if (options.governedRecognitionProposals !== undefined && body.target === "recognition") {
          throw jsonProblem(problemBaseUri, "recognition-proposal-admission-required", 403,
            "recognition proposal admission required",
            "Use the governed recognition proposal route with accepted accreditation evidence.");
        }
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
        && segments.length === 4
        && segments[0] === "v1"
        && segments[1] === "authorizations"
        && segments[2] === "evaluate"
        && segments[3] === "evidence"
      ) {
        const body = await parseJsonBody(request,
          (value) => TrustRegistryApiEvaluateAuthorizationRequestSchema.parse(value), problemBaseUri);
        requireCompleteHistoricalProjection();
        const evaluation = await evaluateAuthorizationEvidenceAtTimestamp(options.source, body, body.at);
        if (evaluation === null) {
          throw jsonProblem(problemBaseUri, "authorization-not-found", 404,
            "authorization not found", "No authorization matches the requested scope and timestamp.");
        }
        if (evaluation.bundle === null) {
          throw jsonProblem(problemBaseUri, "epoch-evidence-unavailable", 424,
            "epoch evidence unavailable", "No matching epoch-bound authorization evidence exists at the requested instant.");
        }
        writeJson(response, 200, TrustRegistryApiAuthorizationEvidenceEvaluationResponseSchema.parse(evaluation));
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
        requireCompleteHistoricalProjection();
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
        && segments.length === 4
        && segments[0] === "v1"
        && segments[1] === "recognitions"
        && segments[2] === "evaluate"
        && segments[3] === "evidence"
      ) {
        const body = await parseJsonBody(request,
          (value) => TrustRegistryApiEvaluateRecognitionRequestSchema.parse(value), problemBaseUri);
        requireCompleteHistoricalProjection();
        const evaluation = await evaluateRecognitionEvidenceAtTimestamp(options.source, body, body.at);
        if (evaluation === null) {
          throw jsonProblem(problemBaseUri, "recognition-not-found", 404,
            "recognition not found", "No recognition matches the requested scope and timestamp.");
        }
        if (evaluation.bundle === null) {
          throw jsonProblem(problemBaseUri, "epoch-evidence-unavailable", 424,
            "epoch evidence unavailable", "No matching epoch-bound recognition evidence exists at the requested instant.");
        }
        writeJson(response, 200, TrustRegistryApiRecognitionEvidenceEvaluationResponseSchema.parse(evaluation));
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
        requireCompleteHistoricalProjection();
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
        if (segments[3] === "query" || segments[3] === "evidence") {
          requireCompleteHistoricalProjection();
        }
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
        if (segments[3] === "query" || segments[3] === "evidence") {
          requireCompleteHistoricalProjection();
        }
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
