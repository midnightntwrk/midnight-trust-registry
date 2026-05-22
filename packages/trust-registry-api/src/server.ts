import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { z, ZodError } from "zod";

import {
  TrustRegistryTrqpAdapter,
  TrqpAuthorizationRequestSchema,
  TrqpRecognitionRequestSchema,
} from "@midnight-ntwrk/trust-registry-trqp-adapter";

import {
  applyMutationOperation,
  createTrqpSourceFromStateSource,
  getAuthorizationEntryById,
  getRecognitionEntryById,
  isMutableStateSource,
  listAuthorizationEntries,
  listRecognitionEntries,
  loadCurrentEpoch,
  loadEpochById,
  loadRegistryRecord,
  loadRegistrySummary,
  resolveAuthorizationEntry,
  resolveRecognitionEntry,
  type TrustRegistryApiMutationResult,
  type TrustRegistryApiStateSource,
} from "./source.js";
import {
  TrustRegistryApiApplicationActionSchema,
  TrustRegistryApiApplicationMutationResponseSchema,
  TrustRegistryApiApplicationSubmitRequestSchema,
  TrustRegistryApiApplicationTargetSchema,
  TrustRegistryApiAuthorizationListQuerySchema,
  TrustRegistryApiAuthorizationListResponseSchema,
  TrustRegistryApiAuthorizationResponseSchema,
  TrustRegistryApiEpochResponseSchema,
  TrustRegistryApiEpochPublishRequestSchema,
  TrustRegistryApiEvidenceResponseSchema,
  TrustRegistryApiHealthResponseSchema,
  TrustRegistryApiProblemDetailsSchema,
  TrustRegistryApiRecognitionListQuerySchema,
  TrustRegistryApiRecognitionListResponseSchema,
  TrustRegistryApiRecognitionResponseSchema,
  TrustRegistryApiRegistryResponseSchema,
  TrustRegistryApiResolveAuthorizationRequestSchema,
  TrustRegistryApiResolveRecognitionRequestSchema,
  TrustRegistryApiSummarySchema,
  TrustRegistryApiAuthorizationRoleSchema,
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
): void => {
  response.statusCode = status;
  response.setHeader("access-control-allow-origin", "*");
  response.setHeader("access-control-allow-headers", "content-type");
  response.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.end(`${JSON.stringify(payload, null, 2)}\n`);
};

const writeNoContent = (
  response: ServerResponse,
): void => {
  response.statusCode = 204;
  response.setHeader("access-control-allow-origin", "*");
  response.setHeader("access-control-allow-headers", "content-type");
  response.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
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

const mapMutationError = (
  error: unknown,
  problemBaseUri: string,
): never => {
  if (error instanceof HttpProblem) {
    throw error;
  }
  if (error instanceof Error) {
    if (error.message.startsWith("unknown issuer authorization:")) {
      throw jsonProblem(
        problemBaseUri,
        "authorization-not-found",
        404,
        "authorization not found",
        error.message,
      );
    }
    if (error.message.startsWith("unknown verifier authorization:")) {
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
    if (
      error.message.startsWith("issuer label already submitted:")
      || error.message.startsWith("verifier label already submitted:")
      || error.message.startsWith("recognition label already submitted:")
    ) {
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
  const problemBaseUri = options.problemBaseUri ?? DEFAULT_PROBLEM_BASE;
  const trqpAdapter = new TrustRegistryTrqpAdapter(
    createTrqpSourceFromStateSource(options.source),
    {
      ...(options.clock === undefined ? {} : { clock: options.clock }),
      problemBaseUri: `${problemBaseUri}/trqp`,
    },
  );

  return createServer(async (request, response) => {
    try {
      const method = request.method ?? "GET";
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      const segments = routeSegments(url.pathname);

      if (method === "OPTIONS") {
        writeNoContent(response);
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
        && segments[1] === "applications"
      ) {
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

      throw jsonProblem(
        problemBaseUri,
        "route-not-found",
        404,
        "route not found",
        `No trust-registry API route matches ${method} ${url.pathname}.`,
      );
    } catch (error) {
      const problem = asProblem(error, problemBaseUri);
      writeJson(response, problem.status, problem);
    }
  });
};
