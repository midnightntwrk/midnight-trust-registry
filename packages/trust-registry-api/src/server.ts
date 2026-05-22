import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { ZodError } from "zod";

import {
  TrustRegistryTrqpAdapter,
  TrqpAuthorizationRequestSchema,
  TrqpRecognitionRequestSchema,
} from "@midnight-ntwrk/trust-registry-trqp-adapter";

import {
  createTrqpSourceFromStateSource,
  getAuthorizationEntryById,
  getRecognitionEntryById,
  listAuthorizationEntries,
  listRecognitionEntries,
  loadCurrentEpoch,
  loadEpochById,
  loadRegistryRecord,
  loadRegistrySummary,
  resolveAuthorizationEntry,
  resolveRecognitionEntry,
  type TrustRegistryApiStateSource,
} from "./source.js";
import {
  TrustRegistryApiAuthorizationListQuerySchema,
  TrustRegistryApiAuthorizationListResponseSchema,
  TrustRegistryApiAuthorizationResponseSchema,
  TrustRegistryApiEpochResponseSchema,
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
  status: number,
  title: string,
  detail?: string,
): HttpProblem =>
  new HttpProblem(
    TrustRegistryApiProblemDetailsSchema.parse({
      type: `${problemBaseUri}/${title.replace(/\s+/g, "-").toLowerCase()}`,
      title,
      status,
      detail,
    }),
  );

const readRequestBody = async (
  request: IncomingMessage,
): Promise<string> =>
  new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    request.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    request.on("error", reject);
  });

const parseJsonBody = async <T>(
  request: IncomingMessage,
  parse: (value: unknown) => T,
): Promise<T> => {
  const raw = await readRequestBody(request);
  const payload = raw.length === 0 ? {} : JSON.parse(raw);
  return parse(payload);
};

const writeJson = (
  response: ServerResponse,
  status: number,
  payload: unknown,
): void => {
  response.statusCode = status;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.end(`${JSON.stringify(payload, null, 2)}\n`);
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
      404,
      "recognition not found",
      `No recognition exists for id ${recognitionId}.`,
    );
  }

  return TrustRegistryApiRecognitionResponseSchema.parse(entry);
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
        && segments.length === 3
        && segments[0] === "v1"
        && segments[1] === "authorizations"
        && segments[2] === "resolve"
      ) {
        const body = await parseJsonBody(
          request,
          (value) => TrustRegistryApiResolveAuthorizationRequestSchema.parse(value),
        );
        const entry = await resolveAuthorizationEntry(options.source, body);
        if (entry === null) {
          throw jsonProblem(
            problemBaseUri,
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
        );
        const entry = await resolveRecognitionEntry(options.source, body);
        if (entry === null) {
          throw jsonProblem(
            problemBaseUri,
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
        );
        const result = segments[3] === "query"
          ? await trqpAdapter.queryAuthorization(body)
          : segments[3] === "evidence"
            ? await trqpAdapter.getAuthorizationEvidence(body)
            : null;
        if (result === null) {
          throw jsonProblem(
            problemBaseUri,
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
        );
        const result = segments[3] === "query"
          ? await trqpAdapter.queryRecognition(body)
          : segments[3] === "evidence"
            ? await trqpAdapter.getRecognitionEvidence(body)
            : null;
        if (result === null) {
          throw jsonProblem(
            problemBaseUri,
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
