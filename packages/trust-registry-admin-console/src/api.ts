import type {
  TrustRegistryApiApplicationAction,
  TrustRegistryApiApplicationMutationResponse,
  TrustRegistryApiApplicationTarget,
  TrustRegistryApiAuthorizationListResponse,
  TrustRegistryApiProblemDetails,
  TrustRegistryApiRecognitionListResponse,
  TrustRegistryApiSummary,
} from "@midnight-ntwrk/trust-registry-api";

import type { ReviewBoard } from "./model.js";

type FetchLike = typeof fetch;

export class TrustRegistryAdminConsoleApiError extends Error {
  constructor(
    readonly problem: Partial<TrustRegistryApiProblemDetails>,
  ) {
    super(problem.detail ?? problem.title ?? "trust-registry api error");
  }
}

export const normalizeApiBaseUrl = (
  value: string,
): string => value.trim().replace(/\/+$/, "");

const parseJson = async <T>(
  response: Response,
): Promise<T> => {
  const raw = await response.text();
  let payload: unknown;
  try {
    payload = raw.length === 0 ? null : JSON.parse(raw);
  } catch {
    payload = {
      title: response.statusText,
      detail: raw,
      status: response.status,
    } satisfies Partial<TrustRegistryApiProblemDetails>;
  }
  if (!response.ok) {
    throw new TrustRegistryAdminConsoleApiError(
      (payload ?? {}) as Partial<TrustRegistryApiProblemDetails>,
    );
  }

  return payload as T;
};

export class TrustRegistryAdminConsoleClient {
  readonly baseUrl: string;

  constructor(
    baseUrl: string,
    private readonly fetchImpl: FetchLike = fetch,
  ) {
    this.baseUrl = normalizeApiBaseUrl(baseUrl);
  }

  async loadReviewBoard(): Promise<ReviewBoard> {
    const [summary, issuers, verifiers, recognitions] = await Promise.all([
      this.request<TrustRegistryApiSummary>("/v1/registry/summary"),
      this.request<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/issuer"),
      this.request<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/verifier"),
      this.request<TrustRegistryApiRecognitionListResponse>("/v1/recognitions"),
    ]);

    return {
      summary,
      issuers: issuers.entries,
      verifiers: verifiers.entries,
      recognitions: recognitions.entries,
    };
  }

  async mutate(
    target: TrustRegistryApiApplicationTarget,
    id: string,
    action: TrustRegistryApiApplicationAction,
  ): Promise<TrustRegistryApiApplicationMutationResponse> {
    return this.request<TrustRegistryApiApplicationMutationResponse>(
      `/v1/applications/${encodeURIComponent(target)}/${encodeURIComponent(id)}/${encodeURIComponent(action)}`,
      {
        method: "POST",
      },
    );
  }

  async publishEpoch(
    label: string,
  ): Promise<TrustRegistryApiApplicationMutationResponse> {
    return this.request<TrustRegistryApiApplicationMutationResponse>(
      "/v1/epochs/publish",
      {
        method: "POST",
        ...(label.trim().length === 0
          ? {}
          : {
              headers: {
                "content-type": "application/json",
              },
              body: JSON.stringify({ label }),
            }),
      },
    );
  }

  private async request<T>(
    path: string,
    init?: RequestInit,
  ): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, init);
    return parseJson<T>(response);
  }
}
