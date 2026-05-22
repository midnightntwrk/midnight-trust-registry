import type {
  TrustRegistryApiApplicationMutationResponse,
  TrustRegistryApiApplicationTarget,
  TrustRegistryApiAuthorizationListResponse,
  TrustRegistryApiProblemDetails,
  TrustRegistryApiRecognitionListResponse,
  TrustRegistryApiSummary,
} from "@midnight-ntwrk/trust-registry-api";

import type { PublicInspection } from "./model.js";

type FetchLike = typeof fetch;

export class TrustRegistryApplicantPortalApiError extends Error {
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
  const payload = raw.length === 0 ? null : JSON.parse(raw);
  if (!response.ok) {
    throw new TrustRegistryApplicantPortalApiError(
      (payload ?? {}) as Partial<TrustRegistryApiProblemDetails>,
    );
  }
  return payload as T;
};

export class TrustRegistryApplicantPortalClient {
  readonly baseUrl: string;

  constructor(
    baseUrl: string,
    private readonly fetchImpl: FetchLike = fetch,
  ) {
    this.baseUrl = normalizeApiBaseUrl(baseUrl);
  }

  async loadPublicInspection(): Promise<PublicInspection> {
    const [summary, activeIssuers, activeVerifiers, activeRecognitions] =
      await Promise.all([
        this.request<TrustRegistryApiSummary>("/v1/registry/summary"),
        this.request<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/issuer?status=active"),
        this.request<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/verifier?status=active"),
        this.request<TrustRegistryApiRecognitionListResponse>("/v1/recognitions?status=active"),
      ]);

    return {
      summary,
      activeIssuers: activeIssuers.entries,
      activeVerifiers: activeVerifiers.entries,
      activeRecognitions: activeRecognitions.entries,
    };
  }

  async submitApplication(
    target: TrustRegistryApiApplicationTarget,
    label: string,
  ): Promise<TrustRegistryApiApplicationMutationResponse> {
    return this.request<TrustRegistryApiApplicationMutationResponse>(
      "/v1/applications",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({ target, label }),
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
