import type {
  TrustRegistryApiApplicationMutationResponse,
  TrustRegistryApiAuthorizationListResponse,
  TrustRegistryApiProblemDetails,
  TrustRegistryApiRecognitionListResponse,
  TrustRegistryApiSummary,
} from "@midnight-ntwrk/trust-registry-api";
import { evaluateAuthorizationRecordAtTime } from "@midnight-ntwrk/trust-registry-client";

import type { PortalSubmissionTarget, PublicInspection } from "./model.js";

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
  const payload = raw.length === 0
    ? null
    : (() => {
        try {
          return JSON.parse(raw);
        } catch {
          return {
            title: response.ok ? "invalid response" : "request failed",
            detail: raw,
            status: response.status,
          };
        }
      })();
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
    const [summary, activeIssuers, activeVerifiers, auditorResult, activeRecognitions] =
      await Promise.all([
        this.request<TrustRegistryApiSummary>("/v1/registry/summary"),
        this.request<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/issuer?status=active"),
        this.request<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/verifier?status=active"),
        this.request<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/auditor?status=active")
          .then((value) => ({ value, failed: false as const }))
          .catch(() => ({ failed: true as const })),
        this.request<TrustRegistryApiRecognitionListResponse>("/v1/recognitions?status=active"),
      ]);

    const now = new Date().toISOString();
    return {
      summary,
      activeAuditors: auditorResult.failed ? [] : auditorResult.value.entries.filter((entry) =>
        entry.authorization?.role === "auditor"
          && entry.authorization.status === "active"
          && evaluateAuthorizationRecordAtTime(entry.authorization, now).trustedAtTime),
      activeIssuers: activeIssuers.entries.filter((entry) =>
        entry.authorization?.role === "issuer" && entry.authorization.status === "active"),
      activeVerifiers: activeVerifiers.entries.filter((entry) =>
        entry.authorization?.role === "verifier" && entry.authorization.status === "active"),
      activeRecognitions: activeRecognitions.entries.filter((entry) =>
        entry.recognition?.status === "active"),
      ...(auditorResult.failed ? { warnings: ["Auditor records are temporarily unavailable."] } : {}),
    };
  }

  async submitApplication(
    target: PortalSubmissionTarget,
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
