import type {
  GovernedMembershipAction,
  GovernedMembershipActionReceipt,
  GovernedMembershipRole,
  GovernedMembershipSignatureRequest,
  PreparedGovernedIssuerProposal,
  PreparedGovernedVerifierProposal,
  PreparedGovernedMaintainerProposal,
  PreparedGovernedMembershipAction,
  TrustRegistryApiApplicationAction,
  TrustRegistryApiApplicationMutationResponse,
  TrustRegistryApiApplicationTarget,
  TrustRegistryApiAuthorizationListResponse,
  TrustRegistryApiProblemDetails,
  TrustRegistryApiRecognitionListResponse,
  TrustRegistryApiSummary,
  TrustRegistryApiMutationContext,
  TrustRegistryApiSignedMutationRequest,
} from "@midnight-ntwrk/trust-registry-api";

import type { ReviewBoard } from "./model.js";

type FetchLike = typeof fetch;
export type GovernedProposalRole = Exclude<GovernedMembershipRole, "recognition">;
export type PreparedGovernedProposal = PreparedGovernedIssuerProposal | PreparedGovernedVerifierProposal
  | PreparedGovernedMaintainerProposal;
export type GovernedProposalResolution = { state: "not-observed" } | { state: "observed"; eventHash: string };

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
    const [summary, issuers, verifiers, auditors, recognitions] = await Promise.all([
      this.request<TrustRegistryApiSummary>("/v1/registry/summary"),
      this.request<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/issuer"),
      this.request<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/verifier"),
      this.request<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/auditor"),
      this.request<TrustRegistryApiRecognitionListResponse>("/v1/recognitions"),
    ]);

    return {
      summary,
      issuers: issuers.entries,
      verifiers: verifiers.entries,
      auditors: auditors.entries,
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

  async loadMutationContext(): Promise<TrustRegistryApiMutationContext> {
    return this.request<TrustRegistryApiMutationContext>("/v1/registry/mutation-context", {
      cache: "no-store",
    });
  }

  /** Submit an externally signed intent; this client never receives a private key. */
  async submitSignedMutation(
    request: TrustRegistryApiSignedMutationRequest,
  ): Promise<TrustRegistryApiApplicationMutationResponse> {
    return this.request<TrustRegistryApiApplicationMutationResponse>("/v1/mutations", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
  }

  async prepareGovernedAction(
    role: GovernedMembershipRole,
    id: string,
    action: GovernedMembershipAction,
  ): Promise<PreparedGovernedMembershipAction> {
    return this.request<PreparedGovernedMembershipAction>(
      `/v1/governed/${encodeURIComponent(role)}/${encodeURIComponent(id)}/actions/${encodeURIComponent(action)}`,
    );
  }

  async submitGovernedAction(
    role: GovernedMembershipRole,
    id: string,
    action: GovernedMembershipAction,
    request: GovernedMembershipSignatureRequest,
  ): Promise<GovernedMembershipActionReceipt> {
    return this.request<GovernedMembershipActionReceipt>(
      `/v1/governed/${encodeURIComponent(role)}/${encodeURIComponent(id)}/actions/${encodeURIComponent(action)}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
      },
    );
  }

  async prepareProposal(
    role: GovernedProposalRole,
    id: string,
    evidence: unknown,
  ): Promise<PreparedGovernedProposal> {
    return this.request<PreparedGovernedProposal>(
      `/v1/governed/${encodeURIComponent(role)}/${encodeURIComponent(id)}/proposal/prepare`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ evidence }),
      },
    );
  }

  async submitProposal(
    role: GovernedProposalRole,
    id: string,
    request: {
      evidence: unknown;
      prepared: PreparedGovernedProposal;
      signers: GovernedMembershipSignatureRequest["signers"];
      evidenceVerifierSignature: string;
    },
  ): Promise<GovernedMembershipActionReceipt> {
    return this.request<GovernedMembershipActionReceipt>(
      `/v1/governed/${encodeURIComponent(role)}/${encodeURIComponent(id)}/proposal/submit`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
      },
    );
  }

  async resolveProposal(
    role: GovernedProposalRole,
    id: string,
    evidence: unknown,
  ): Promise<GovernedProposalResolution> {
    return this.request<GovernedProposalResolution>(
      `/v1/governed/${encodeURIComponent(role)}/${encodeURIComponent(id)}/proposal/resolve`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ evidence }),
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
