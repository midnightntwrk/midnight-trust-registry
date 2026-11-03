import type {
  GovernedMembershipAction,
  GovernedMembershipActionReceipt,
  GovernedMembershipRole,
  GovernedMembershipSignatureRequest,
  GovernedEpochPublicationReceipt,
  GovernedEpochPublishRequest,
  GovernedEvidenceVerifierSubmitRequest,
  GovernedPolicyActionReceipt,
  GovernedThresholdSubmitRequest,
  GovernedThresholds,
  PreparedGovernedEpochPublication,
  PreparedGovernedPolicyAction,
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
  TrustRegistryApiHealthResponse,
  TrustRegistryApiMutationContext,
  TrustRegistryApiSignedMutationRequest,
} from "@midnight-ntwrk/trust-registry-api";

import { toAuthorizationReviewCard, toRecognitionReviewCard,
  type ReviewBoard, type ReviewCard, type ReviewTarget } from "./model.js";

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
    const health = await this.request<TrustRegistryApiHealthResponse>("/health", { cache: "no-store" });
    if (health.status !== "ok" || !["snapshot", "workspace", "memory", "local-ledger"].includes(health.sourceMode)) {
      throw new Error("Admin API health did not identify a supported source mode");
    }
    if (health.sourceMode === "local-ledger") {
      const planSha256 = health.localPlanSha256;
      if (typeof planSha256 !== "string" || !/^[0-9a-f]{64}$/u.test(planSha256)
        || !/^0x[0-9a-f]{64}$/u.test(health.finalizedBlockHash ?? "")) {
        throw new Error("Local admin API health lacks its approved plan or finalized checkpoint");
      }
      const summary = await this.request<TrustRegistryApiSummary>("/v1/registry/summary", { cache: "no-store" });
      if (summary.registryId !== health.registryId) {
        throw new Error("Local admin summary differs from the signed-plan registry");
      }
      return { sourceMode: "local-ledger", localPlanSha256: planSha256,
        summary, issuers: [], verifiers: [], auditors: [], recognitions: [] };
    }
    const [summary, issuers, verifiers, auditors, recognitions] = await Promise.all([
      this.request<TrustRegistryApiSummary>("/v1/registry/summary"),
      this.request<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/issuer"),
      this.request<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/verifier"),
      this.request<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/auditor"),
      this.request<TrustRegistryApiRecognitionListResponse>("/v1/recognitions"),
    ]);

    return {
      sourceMode: health.sourceMode,
      summary,
      issuers: issuers.entries,
      verifiers: verifiers.entries,
      auditors: auditors.entries,
      recognitions: recognitions.entries,
    };
  }

  async loadCurrentReviewCard(target: ReviewTarget, id: string, board: ReviewBoard): Promise<ReviewCard> {
    if (board.sourceMode !== "local-ledger" || id.trim().length === 0 || id.length > 256) {
      throw new Error("Exact-ID admin lookup requires the current local-ledger board");
    }
    const health = await this.request<TrustRegistryApiHealthResponse>("/health", { cache: "no-store" });
    if (health.status !== "ok" || health.sourceMode !== "local-ledger"
      || health.registryId !== board.summary.registryId
      || health.localPlanSha256 !== board.localPlanSha256
      || !/^0x[0-9a-f]{64}$/u.test(health.finalizedBlockHash ?? "")) {
      throw new Error("Local admin API plan or registry changed before the exact-ID lookup");
    }
    const path = target === "recognition"
      ? `/v1/recognitions/${encodeURIComponent(id)}`
      : `/v1/authorizations/${encodeURIComponent(target)}/${encodeURIComponent(id)}`;
    const entry = target === "recognition"
      ? await this.request<TrustRegistryApiRecognitionListResponse["entries"][number]>(path, { cache: "no-store" })
      : await this.request<TrustRegistryApiAuthorizationListResponse["entries"][number]>(path, { cache: "no-store" });
    const after = await this.request<TrustRegistryApiHealthResponse>("/health", { cache: "no-store" });
    if (after.status !== "ok" || after.sourceMode !== "local-ledger"
      || after.registryId !== health.registryId
      || after.localPlanSha256 !== health.localPlanSha256
      || after.finalizedBlockHash !== health.finalizedBlockHash
      || after.generatedAt !== health.generatedAt) {
      throw new Error("Local admin API checkpoint changed during the exact-ID lookup");
    }
    if (target === "recognition") {
      const recognition = entry as TrustRegistryApiRecognitionListResponse["entries"][number];
      if (recognition.recognition.registryId !== board.summary.registryId
        || recognition.recognition.recognitionId !== id) {
        throw new Error("Local recognition lookup returned a mismatched record");
      }
      return toRecognitionReviewCard(recognition);
    }
    const authorization = entry as TrustRegistryApiAuthorizationListResponse["entries"][number];
    if (authorization.authorization.registryId !== board.summary.registryId
      || authorization.authorization.authorizationId !== id
      || authorization.authorization.role !== target) {
      throw new Error("Local authorization lookup returned a mismatched record");
    }
    return toAuthorizationReviewCard(target, authorization);
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

  async prepareGovernedEpoch(label: string): Promise<PreparedGovernedEpochPublication> {
    return this.request<PreparedGovernedEpochPublication>("/v1/governed/epochs/prepare", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ label }),
    });
  }

  async submitGovernedEpoch(request: GovernedEpochPublishRequest): Promise<GovernedEpochPublicationReceipt> {
    return this.request<GovernedEpochPublicationReceipt>("/v1/governed/epochs/publish", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
  }

  async prepareThresholdRevision(thresholds: GovernedThresholds): Promise<PreparedGovernedPolicyAction> {
    return this.request<PreparedGovernedPolicyAction>("/v1/governed/policy/thresholds/prepare", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ thresholds }),
    });
  }

  async submitThresholdRevision(request: GovernedThresholdSubmitRequest): Promise<GovernedPolicyActionReceipt> {
    return this.request<GovernedPolicyActionReceipt>("/v1/governed/policy/thresholds/submit", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
  }

  async prepareEvidenceVerifierRegistration(): Promise<PreparedGovernedPolicyAction> {
    return this.request<PreparedGovernedPolicyAction>("/v1/governed/policy/evidence-verifier/prepare", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
  }

  async submitEvidenceVerifierRegistration(
    request: GovernedEvidenceVerifierSubmitRequest,
  ): Promise<GovernedPolicyActionReceipt> {
    return this.request<GovernedPolicyActionReceipt>("/v1/governed/policy/evidence-verifier/submit", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
  }

  private async request<T>(
    path: string,
    init?: RequestInit,
  ): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, init);
    return parseJson<T>(response);
  }
}
