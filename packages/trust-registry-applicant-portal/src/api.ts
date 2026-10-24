import type {
  TrustRegistryApiApplicationMutationResponse,
  TrustRegistryApiAuthorizationListResponse,
  TrustRegistryApiAuthorizationEvidenceEvaluationResponse,
  TrustRegistryApiEvaluateAuthorizationRequest,
  TrustRegistryApiEvaluateRecognitionRequest,
  TrustRegistryApiHealthResponse,
  TrustRegistryApiResolveAuthorizationRequest,
  TrustRegistryApiResolveRecognitionRequest,
  TrustRegistryApiProblemDetails,
  TrustRegistryApiRecognitionListResponse,
  TrustRegistryApiRecognitionEvidenceEvaluationResponse,
  TrustRegistryApiSummary,
  TrustRegistryApiMutationContext,
  TrustRegistryApiSignedMutationRequest,
  ApplicationVpHttpIssueResult,
  ApplicationVpHttpSubmissionResult,
  ApplicationChallengeBinding,
  PendingApplicationRecord,
  RecognitionAdmissionReceipt,
} from "@midnight-ntwrk/trust-registry-api";
import type { PortalSubmissionTarget, PublicInspection } from "./model.js";

type FetchLike = typeof fetch;

export const isCurrentlyActive = (
  record: { status?: string; effectiveUntil?: string | undefined } | undefined,
  startsAt: unknown,
  nowMs: number,
): boolean => {
  if (record?.status !== "active" || typeof startsAt !== "string") return false;
  if (record.effectiveUntil !== undefined && typeof record.effectiveUntil !== "string") return false;
  const activeFrom = Date.parse(startsAt);
  const effectiveUntil = record.effectiveUntil === undefined ? Infinity : Date.parse(record.effectiveUntil);
  return Number.isFinite(activeFrom) && !Number.isNaN(effectiveUntil)
    && activeFrom <= nowMs && nowMs <= effectiveUntil;
};

const isRenderableAuditorList = (value: unknown): value is TrustRegistryApiAuthorizationListResponse => {
  if (value === null || typeof value !== "object" || !("entries" in value) || !Array.isArray(value.entries)) {
    return false;
  }
  return value.entries.every((entry: unknown) => {
    if (entry === null || typeof entry !== "object" || !("authorization" in entry)) return false;
    const authorization = entry.authorization;
    if (authorization === null || typeof authorization !== "object") return false;
    const fields = ["authorizationId", "role", "status", "resourceType", "resourceId", "trustLevel", "subjectDid", "activeFrom"];
    return "label" in entry && typeof entry.label === "string"
      && fields.every((field) => field in authorization && typeof authorization[field as keyof typeof authorization] === "string")
      && (!("effectiveUntil" in authorization) || authorization.effectiveUntil === undefined
        || typeof authorization.effectiveUntil === "string");
  });
};

export class TrustRegistryApplicantPortalApiError extends Error {
  constructor(
    readonly problem: Partial<TrustRegistryApiProblemDetails>,
  ) {
    super(problem.detail ?? problem.title ?? "trust-registry api error");
  }
}

const isUnavailableLocalList = (error: unknown): boolean =>
  error instanceof TrustRegistryApplicantPortalApiError
    && error.problem.status === 503
    && error.problem.type?.endsWith("/local-list-projection-unavailable") === true;

const listWarning = (role: string): string =>
  `Current ${role} list is unavailable; no trust decision can be inferred.`;

export const normalizeApiBaseUrl = (
  value: string,
): string => value.trim().replace(/\/+$/, "");

const privateApplicationPath = (applicationId: string, action: "binding" | "challenges" | "submissions" | "receipt"): string => {
  if (applicationId.length === 0 || applicationId !== applicationId.trim()) {
    throw new Error("A valid application ID is required.");
  }
  return `/v1/application-evidence/${encodeURIComponent(applicationId)}/${action}`;
};

const parsePrivateResponse = async <T>(response: Response): Promise<T> => {
  if (!response.ok) {
    throw new TrustRegistryApplicantPortalApiError({
      status: response.status,
      title: `application evidence request failed (${response.status})`,
    });
  }
  try {
    return await response.json() as T;
  } catch {
    throw new Error("Application evidence response was invalid.");
  }
};

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

  async loadHistoricalAuthorizationEvidence(
    request: TrustRegistryApiEvaluateAuthorizationRequest,
  ): Promise<TrustRegistryApiAuthorizationEvidenceEvaluationResponse> {
    return this.request<TrustRegistryApiAuthorizationEvidenceEvaluationResponse>(
      "/v1/authorizations/evaluate/evidence",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
        cache: "no-store",
      },
    );
  }

  async loadHistoricalRecognitionEvidence(
    request: TrustRegistryApiEvaluateRecognitionRequest,
  ): Promise<TrustRegistryApiRecognitionEvidenceEvaluationResponse> {
    return this.request<TrustRegistryApiRecognitionEvidenceEvaluationResponse>(
      "/v1/recognitions/evaluate/evidence",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
        cache: "no-store",
      },
    );
  }

  async loadPublicInspection(): Promise<PublicInspection> {
    let localProjectionGated = false;
    const localList = async <T>(path: string): Promise<T | null> => {
      try {
        return await this.request<T>(path);
      } catch (error) {
        if (isUnavailableLocalList(error)) {
          localProjectionGated = true;
          return null;
        }
        throw error;
      }
    };
    const [health, summary, activeIssuers, activeVerifiers, auditorResult, activeRecognitions] =
      await Promise.all([
        this.request<TrustRegistryApiHealthResponse>("/health"),
        this.request<TrustRegistryApiSummary>("/v1/registry/summary"),
        localList<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/issuer?status=active"),
        localList<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/verifier?status=active"),
        localList<TrustRegistryApiAuthorizationListResponse>("/v1/authorizations/auditor?status=active")
          .then((value) => ({ value, failed: false as const }))
          .catch(() => ({ failed: true as const })),
        localList<TrustRegistryApiRecognitionListResponse>("/v1/recognitions?status=active"),
      ]);

    const nowMs = Date.now();
    const auditorEntries = auditorResult.failed || !isRenderableAuditorList(auditorResult.value)
      ? null : auditorResult.value.entries;
    if (activeIssuers !== null && !Array.isArray(activeIssuers.entries)) throw new Error("Issuer list response was invalid.");
    if (activeVerifiers !== null && !Array.isArray(activeVerifiers.entries)) throw new Error("Verifier list response was invalid.");
    if (activeRecognitions !== null && !Array.isArray(activeRecognitions.entries)) throw new Error("Recognition list response was invalid.");
    const unavailableLists = [
      ...(activeIssuers === null ? ["issuer" as const] : []),
      ...(activeVerifiers === null ? ["verifier" as const] : []),
      ...(auditorEntries === null ? ["auditor" as const] : []),
      ...(activeRecognitions === null ? ["recognition" as const] : []),
    ];
    if (localProjectionGated && health.sourceMode !== "local-ledger") {
      throw new Error("Local list projection gate requires a confirmed local-ledger API mode.");
    }
    if (health.sourceMode === "local-ledger"
      && (health.status !== "ok" || health.registryId !== summary.registryId)) {
      throw new Error("Local API health and registry summary do not match.");
    }
    return {
      summary,
      ...(health.sourceMode === "local-ledger" ? { sourceMode: "local-ledger" as const } : {}),
      activeAuditors: auditorEntries?.filter((entry) =>
        entry?.authorization?.role === "auditor"
          && isCurrentlyActive(entry.authorization, entry.authorization.activeFrom, nowMs)) ?? [],
      activeIssuers: activeIssuers?.entries.filter((entry) =>
        entry.authorization?.role === "issuer" && isCurrentlyActive(entry.authorization, entry.authorization.activeFrom, nowMs)) ?? [],
      activeVerifiers: activeVerifiers?.entries.filter((entry) =>
        entry.authorization?.role === "verifier" && isCurrentlyActive(entry.authorization, entry.authorization.activeFrom, nowMs)) ?? [],
      activeRecognitions: activeRecognitions?.entries.filter((entry) =>
        isCurrentlyActive(entry.recognition, entry.recognition?.effectiveFrom, nowMs)) ?? [],
      ...(unavailableLists.length === 0 ? {} : {
        unavailableLists,
        warnings: unavailableLists.map(listWarning),
      }),
    };
  }

  async loadCurrentAuthorization(
    request: TrustRegistryApiResolveAuthorizationRequest,
  ): Promise<TrustRegistryApiAuthorizationListResponse["entries"][number]> {
    return this.request("/v1/authorizations/resolve", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
      cache: "no-store",
    });
  }

  async loadCurrentRecognition(
    request: TrustRegistryApiResolveRecognitionRequest,
  ): Promise<TrustRegistryApiRecognitionListResponse["entries"][number]> {
    return this.request("/v1/recognitions/resolve", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
      cache: "no-store",
    });
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

  async loadAuditorAuthorization(authorizationId: string): Promise<TrustRegistryApiAuthorizationListResponse["entries"][number] | null> {
    if (authorizationId.length === 0 || authorizationId !== authorizationId.trim()) {
      throw new Error("A valid auditor authorization ID is required.");
    }
    try {
      return await this.request<TrustRegistryApiAuthorizationListResponse["entries"][number]>(
        `/v1/authorizations/auditor/${encodeURIComponent(authorizationId)}`,
        { cache: "no-store" },
      );
    } catch (error) {
      if (error instanceof TrustRegistryApplicantPortalApiError && error.problem.status === 404) return null;
      throw error;
    }
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

  /** Use only with an authenticated same-origin host; no presentation is stored by this client. */
  async registerPendingApplication(request: unknown): Promise<PendingApplicationRecord> {
    const response = await this.fetchImpl(`${this.baseUrl}/v1/pending-applications`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    return parsePrivateResponse<PendingApplicationRecord>(response);
  }

  /** Use only with an authenticated same-origin host; no presentation is stored by this client. */
  async loadPendingApplicationBinding(applicationId: string): Promise<ApplicationChallengeBinding> {
    const response = await this.fetchImpl(`${this.baseUrl}${privateApplicationPath(applicationId, "binding")}`, {
      method: "GET",
      credentials: "same-origin",
    });
    return parsePrivateResponse<ApplicationChallengeBinding>(response);
  }

  /** Use only with an authenticated same-origin host; no presentation is stored by this client. */
  async issueApplicationChallenge(applicationId: string): Promise<ApplicationVpHttpIssueResult> {
    const response = await this.fetchImpl(`${this.baseUrl}${privateApplicationPath(applicationId, "challenges")}`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    return parsePrivateResponse<ApplicationVpHttpIssueResult>(response);
  }

  /** The VP exists only in this request; the server returns signed redacted evidence. */
  async submitApplicationPresentation(
    applicationId: string,
    challenge: Pick<ApplicationVpHttpIssueResult, "nonce" | "challengeHash">,
    presentation: unknown,
  ): Promise<ApplicationVpHttpSubmissionResult> {
    const response = await this.fetchImpl(`${this.baseUrl}${privateApplicationPath(applicationId, "submissions")}`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nonce: challenge.nonce,
        challengeHash: challenge.challengeHash,
        presentation,
      }),
    });
    return parsePrivateResponse<ApplicationVpHttpSubmissionResult>(response);
  }

  /** Recover only accepted redacted evidence after a lost response; this never resubmits the VP. */
  async loadAcceptedApplicationEvidence(applicationId: string): Promise<ApplicationVpHttpSubmissionResult> {
    const response = await this.fetchImpl(`${this.baseUrl}${privateApplicationPath(applicationId, "receipt")}`, {
      method: "GET",
      credentials: "same-origin",
    });
    return parsePrivateResponse<ApplicationVpHttpSubmissionResult>(response);
  }

  /** Only the accredited authority's authenticated same-origin session may inspect this result. */
  async resolveRecognitionProposal(recognitionId: string, receiptId: string, evidenceCommitment: string): Promise<
    { state: "not-observed" } | { state: "observed"; eventHash: string }
  > {
    const response = await this.fetchImpl(
      `${this.baseUrl}/v1/governed/recognition/${encodeURIComponent(recognitionId)}/proposal/resolve`,
      {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ receiptId, evidenceCommitment }),
      },
    );
    return parsePrivateResponse(response);
  }

  /** Challenge and raw VP exchange are private and require an authenticated same-origin host. */
  async issueRecognitionChallenge(recognitionId: string): Promise<{
    recognitionId: string; nonce: string; challengeHash: string; issuedAt: string; expiresAt: string;
  }> {
    const response = await this.fetchImpl(
      `${this.baseUrl}/v1/recognition-evidence/${encodeURIComponent(recognitionId)}/challenges`,
      { method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "content-type": "application/json" }, body: "{}" },
    );
    return parsePrivateResponse(response);
  }

  async submitRecognitionAccreditation(recognitionId: string, signedSubmission: unknown): Promise<{
    recognitionId: string; evidenceCommitment: string; receipt?: RecognitionAdmissionReceipt; expiresAt: string;
  }> {
    const response = await this.fetchImpl(
      `${this.baseUrl}/v1/recognition-evidence/${encodeURIComponent(recognitionId)}/submissions`,
      { method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "content-type": "application/json" }, body: JSON.stringify(signedSubmission) },
    );
    return parsePrivateResponse(response);
  }

  async loadAcceptedRecognitionAccreditation(recognitionId: string): Promise<RecognitionAdmissionReceipt> {
    const response = await this.fetchImpl(
      `${this.baseUrl}/v1/recognition-evidence/${encodeURIComponent(recognitionId)}/accepted`,
      { method: "GET", credentials: "same-origin", cache: "no-store" },
    );
    return parsePrivateResponse(response);
  }

  private async request<T>(
    path: string,
    init?: RequestInit,
  ): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, init);
    return parseJson<T>(response);
  }
}
