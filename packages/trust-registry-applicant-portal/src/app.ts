import { TrustRegistryApplicantPortalApiError, TrustRegistryApplicantPortalClient, isCurrentlyActive, normalizeApiBaseUrl } from "./api.js";
import { TARGET_OPTIONS, describeSubmission, toInspectionCards, type PortalSubmissionTarget, type PublicInspection } from "./model.js";
import { TrustRegistryApiEvaluateRecognitionRequestSchema, TrustRegistryApiResolveRecognitionRequestSchema } from "@midnight-ntwrk/trust-registry-api/browser-schemas";
import type { ApplicationChallengeBinding, ApplicationVpHttpIssueResult, ApplicationVpHttpSubmissionResult, RecognitionAdmissionReceipt, TrustRegistryApiAuthorizationEvidenceEvaluationResponse, TrustRegistryApiAuthorizationListResponse, TrustRegistryApiEvaluateAuthorizationRequest, TrustRegistryApiEvaluateRecognitionRequest, TrustRegistryApiMutationContext, TrustRegistryApiRecognitionEvidenceEvaluationResponse, TrustRegistryApiRecognitionListResponse, TrustRegistryApiResolveAuthorizationRequest, TrustRegistryApiResolveRecognitionRequest, TrustRegistryApiSignedMutationRequest } from "@midnight-ntwrk/trust-registry-api";
import { canonicalizeAuthorizationScope, computeAuthorizationScopeCommitment, type PendingApplicationPayload } from "@midnight-ntwrk/trust-registry-domain/browser";
import { prepareAuditorApplication, signPreparedAuditorApplication, type AuditorApplicationDraft, type PreparedAuditorApplication } from "./auditor-application.js";
import { prepareIssuerApplication, prepareMaintainerApplication, prepareVerifierApplication, signPreparedMembershipApplication, type IssuerApplicationDraft, type MaintainerApplicationDraft, type PreparedMembershipApplication, type VerifierApplicationDraft } from "./membership-application.js";

const STORAGE_KEY = "trust-registry.portal.api-base";

type AppState = {
  apiBase: string;
  error: string | undefined;
  flash: string | undefined;
  inspection: PublicInspection | undefined;
  loading: boolean;
  observedAt: string | undefined;
  submitting: boolean;
  signedBusy: boolean;
  signedContext: TrustRegistryApiMutationContext | undefined;
  evidenceBusy: boolean;
  evidenceError: string | undefined;
  evidenceFlash: string | undefined;
  acceptedEvidence: ApplicationVpHttpSubmissionResult | undefined;
  pendingApplication: { binding: ApplicationChallengeBinding; challenge?: ApplicationVpHttpIssueResult } | undefined;
  auditorStatus: { authorizationId: string; status: string; currentTrust: boolean } | undefined;
  auditorStatusBusy: boolean;
  auditorDraft: AuditorApplicationDraft | undefined;
  auditorPreparationBusy: boolean;
  preparedAuditor: PreparedAuditorApplication | undefined;
  memberDraft: { role: "issuer"; draft: IssuerApplicationDraft } | { role: "verifier"; draft: VerifierApplicationDraft } | { role: "maintainer"; draft: MaintainerApplicationDraft } | undefined;
  memberPreparationBusy: boolean;
  preparedMember: PreparedMembershipApplication | undefined;
  currentAuthorizationQuery: TrustRegistryApiResolveAuthorizationRequest | undefined;
  currentAuthorizationResult: TrustRegistryApiAuthorizationListResponse["entries"][number] | undefined;
  currentAuthorizationBusy: boolean;
  currentAuthorizationError: string | undefined;
  currentRecognitionQuery: TrustRegistryApiResolveRecognitionRequest | undefined;
  currentRecognitionDraft: { recognizedAuthorityDid: string; recognizedRegistryId: string;
    scopeResourceType: string; scopeResourceId: string; scopeContext: string } | undefined;
  currentRecognitionResult: TrustRegistryApiRecognitionListResponse["entries"][number] | undefined;
  currentRecognitionBusy: boolean;
  currentRecognitionError: string | undefined;
  historicalQuery: TrustRegistryApiEvaluateAuthorizationRequest | undefined;
  historicalDraft: TrustRegistryApiEvaluateAuthorizationRequest | undefined;
  historicalResult: TrustRegistryApiAuthorizationEvidenceEvaluationResponse | undefined;
  historicalBusy: boolean;
  historicalError: string | undefined;
  historicalRecognitionQuery: TrustRegistryApiEvaluateRecognitionRequest | undefined;
  historicalRecognitionDraft: { recognizedAuthorityDid: string; recognizedRegistryId: string;
    scopeResourceType: string; scopeResourceId: string; scopeContext: string; at: string } | undefined;
  historicalRecognitionResult: TrustRegistryApiRecognitionEvidenceEvaluationResponse | undefined;
  historicalRecognitionBusy: boolean;
  historicalRecognitionError: string | undefined;
  recognitionRecoveryBusy: boolean;
  recognitionRecoveryMessage: string | undefined;
  recognitionId: string;
  recognitionChallenge: { recognitionId: string; nonce: string; challengeHash: string; expiresAt: string } | undefined;
  recognitionAdmission: RecognitionAdmissionReceipt | undefined;
};

type AuditorScopeInput = {
  requestProfileId: string;
  purpose: string;
  credentialScopeCommitment: string;
  allowedAttributes: string[];
  allowedPredicates: string[];
  disclosureLevel: string;
};

const parseScopeList = (value: string): string[] => {
  const items = value.split("\n").map((item) => item.trim()).filter((item) => item.length > 0);
  if (new Set(items).size !== items.length) throw new Error("Request scope lists cannot contain duplicate IDs.");
  return items;
};

const readAuditorDraft = (form: HTMLFormElement): AuditorApplicationDraft => {
  const field = (name: string) => form.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[name='${name}']`)?.value.trim() ?? "";
  return {
    applicationId: field("applicationId"),
    authorizationId: field("authorizationId"),
    actorDid: field("actorDid"),
    actorKeyId: field("actorKeyId"),
    requestProfileId: field("requestProfileId"),
    purpose: field("purpose"),
    credentialScopeCommitment: field("credentialScopeCommitment"),
    allowedAttributes: parseScopeList(field("allowedAttributes")),
    allowedPredicates: parseScopeList(field("allowedPredicates")),
    disclosureLevel: field("disclosureLevel"),
  };
};

const readMemberIdentity = (form: HTMLFormElement) => {
  const field = (name: string) => form.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[name='${name}']`)?.value.trim() ?? "";
  return { field, applicationId: field("applicationId"), authorizationId: field("authorizationId"), actorDid: field("actorDid"), actorKeyId: field("actorKeyId") };
};

const readIssuerDraft = (form: HTMLFormElement): IssuerApplicationDraft => {
  const { field, ...identity } = readMemberIdentity(form);
  return {
    ...identity,
    credentialFamilyId: field("credentialFamilyId"),
    schemaId: field("schemaId"),
    schemaVersion: field("schemaVersion"),
    credentialDefinitionId: field("credentialDefinitionId"),
    statusMethod: field("statusMethod"),
    governedResourceType: field("governedResourceType") as IssuerApplicationDraft["governedResourceType"],
  };
};

const readVerifierDraft = (form: HTMLFormElement): VerifierApplicationDraft => {
  const { field, ...identity } = readMemberIdentity(form);
  return {
    ...identity,
    requestProfileId: field("requestProfileId"),
    purpose: field("purpose"),
    credentialScopeCommitment: field("credentialScopeCommitment"),
    allowedAttributes: parseScopeList(field("allowedAttributes")),
    allowedPredicates: parseScopeList(field("allowedPredicates")),
    disclosureLevel: field("disclosureLevel"),
  };
};

const readMaintainerDraft = (form: HTMLFormElement): MaintainerApplicationDraft => {
  const identity = readMemberIdentity(form);
  return {
    applicationId: identity.applicationId,
    authorizationId: identity.authorizationId,
    actorDid: identity.actorDid,
    actorKeyId: identity.actorKeyId,
  };
};

const parseRecognitionContext = (raw: string): Record<string, string> | undefined => {
  if (raw.trim() === "") return undefined;
  const parsed: unknown = JSON.parse(raw);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
    || Object.values(parsed).some((value) => typeof value !== "string")) {
    throw new Error("Recognition scope context must be a JSON object of string values.");
  }
  return parsed as Record<string, string>;
};

const sameRecognitionContext = (
  left: unknown,
  right: Record<string, string> | undefined,
): boolean => {
  if (left === undefined || right === undefined) return left === undefined && right === undefined;
  if (left === null || typeof left !== "object" || Array.isArray(left)
    || Object.values(left).some((value) => typeof value !== "string")) return false;
  return JSON.stringify(Object.entries(left).sort()) === JSON.stringify(Object.entries(right).sort());
};

const auditorScopeMatches = (value: unknown, expected: AuditorScopeInput): boolean => {
  if (value === null || typeof value !== "object") return false;
  const scope = value as Record<string, unknown>;
  const sameList = (actual: unknown, wanted: string[]) => Array.isArray(actual)
    && actual.every((item) => typeof item === "string")
    && JSON.stringify([...actual].sort()) === JSON.stringify([...wanted].sort());
  return scope.version === "tr-scope-v1" && scope.role === "auditor"
    && scope.requestProfileId === expected.requestProfileId
    && scope.purpose === expected.purpose
    && scope.credentialScopeCommitment === expected.credentialScopeCommitment
    && scope.disclosureLevel === expected.disclosureLevel
    && sameList(scope.allowedAttributes, expected.allowedAttributes)
    && sameList(scope.allowedPredicates, expected.allowedPredicates);
};

export const canUsePrivateEvidenceHost = (apiBase: string, pageUrl: URL): boolean => {
  try {
    const api = new URL(apiBase);
    return api.username === "" && api.password === "" && api.origin === pageUrl.origin
      && (api.protocol === "https:" || api.hostname === "localhost" || api.hostname === "127.0.0.1");
  } catch {
    return false;
  }
};

export const escapeHtml = (value: string): string =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");

const formatObservationTime = (value: string): string => {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium", timeStyle: "short", timeZone: "UTC",
  }).format(date)} UTC`;
};

const downloadUnverifiedEvidence = (
  root: HTMLElement,
  kind: "historical-authorization-evidence" | "historical-recognition-evidence",
  query: unknown,
  result: unknown,
): void => {
  const payload = {
    format: "midnight-trust-registry-unverified-api-claim-v1",
    kind,
    verifiedFinality: false,
    query,
    result,
  };
  const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2) + "\n"], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `midnight-trust-registry-${kind}.json`;
  link.hidden = true;
  root.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};

const formatApiError = (error: unknown): string => {
  if (error instanceof TrustRegistryApplicantPortalApiError) {
    const title = error.problem.title ?? "request failed";
    return error.problem.detail === undefined ? title : `${title}: ${error.problem.detail}`;
  }

  return error instanceof Error ? error.message : String(error);
};

const isRenderablePendingBinding = (value: unknown, expectedApplicationId?: string): value is ApplicationChallengeBinding => {
  if (value === null || typeof value !== "object") return false;
  const binding = value as Partial<ApplicationChallengeBinding>;
  const resource = binding.governedResource;
  const scope = binding.scope;
  if (typeof binding.applicationId !== "string" || (expectedApplicationId !== undefined
    && binding.applicationId !== expectedApplicationId) || typeof binding.subjectDid !== "string"
    || typeof binding.policyId !== "string" || typeof binding.policyVersion !== "string"
    || typeof binding.scopeCommitment !== "string" || scope === undefined || scope === null
    || resource === undefined || resource === null
    || typeof resource.type !== "string" || typeof resource.id !== "string" || scope.role !== binding.role) {
    return false;
  }
  if (binding.role === "issuer") {
    return ["credentialFamily", "schema", "schemaVersion", "credentialDefinition", "statusMethodRequirement"]
      .includes(resource.type);
  }
  if (binding.role === "verifier" || binding.role === "auditor") return resource.type === "requestProfile";
  return binding.role === "maintainer" && resource.type === "registry";
};

export const createApplicantPortalApp = (
  root: HTMLElement,
  options: {
    fetchImpl?: typeof fetch;
    initialUrl?: URL;
    storage?: Storage;
    demoMode?: boolean;
  } = {},
): void => {
  const initialUrl = options.initialUrl ?? new URL(window.location.href);
  const demoMode = (options.demoMode ?? initialUrl.searchParams.get("demo") === "1")
    && ["localhost", "127.0.0.1", "[::1]"].includes(initialUrl.hostname);
  const storage = options.storage ?? window.localStorage;
  const fetchImpl = options.fetchImpl ?? window.fetch.bind(window);
  const sameOriginApi = initialUrl.pathname.startsWith("/applicant/");
  // An explicit query parameter is a one-off override for local testing and
  // should not silently replace the persisted default.
  const queryBase = initialUrl.searchParams.get("apiBase");
  let lookupActive: "authorization" | "recognition" = initialUrl.hash === "#current-recognition-lookup"
    ? "recognition" : "authorization";

  const state: AppState = {
    apiBase: sameOriginApi ? initialUrl.origin
      : normalizeApiBaseUrl(queryBase ?? storage.getItem(STORAGE_KEY) ?? "http://127.0.0.1:4400"),
    error: undefined,
    flash: undefined,
    inspection: undefined,
    loading: false,
    observedAt: undefined,
    submitting: false,
    signedBusy: false,
    signedContext: undefined,
    evidenceBusy: false,
    evidenceError: undefined,
    evidenceFlash: undefined,
    acceptedEvidence: undefined,
    pendingApplication: undefined,
    auditorStatus: undefined,
    auditorStatusBusy: false,
    auditorDraft: undefined,
    auditorPreparationBusy: false,
    preparedAuditor: undefined,
    memberDraft: undefined,
    memberPreparationBusy: false,
    preparedMember: undefined,
    currentAuthorizationQuery: undefined,
    currentAuthorizationResult: undefined,
    currentAuthorizationBusy: false,
    currentAuthorizationError: undefined,
    currentRecognitionQuery: undefined,
    currentRecognitionDraft: undefined,
    currentRecognitionResult: undefined,
    currentRecognitionBusy: false,
    currentRecognitionError: undefined,
    historicalQuery: undefined,
    historicalDraft: undefined,
    historicalResult: undefined,
    historicalBusy: false,
    historicalError: undefined,
    historicalRecognitionQuery: undefined,
    historicalRecognitionDraft: undefined,
    historicalRecognitionResult: undefined,
    historicalRecognitionBusy: false,
    historicalRecognitionError: undefined,
    recognitionRecoveryBusy: false,
    recognitionRecoveryMessage: undefined,
    recognitionId: "",
    recognitionChallenge: undefined,
    recognitionAdmission: undefined,
  };
  let evidenceRequestId = 0;
  let signedContextRequestId = 0;
  let auditorStatusRequestId = 0;
  let auditorPreparationRequestId = 0;
  let memberPreparationRequestId = 0;
  let historicalRequestId = 0;
  let historicalRecognitionRequestId = 0;
  let currentAuthorizationRequestId = 0;
  let currentRecognitionRequestId = 0;
  let inspectionRequestId = 0;
  let recognitionRequestId = 0;
  let recordSearchQuery = "";
  let demoSelection: PortalSubmissionTarget = "issuer";

  const filterRecordCards = () => {
    const overview = root.querySelector<HTMLElement>(".records-overview");
    if (overview === null) return;
    const query = recordSearchQuery.trim().toLocaleLowerCase();
    let visible = 0;
    overview.querySelectorAll<HTMLElement>(".lane").forEach((lane) => {
      let laneVisible = 0;
      const role = lane.querySelector("h2")?.textContent?.toLocaleLowerCase() ?? "";
      lane.querySelectorAll<HTMLElement>(".card").forEach((card) => {
        card.hidden = query !== "" && !role.includes(query)
          && !card.textContent?.toLocaleLowerCase().includes(query);
        if (!card.hidden) laneVisible += 1;
      });
      lane.hidden = query !== "" && laneVisible === 0 && lane.querySelector(".empty-state") === null;
      visible += laneVisible;
    });
    const count = overview.querySelector<HTMLElement>("[data-record-count]");
    if (count !== null) {
      const total = overview.querySelectorAll(".card").length;
      count.textContent = `${visible.toString()} of ${total.toString()} active ${total === 1 ? "record" : "records"} shown`;
    }
    const noMatch = overview.querySelector<HTMLElement>("[data-record-no-match]");
    if (noMatch !== null) noMatch.hidden = query === "" || visible > 0 || overview.querySelectorAll(".card").length === 0;
  };

  const setState = (next: Partial<AppState>) => {
    Object.assign(state, next);
    render();
  };

  const client = () => new TrustRegistryApplicantPortalClient(state.apiBase, fetchImpl);

  const issueRecognitionChallenge = async (recognitionId: string) => {
    if (state.recognitionRecoveryBusy || !canUsePrivateEvidenceHost(state.apiBase, initialUrl)) return;
    if (recognitionId.length === 0) {
      setState({ recognitionRecoveryMessage: "Enter the exact recognition ID." });
      return;
    }
    const requestId = ++recognitionRequestId;
    const apiBase = state.apiBase;
    setState({ recognitionRecoveryBusy: true, recognitionRecoveryMessage: undefined, recognitionId,
      recognitionChallenge: undefined, recognitionAdmission: undefined });
    try {
      const challenge = await client().issueRecognitionChallenge(recognitionId);
      if (requestId !== recognitionRequestId || apiBase !== state.apiBase) return;
      if (challenge.recognitionId !== recognitionId) throw new Error("Recognition challenge ID mismatch.");
      setState({ recognitionRecoveryBusy: false, recognitionChallenge: challenge });
    } catch (error) {
      if (requestId !== recognitionRequestId || apiBase !== state.apiBase) return;
      setState({ recognitionRecoveryBusy: false, recognitionRecoveryMessage: formatApiError(error) });
    }
  };

  const submitRecognitionAccreditation = async (recognitionId: string, raw: string) => {
    if (state.recognitionRecoveryBusy || !canUsePrivateEvidenceHost(state.apiBase, initialUrl)) return;
    if (state.recognitionChallenge?.recognitionId !== recognitionId) {
      setState({ recognitionRecoveryMessage: "Issue a challenge for this exact recognition before submitting." });
      return;
    }
    let submission: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Invalid accreditation submission.");
      submission = parsed as Record<string, unknown>;
      if (submission.nonce !== state.recognitionChallenge.nonce) throw new Error("Accreditation nonce does not match this challenge.");
    } catch {
      setState({ recognitionRecoveryMessage: "Accreditation submission must be JSON with the current challenge nonce." });
      return;
    }
    const requestId = ++recognitionRequestId;
    const apiBase = state.apiBase;
    setState({ recognitionRecoveryBusy: true, recognitionRecoveryMessage: undefined, recognitionId });
    try {
      const accepted = await client().submitRecognitionAccreditation(recognitionId, submission);
      if (requestId !== recognitionRequestId || apiBase !== state.apiBase) return;
      if (accepted.recognitionId !== recognitionId || accepted.receipt?.evidenceCommitment !== accepted.evidenceCommitment) {
        throw new Error("Accepted recognition receipt does not match the submission.");
      }
      setState({ recognitionRecoveryBusy: false, recognitionChallenge: undefined,
        recognitionAdmission: accepted.receipt,
        recognitionRecoveryMessage: `Recognition accreditation accepted. Governance approval is still required.` });
    } catch (error) {
      if (requestId !== recognitionRequestId || apiBase !== state.apiBase) return;
      setState({ recognitionRecoveryBusy: false, recognitionChallenge: undefined,
        recognitionRecoveryMessage: formatApiError(error) });
    }
  };

  const loadAcceptedRecognitionAccreditation = async (recognitionId: string) => {
    if (state.recognitionRecoveryBusy || !canUsePrivateEvidenceHost(state.apiBase, initialUrl)) return;
    if (recognitionId.length === 0) {
      setState({ recognitionRecoveryMessage: "Enter the exact recognition ID." });
      return;
    }
    const requestId = ++recognitionRequestId;
    const apiBase = state.apiBase;
    setState({ recognitionRecoveryBusy: true, recognitionRecoveryMessage: undefined, recognitionId });
    try {
      const receipt = await client().loadAcceptedRecognitionAccreditation(recognitionId);
      if (requestId !== recognitionRequestId || apiBase !== state.apiBase) return;
      if (receipt.recognitionId !== recognitionId) throw new Error("Accepted recognition receipt ID mismatch.");
      setState({ recognitionRecoveryBusy: false, recognitionAdmission: receipt,
        recognitionRecoveryMessage: "Accepted accreditation receipt recovered. Governance approval is still required." });
    } catch (error) {
      if (requestId !== recognitionRequestId || apiBase !== state.apiBase) return;
      setState({ recognitionRecoveryBusy: false, recognitionRecoveryMessage: formatApiError(error) });
    }
  };

  const recoverRecognitionProposal = async (recognitionId: string, receiptId: string, evidenceCommitment: string) => {
    if (state.recognitionRecoveryBusy || !canUsePrivateEvidenceHost(state.apiBase, initialUrl)) return;
    if (recognitionId.length === 0 || !/^0x[0-9a-f]{64}$/u.test(receiptId)
      || !/^0x[0-9a-f]{64}$/u.test(evidenceCommitment)) {
      setState({ recognitionRecoveryMessage: "Enter the exact recognition ID and 32-byte receipt and evidence commitments." });
      return;
    }
    const requestId = ++recognitionRequestId;
    const apiBase = state.apiBase;
    setState({ recognitionRecoveryBusy: true, recognitionRecoveryMessage: undefined, recognitionId });
    try {
      const result = await client().resolveRecognitionProposal(recognitionId, receiptId, evidenceCommitment);
      if (requestId !== recognitionRequestId || apiBase !== state.apiBase) return;
      setState({ recognitionRecoveryBusy: false, recognitionRecoveryMessage: result.state === "observed"
        ? `Compact recognition proposal observed: ${result.eventHash}. Network finality is not implied.`
        : "Recognition proposal not observed. This does not prove failure; do not resubmit automatically." });
    } catch (error) {
      if (requestId !== recognitionRequestId || apiBase !== state.apiBase) return;
      setState({ recognitionRecoveryBusy: false, recognitionRecoveryMessage: formatApiError(error) });
    }
  };

  const requirePrivateHost = () => {
    if (!canUsePrivateEvidenceHost(state.apiBase, initialUrl)) {
      throw new Error("Private evidence requires an authenticated same-origin HTTPS or localhost host.");
    }
  };

  const registerApplication = async (rawRequest: string, expectedAuditorScope?: AuditorScopeInput, expectedPayload?: PendingApplicationPayload) => {
    const requestId = ++evidenceRequestId;
    setState({
      evidenceBusy: true, pendingApplication: undefined, acceptedEvidence: undefined,
      evidenceError: undefined, evidenceFlash: undefined,
    });
    try {
      requirePrivateHost();
      let signedRequest: unknown;
      try {
        signedRequest = JSON.parse(rawRequest);
      } catch {
        throw new Error("Signed application must be valid JSON.");
      }
      if (signedRequest === null || typeof signedRequest !== "object" || Array.isArray(signedRequest)) {
        throw new Error("Signed application must be a JSON object.");
      }
      const candidate = signedRequest as {
        applicationId?: unknown;
        authorizationId?: unknown;
        scope?: { role?: unknown };
        governedResource?: { type?: unknown; id?: unknown };
        intent?: { target?: unknown; actorDid?: unknown; registryId?: unknown };
      };
      if (typeof candidate.applicationId !== "string" || typeof candidate.authorizationId !== "string"
        || candidate.authorizationId.length === 0 || typeof candidate.scope?.role !== "string"
        || !["issuer", "verifier", "auditor", "maintainer"].includes(candidate.scope.role)
        || candidate.intent?.target !== candidate.scope.role
        || typeof candidate.governedResource?.type !== "string"
        || typeof candidate.governedResource.id !== "string") {
        throw new Error("Signed application must request one matching membership role.");
      }
      if (expectedAuditorScope !== undefined && (!auditorScopeMatches(candidate.scope, expectedAuditorScope)
        || candidate.governedResource.type !== "requestProfile"
        || !/^tr:request-resource:v1:[0-9a-f]{64}$/u.test(candidate.governedResource.id))) {
        throw new Error("Signed auditor application does not match the complete request scope and canonical resource.");
      }
      if (expectedPayload !== undefined && (candidate.applicationId !== expectedPayload.applicationId
        || candidate.authorizationId !== expectedPayload.authorizationId
        || canonicalizeAuthorizationScope(candidate.scope as PendingApplicationPayload["scope"])
          !== canonicalizeAuthorizationScope(expectedPayload.scope)
        || candidate.governedResource.type !== expectedPayload.governedResource.type
        || candidate.governedResource.id !== expectedPayload.governedResource.id)) {
        throw new Error("Signed application does not match the prepared scope and resource.");
      }
      const record = await client().registerPendingApplication(signedRequest);
      if (requestId !== evidenceRequestId) return;
      if (record?.status !== "pending" || record.authorizationId !== candidate.authorizationId
        || !isRenderablePendingBinding(record.binding, candidate.applicationId)
        || record.binding.role !== candidate.scope.role
        || record.binding.governedResource.type !== candidate.governedResource.type
        || record.binding.governedResource.id !== candidate.governedResource.id
        || (expectedAuditorScope !== undefined && !auditorScopeMatches(record.binding.scope, expectedAuditorScope))) {
        throw new Error("Host did not return a canonical pending membership application.");
      }
      const binding = record.binding;
      if (expectedPayload !== undefined && (binding.registryId !== candidate.intent?.registryId
        || binding.subjectDid !== candidate.intent?.actorDid
        || binding.scopeCommitment !== computeAuthorizationScopeCommitment(expectedPayload.scope)
        || canonicalizeAuthorizationScope(binding.scope) !== canonicalizeAuthorizationScope(expectedPayload.scope))) {
        throw new Error("Host returned a different pending membership registry, scope, or applicant.");
      }
      setState({
        pendingApplication: { binding },
        preparedAuditor: undefined,
        auditorDraft: undefined,
        preparedMember: undefined,
        memberDraft: undefined,
        ...(binding.role === "auditor" ? {
          auditorStatus: { authorizationId: record.authorizationId, status: "pending", currentTrust: false },
        } : {}),
        evidenceFlash: `Pending ${binding.role} application ${binding.applicationId} registered. Present eligibility evidence next.`,
      });
    } catch (error) {
      if (requestId === evidenceRequestId) setState({ evidenceError: formatApiError(error) });
    } finally {
      if (requestId === evidenceRequestId) setState({ evidenceBusy: false });
    }
  };

  const prepareAuditor = async (draft: AuditorApplicationDraft) => {
    const requestId = ++auditorPreparationRequestId;
    const apiBase = state.apiBase;
    setState({ auditorDraft: draft, auditorPreparationBusy: true, preparedAuditor: undefined, evidenceError: undefined });
    try {
      requirePrivateHost();
      const context = await client().loadMutationContext();
      if (requestId !== auditorPreparationRequestId || apiBase !== state.apiBase) return;
      const nonce = `0x${Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
      const preparedAuditor = prepareAuditorApplication(draft, context, nonce);
      setState({ preparedAuditor, auditorPreparationBusy: false });
    } catch (error) {
      if (requestId === auditorPreparationRequestId && apiBase === state.apiBase) {
        setState({ auditorPreparationBusy: false, evidenceError: formatApiError(error) });
      }
    }
  };

  const prepareMember = async (
    member: { role: "issuer"; draft: IssuerApplicationDraft } | { role: "verifier"; draft: VerifierApplicationDraft } | { role: "maintainer"; draft: MaintainerApplicationDraft },
  ) => {
    const requestId = ++memberPreparationRequestId;
    const apiBase = state.apiBase;
    setState({ memberDraft: member, memberPreparationBusy: true, preparedMember: undefined, evidenceError: undefined });
    try {
      requirePrivateHost();
      const context = await client().loadMutationContext();
      if (requestId !== memberPreparationRequestId || apiBase !== state.apiBase) return;
      const nonce = `0x${Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
      const preparedMember = member.role === "issuer"
        ? prepareIssuerApplication(member.draft, context, nonce)
        : member.role === "verifier"
          ? prepareVerifierApplication(member.draft, context, nonce)
          : prepareMaintainerApplication(member.draft, context, nonce);
      setState({ preparedMember, memberPreparationBusy: false });
    } catch (error) {
      if (requestId === memberPreparationRequestId && apiBase === state.apiBase) {
        setState({ memberPreparationBusy: false, evidenceError: formatApiError(error) });
      }
    }
  };

  const loadApplicationBinding = async (applicationId: string) => {
    const requestId = ++evidenceRequestId;
    setState({
      evidenceBusy: true, pendingApplication: undefined, acceptedEvidence: undefined,
      evidenceError: undefined, evidenceFlash: undefined,
    });
    try {
      requirePrivateHost();
      const binding = await client().loadPendingApplicationBinding(applicationId);
      if (requestId !== evidenceRequestId) return;
      if (!isRenderablePendingBinding(binding, applicationId)) {
        throw new Error("This pending application is not a canonical membership request.");
      }
      setState({ pendingApplication: { binding } });
    } catch (error) {
      if (requestId === evidenceRequestId) setState({ evidenceError: formatApiError(error) });
    } finally {
      if (requestId === evidenceRequestId) setState({ evidenceBusy: false });
    }
  };

  const issueApplicationChallenge = async () => {
    const pending = state.pendingApplication;
    if (pending === undefined) return;
    const requestId = ++evidenceRequestId;
    setState({
      evidenceBusy: true, pendingApplication: { binding: pending.binding }, acceptedEvidence: undefined,
      evidenceError: undefined, evidenceFlash: undefined,
    });
    try {
      requirePrivateHost();
      const challenge = await client().issueApplicationChallenge(pending.binding.applicationId);
      if (requestId !== evidenceRequestId) return;
      if (challenge.applicationId !== pending.binding.applicationId) {
        throw new Error("Challenge application ID did not match the pending application.");
      }
      setState({ pendingApplication: { binding: pending.binding, challenge } });
    } catch (error) {
      if (requestId === evidenceRequestId) setState({ evidenceError: formatApiError(error) });
    } finally {
      if (requestId === evidenceRequestId) setState({ evidenceBusy: false });
    }
  };

  const submitApplicationPresentation = async (rawPresentation: string) => {
    const pending = state.pendingApplication;
    if (pending?.challenge === undefined) return;
    const requestId = ++evidenceRequestId;
    setState({ evidenceBusy: true, evidenceError: undefined, evidenceFlash: undefined });
    try {
      requirePrivateHost();
      let presentation: unknown;
      try {
        presentation = JSON.parse(rawPresentation);
      } catch {
        throw new Error("Presentation must be valid JSON.");
      }
      if (presentation === null || typeof presentation !== "object" || Array.isArray(presentation)) {
        throw new Error("Presentation must be a JSON object.");
      }
      const result = await client().submitApplicationPresentation(
        pending.binding.applicationId, pending.challenge, presentation,
      );
      if (requestId !== evidenceRequestId) return;
      setState({
        pendingApplication: { binding: pending.binding },
        acceptedEvidence: result,
        evidenceFlash: `${pending.binding.role} evidence accepted: ${result.receipt.receiptId}. The application still requires governance approval.`,
      });
    } catch (error) {
      if (requestId === evidenceRequestId) {
        setState({ pendingApplication: { binding: pending.binding }, evidenceError: formatApiError(error) });
      }
    } finally {
      if (requestId === evidenceRequestId) setState({ evidenceBusy: false });
    }
  };

  const recoverAcceptedEvidence = async (applicationId: string) => {
    const requestId = ++evidenceRequestId;
    setState({ evidenceBusy: true, acceptedEvidence: undefined, evidenceError: undefined, evidenceFlash: undefined });
    try {
      requirePrivateHost();
      const result = await client().loadAcceptedApplicationEvidence(applicationId);
      if (requestId !== evidenceRequestId) return;
      if (result.evidence.envelope.applicationId !== applicationId
        || result.receipt.evidenceCommitment !== result.evidence.commitment) {
        throw new Error("Accepted evidence does not match the requested application.");
      }
      setState({
        acceptedEvidence: result,
        evidenceFlash: `Accepted evidence recovered: ${result.receipt.receiptId}. Do not resubmit the VP.`,
      });
    } catch (error) {
      if (requestId === evidenceRequestId) setState({ evidenceError: formatApiError(error) });
    } finally {
      if (requestId === evidenceRequestId) setState({ evidenceBusy: false });
    }
  };

  const refreshAuditorStatus = async (authorizationId: string) => {
    const requestId = ++auditorStatusRequestId;
    const apiBase = state.apiBase;
    setState({ auditorStatusBusy: true, error: undefined });
    try {
      const entry = await client().loadAuditorAuthorization(authorizationId);
      if (requestId !== auditorStatusRequestId || apiBase !== state.apiBase) return;
      if (entry !== null && (entry.authorization.role !== "auditor"
        || entry.authorization.authorizationId !== authorizationId)) {
        throw new Error("Auditor status response did not match the requested authorization.");
      }
      setState({ auditorStatus: entry === null
        ? {
            authorizationId,
            status: state.auditorStatus?.authorizationId === authorizationId
              && state.auditorStatus.status === "pending" ? "pending" : "not recorded",
            currentTrust: false,
          }
        : {
            authorizationId,
            status: entry.authorization.status,
            currentTrust: isCurrentlyActive(entry.authorization, entry.authorization.activeFrom, Date.now()),
          } });
    } catch (error) {
      if (requestId === auditorStatusRequestId) setState({ error: formatApiError(error) });
    } finally {
      if (requestId === auditorStatusRequestId) setState({ auditorStatusBusy: false });
    }
  };

  const refreshInspection = async (flash?: string) => {
    const requestId = ++inspectionRequestId;
    const apiBase = state.apiBase;
    currentAuthorizationRequestId += 1;
    currentRecognitionRequestId += 1;
    setState({ loading: true, error: undefined, inspection: undefined,
      currentAuthorizationBusy: false, currentAuthorizationResult: undefined, currentAuthorizationError: undefined,
      currentRecognitionBusy: false, currentRecognitionResult: undefined, currentRecognitionError: undefined,
      ...(flash === undefined ? {} : { flash }) });
    try {
      const inspection = await client().loadPublicInspection();
      if (requestId !== inspectionRequestId || apiBase !== state.apiBase) return;
      setState({
        error: undefined,
        inspection,
        loading: false,
        observedAt: new Date().toISOString(),
      });
    } catch (error) {
      if (requestId !== inspectionRequestId || apiBase !== state.apiBase) return;
      setState({
        error: formatApiError(error),
        flash: undefined,
        inspection: undefined,
        loading: false,
        observedAt: undefined,
      });
    }
  };

  const loadCurrentAuthorization = async (query: TrustRegistryApiResolveAuthorizationRequest) => {
    if (state.currentAuthorizationBusy || state.inspection?.sourceMode !== "local-ledger") return;
    const requestId = ++currentAuthorizationRequestId;
    const apiBase = state.apiBase;
    setState({ currentAuthorizationQuery: query, currentAuthorizationBusy: true,
      currentAuthorizationResult: undefined, currentAuthorizationError: undefined });
    try {
      const result = await client().loadCurrentAuthorization(query, state.inspection!);
      if (requestId !== currentAuthorizationRequestId || apiBase !== state.apiBase) return;
      if (result?.authorization?.role !== query.role
        || result.authorization.subjectDid !== query.subjectDid
        || result.authorization.resourceId !== query.resourceId
        || (query.resourceType !== undefined && result.authorization.resourceType !== query.resourceType)
        || (query.trustLevel !== undefined && result.authorization.trustLevel !== query.trustLevel)
        || typeof result.label !== "string" || typeof result.authorization.status !== "string") {
        throw new Error("Current authorization response does not match the requested scope.");
      }
      setState({ currentAuthorizationResult: result });
    } catch (error) {
      if (requestId === currentAuthorizationRequestId && apiBase === state.apiBase) {
        setState({ currentAuthorizationError: formatApiError(error) });
      }
    } finally {
      if (requestId === currentAuthorizationRequestId && apiBase === state.apiBase) {
        setState({ currentAuthorizationBusy: false });
      }
    }
  };

  const loadCurrentRecognition = async (query: TrustRegistryApiResolveRecognitionRequest) => {
    if (state.currentRecognitionBusy || state.inspection?.sourceMode !== "local-ledger") return;
    const requestId = ++currentRecognitionRequestId;
    const apiBase = state.apiBase;
    setState({ currentRecognitionQuery: query, currentRecognitionDraft: undefined, currentRecognitionBusy: true,
      currentRecognitionResult: undefined, currentRecognitionError: undefined });
    try {
      const result = await client().loadCurrentRecognition(query, state.inspection!);
      if (requestId !== currentRecognitionRequestId || apiBase !== state.apiBase) return;
      const recognition = result?.recognition;
      if (recognition?.recognizedAuthorityDid !== query.recognizedAuthorityDid
        || recognition.recognizedRegistryId !== query.recognizedRegistryId
        || recognition.scope?.resourceType !== query.scopeResourceType
        || recognition.scope.resourceId !== query.scopeResourceId
        || !sameRecognitionContext(recognition.scope.context, query.scopeContext)
        || (query.trustLevel !== undefined && recognition.trustLevel !== query.trustLevel)
        || typeof result.label !== "string" || typeof recognition.status !== "string") {
        throw new Error("Current recognition response does not match the requested scope.");
      }
      setState({ currentRecognitionResult: result });
    } catch (error) {
      if (requestId === currentRecognitionRequestId && apiBase === state.apiBase) {
        setState({ currentRecognitionError: formatApiError(error) });
      }
    } finally {
      if (requestId === currentRecognitionRequestId && apiBase === state.apiBase) {
        setState({ currentRecognitionBusy: false });
      }
    }
  };

  const loadHistoricalEvidence = async (query: TrustRegistryApiEvaluateAuthorizationRequest) => {
    if (state.historicalBusy) return;
    const requestId = ++historicalRequestId;
    const apiBase = state.apiBase;
    setState({ historicalQuery: query, historicalBusy: true, historicalResult: undefined, historicalError: undefined });
    try {
      const result = await client().loadHistoricalAuthorizationEvidence(query);
      if (requestId !== historicalRequestId || apiBase !== state.apiBase) return;
      if (result.evaluatedAt !== query.at
        || (result.statusAtTime !== null && typeof result.statusAtTime !== "string")
        || typeof result.trustedAtTime !== "boolean"
        || typeof result.epoch?.epochId !== "string"
        || typeof result.bundle?.epoch?.epochId !== "string"
        || typeof result.bundle?.policy?.policyId !== "string"
        || result.epoch.epochId !== result.bundle.epoch.epochId
        || result.bundle?.authorization?.role !== query.role
        || result.bundle.authorization.subjectDid !== query.subjectDid
        || result.bundle.authorization.resourceId !== query.resourceId) {
        throw new Error("Historical evidence response does not match the requested record and epoch.");
      }
      setState({ historicalResult: result });
    } catch (error) {
      if (requestId === historicalRequestId && apiBase === state.apiBase) {
        setState({ historicalError: formatApiError(error) });
      }
    } finally {
      if (requestId === historicalRequestId && apiBase === state.apiBase) {
        setState({ historicalBusy: false });
      }
    }
  };

  const loadHistoricalRecognition = async (query: TrustRegistryApiEvaluateRecognitionRequest) => {
    if (state.historicalRecognitionBusy) return;
    const requestId = ++historicalRecognitionRequestId;
    const apiBase = state.apiBase;
    setState({ historicalRecognitionQuery: query, historicalRecognitionBusy: true,
      historicalRecognitionResult: undefined, historicalRecognitionError: undefined });
    try {
      const result = await client().loadHistoricalRecognitionEvidence(query);
      if (requestId !== historicalRecognitionRequestId || apiBase !== state.apiBase) return;
      const recognition = result.bundle?.recognition;
      if (result.evaluatedAt !== query.at
        || (result.statusAtTime !== null && typeof result.statusAtTime !== "string")
        || typeof result.trustedAtTime !== "boolean"
        || typeof result.epoch?.epochId !== "string"
        || typeof result.bundle?.epoch?.epochId !== "string"
        || typeof result.bundle?.policy?.policyId !== "string"
        || result.epoch.epochId !== result.bundle.epoch.epochId
        || recognition?.recognizedAuthorityDid !== query.recognizedAuthorityDid
        || recognition?.scope?.resourceId !== query.scopeResourceId
        || recognition?.recognizedRegistryId !== query.recognizedRegistryId
        || recognition?.scope?.resourceType !== query.scopeResourceType
        || !sameRecognitionContext(recognition?.scope?.context, query.scopeContext)) {
        throw new Error("Historical recognition response does not match the requested scope and epoch.");
      }
      setState({ historicalRecognitionResult: result });
    } catch (error) {
      if (requestId === historicalRecognitionRequestId && apiBase === state.apiBase) {
        setState({ historicalRecognitionError: formatApiError(error) });
      }
    } finally {
      if (requestId === historicalRecognitionRequestId && apiBase === state.apiBase) {
        setState({ historicalRecognitionBusy: false });
      }
    }
  };

  const submitApplication = async (
    target: PortalSubmissionTarget,
    label: string,
  ) => {
    if (!demoMode || state.inspection?.sourceMode === "local-ledger") return;
    setState({ submitting: true, error: undefined, flash: undefined });
    try {
      const result = await client().submitApplication(target, label);
      await refreshInspection(describeSubmission(result));
      const labelInput = root.querySelector<HTMLInputElement>("[name='label']");
      if (labelInput !== null) {
        labelInput.value = "";
      }
    } catch (error) {
      setState({
        error: formatApiError(error),
        flash: undefined,
        submitting: false,
      });
      return;
    }
    setState({ submitting: false });
  };

  const loadSignedContext = async () => {
    if (state.signedBusy) return;
    const requestId = ++signedContextRequestId;
    setState({ signedBusy: true, signedContext: undefined, error: undefined, flash: undefined });
    try {
      const signedContext = await client().loadMutationContext();
      if (requestId === signedContextRequestId) setState({ signedContext });
    } catch (error) {
      if (requestId === signedContextRequestId) setState({ error: formatApiError(error) });
    } finally {
      if (requestId === signedContextRequestId) setState({ signedBusy: false });
    }
  };

  const submitSignedApplication = async (raw: string) => {
    if (state.signedBusy || state.signedContext === undefined) return;
    let candidate: unknown;
    try {
      candidate = JSON.parse(raw);
    } catch {
      setState({ error: "Signed mutation envelope must be valid JSON." });
      return;
    }
    if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
      setState({ error: "Paste an externally signed issuer or verifier submission envelope." });
      return;
    }
    const parsed = candidate as Partial<TrustRegistryApiSignedMutationRequest>;
    if (parsed.operation?.operation !== "submit"
      || !["issuer", "verifier"].includes(parsed.operation.target)
      || parsed.intent === null || typeof parsed.intent !== "object"
      || parsed.signature === null || typeof parsed.signature !== "object") {
      setState({ error: "Paste an externally signed issuer or verifier submission envelope." });
      return;
    }
    const { intent } = parsed;
    const context = state.signedContext;
    if (intent.registryId !== context.registryId || intent.expectedEpochId !== context.expectedEpochId
      || intent.expectedWorkspaceCommitment !== context.expectedWorkspaceCommitment) {
      setState({ signedContext: undefined, error: "Signing context changed. Load a fresh context and sign again." });
      return;
    }
    const apiBase = state.apiBase;
    setState({ signedBusy: true, error: undefined, flash: undefined });
    try {
      const result = await client().submitSignedMutation(parsed as TrustRegistryApiSignedMutationRequest);
      if (state.apiBase !== apiBase) return;
      state.signedContext = undefined;
      await refreshInspection(`Signed ${result.operation.operation} accepted for ${parsed.operation.target}.`);
    } catch (error) {
      if (state.apiBase === apiBase) setState({ signedContext: undefined, error: formatApiError(error) });
    } finally {
      setState({ signedBusy: false });
    }
  };

  const bindEvents = () => {
    root.querySelectorAll<HTMLAnchorElement>(".mobile-task-menu nav a").forEach((link) => {
      link.addEventListener("click", () => {
        const menu = link.closest<HTMLDetailsElement>(".mobile-task-menu");
        if (menu !== null) menu.open = false;
      });
    });
    root.querySelector<HTMLFormElement>("[data-api-base-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      if (sameOriginApi) return;
      const form = event.currentTarget as HTMLFormElement | null;
      if (form === null) {
        return;
      }
      const input = form.querySelector<HTMLInputElement>("[name='apiBase']");
      if (input === null) {
        return;
      }
      const apiBase = normalizeApiBaseUrl(input.value);
      storage.setItem(STORAGE_KEY, apiBase);
      evidenceRequestId += 1;
      signedContextRequestId += 1;
      auditorStatusRequestId += 1;
      auditorPreparationRequestId += 1;
      memberPreparationRequestId += 1;
      historicalRequestId += 1;
      historicalRecognitionRequestId += 1;
      currentAuthorizationRequestId += 1;
      currentRecognitionRequestId += 1;
      recognitionRequestId += 1;
      setState({ apiBase, inspection: undefined, signedBusy: false, signedContext: undefined, pendingApplication: undefined, auditorStatus: undefined, auditorStatusBusy: false, auditorDraft: undefined, preparedAuditor: undefined, auditorPreparationBusy: false, memberDraft: undefined, preparedMember: undefined, memberPreparationBusy: false, currentAuthorizationBusy: false, currentAuthorizationResult: undefined, currentAuthorizationError: undefined, currentRecognitionBusy: false, currentRecognitionResult: undefined, currentRecognitionError: undefined, historicalBusy: false, historicalResult: undefined, historicalError: undefined, historicalDraft: undefined, historicalRecognitionBusy: false, historicalRecognitionResult: undefined, historicalRecognitionError: undefined, historicalRecognitionDraft: undefined, evidenceBusy: false, evidenceError: undefined, evidenceFlash: undefined,
        recognitionId: "", recognitionChallenge: undefined, recognitionAdmission: undefined,
        recognitionRecoveryBusy: false, recognitionRecoveryMessage: undefined });
      void refreshInspection();
    });

    root.querySelectorAll<HTMLButtonElement>("[data-refresh], [data-settings-refresh]").forEach((button) => button.addEventListener("click", () => {
      void refreshInspection();
    }));

    root.querySelector<HTMLFormElement>("[data-current-authorization]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const field = (name: string) => form.querySelector<HTMLInputElement>(`[name='${name}']`)?.value.trim() ?? "";
      const role = form.querySelector<HTMLSelectElement>("[name='role']")?.value;
      if (role !== "issuer" && role !== "verifier" && role !== "auditor") return;
      void loadCurrentAuthorization({ role, subjectDid: field("subjectDid"), resourceId: field("resourceId") });
    });

    root.querySelector<HTMLFormElement>("[data-current-recognition]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const field = (name: string) => form.querySelector<HTMLInputElement>(`[name='${name}']`)?.value.trim() ?? "";
      const draft = {
        recognizedAuthorityDid: field("recognizedAuthorityDid"),
        recognizedRegistryId: field("recognizedRegistryId"),
        scopeResourceType: field("scopeResourceType"),
        scopeResourceId: field("scopeResourceId"),
        scopeContext: form.querySelector<HTMLTextAreaElement>("[name='scopeContext']")?.value ?? "",
      };
      try {
        const scopeContext = parseRecognitionContext(draft.scopeContext);
        const { recognizedRegistryId, scopeResourceType } = draft;
        if (recognizedRegistryId === "" || scopeResourceType === "") {
          throw new Error("Recognition lookup requires registry ID and scope resource type.");
        }
        const query = TrustRegistryApiResolveRecognitionRequestSchema.parse({
          recognizedAuthorityDid: draft.recognizedAuthorityDid,
          recognizedRegistryId,
          scopeResourceType,
          scopeResourceId: draft.scopeResourceId,
          ...(scopeContext === undefined ? {} : { scopeContext }),
        });
        void loadCurrentRecognition(query);
      } catch (error) {
        setState({ currentRecognitionDraft: draft, currentRecognitionResult: undefined,
          currentRecognitionError: formatApiError(error) });
      }
    });

    root.querySelectorAll<HTMLButtonElement>("[data-copy-current-claim]").forEach((button) => {
      button.addEventListener("click", async () => {
        const details = button.closest("details");
        const claim = details?.querySelector("pre")?.textContent;
        const feedback = details?.querySelector<HTMLElement>("[data-copy-claim-feedback]");
        if (claim === undefined || claim === null || feedback === null || feedback === undefined) return;
        try {
          if (navigator.clipboard?.writeText === undefined) throw new Error("Clipboard unavailable");
          await navigator.clipboard.writeText(claim);
          feedback.textContent = "Copied current API claim. Verify before relying on it.";
        } catch {
          feedback.textContent = "Copy unavailable. Select the JSON below to copy it manually.";
        }
      });
    });

    root.querySelector<HTMLFormElement>("[data-historical-authorization]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const field = (name: string) => form.querySelector<HTMLInputElement>(`[name='${name}']`)?.value.trim() ?? "";
      const role = form.querySelector<HTMLSelectElement>("[name='role']")?.value;
      if (role !== "issuer" && role !== "verifier" && role !== "auditor") return;
      void loadHistoricalEvidence({ role, subjectDid: field("subjectDid"), resourceId: field("resourceId"), at: field("at") });
    });
    root.querySelector<HTMLFormElement>("[data-historical-authorization]")?.addEventListener("input", (event) => {
      const form = event.currentTarget as HTMLFormElement;
      const field = (name: string) => form.querySelector<HTMLInputElement>(`[name='${name}']`)?.value ?? "";
      const role = form.querySelector<HTMLSelectElement>("[name='role']")?.value;
      if (role === "issuer" || role === "verifier" || role === "auditor") {
        state.historicalDraft = { role, subjectDid: field("subjectDid"), resourceId: field("resourceId"), at: field("at") };
      }
      ++historicalRequestId;
      state.historicalBusy = false;
      state.historicalResult = undefined;
      root.querySelector("[data-historical-result]")?.remove();
      const submit = root.querySelector<HTMLButtonElement>("[data-historical-authorization] button[type='submit']");
      if (submit !== null) submit.disabled = false;
    });
    root.querySelector<HTMLButtonElement>("[data-download-historical-authorization]")?.addEventListener("click", () => {
      if (state.historicalQuery === undefined || state.historicalResult === undefined) return;
      downloadUnverifiedEvidence(root, "historical-authorization-evidence", state.historicalQuery, state.historicalResult);
    });

    root.querySelector<HTMLFormElement>("[data-historical-recognition]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const field = (name: string) => form.querySelector<HTMLInputElement>(`[name='${name}']`)?.value.trim() ?? "";
      try {
        const scopeContext = parseRecognitionContext(
          form.querySelector<HTMLTextAreaElement>("[name='scopeContext']")?.value ?? "",
        );
        const recognizedRegistryId = field("recognizedRegistryId");
        const scopeResourceType = field("scopeResourceType");
        if (recognizedRegistryId === "" || scopeResourceType === "") {
          throw new Error("Recognition lookup requires registry ID and scope resource type.");
        }
        const query = TrustRegistryApiEvaluateRecognitionRequestSchema.parse({
          recognizedAuthorityDid: field("recognizedAuthorityDid"),
          scopeResourceId: field("scopeResourceId"),
          at: field("at"),
          recognizedRegistryId,
          scopeResourceType,
          ...(scopeContext === undefined ? {} : { scopeContext }),
        });
        void loadHistoricalRecognition(query);
      } catch (error) {
        setState({ historicalRecognitionResult: undefined, historicalRecognitionError: formatApiError(error) });
      }
    });
    root.querySelector<HTMLFormElement>("[data-historical-recognition]")?.addEventListener("input", (event) => {
      const form = event.currentTarget as HTMLFormElement;
      const field = (name: string) => form.querySelector<HTMLInputElement>(`[name='${name}']`)?.value ?? "";
      state.historicalRecognitionDraft = {
        recognizedAuthorityDid: field("recognizedAuthorityDid"), recognizedRegistryId: field("recognizedRegistryId"),
        scopeResourceType: field("scopeResourceType"), scopeResourceId: field("scopeResourceId"),
        scopeContext: form.querySelector<HTMLTextAreaElement>("[name='scopeContext']")?.value ?? "", at: field("at"),
      };
      ++historicalRecognitionRequestId;
      state.historicalRecognitionBusy = false;
      state.historicalRecognitionResult = undefined;
      root.querySelector("[data-historical-recognition-result]")?.remove();
      const submit = root.querySelector<HTMLButtonElement>("[data-historical-recognition] button[type='submit']");
      if (submit !== null) submit.disabled = false;
    });
    root.querySelector<HTMLButtonElement>("[data-download-historical-recognition]")?.addEventListener("click", () => {
      if (state.historicalRecognitionQuery === undefined || state.historicalRecognitionResult === undefined) return;
      downloadUnverifiedEvidence(root, "historical-recognition-evidence",
        state.historicalRecognitionQuery, state.historicalRecognitionResult);
    });

    root.querySelector<HTMLButtonElement>("[data-signed-context]")?.addEventListener("click", () => {
      void loadSignedContext();
    });
    root.querySelector<HTMLFormElement>("[data-signed-submit]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const input = (event.currentTarget as HTMLFormElement).querySelector<HTMLTextAreaElement>("[name='signedEnvelope']");
      if (input === null) return;
      const raw = input.value;
      input.value = "";
      void submitSignedApplication(raw);
    });

    root.querySelector<HTMLFormElement>("[data-submit-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement | null;
      if (form === null) {
        return;
      }
      const targetInput = form.querySelector<HTMLInputElement>("[name='target']:checked");
      const labelInput = form.querySelector<HTMLInputElement>("[name='label']");
      if (targetInput === null || labelInput === null) {
        return;
      }
      const target = TARGET_OPTIONS.find((option) => option.value === targetInput.value)?.value;
      if (target === undefined) {
        setState({ error: "This portal does not support that application role." });
        return;
      }
      void submitApplication(target, labelInput.value.trim());
    });
    root.querySelector<HTMLFieldSetElement>(".demo-targets")?.addEventListener("change", (event) => {
      const input = event.target;
      if (!(input instanceof HTMLInputElement) || input.name !== "target") return;
      const target = TARGET_OPTIONS.find((option) => option.value === input.value)?.value;
      if (target !== undefined) demoSelection = target;
    });

    root.querySelector<HTMLFormElement>("[data-application-binding-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const applicationId = form.querySelector<HTMLInputElement>("[name='applicationId']")?.value.trim();
      if (applicationId !== undefined && applicationId.length > 0) void loadApplicationBinding(applicationId);
    });
    root.querySelector<HTMLButtonElement>("[data-application-receipt]")?.addEventListener("click", (event) => {
      const form = (event.currentTarget as HTMLButtonElement).closest<HTMLFormElement>("form");
      const applicationId = form?.querySelector<HTMLInputElement>("[name='applicationId']")?.value.trim();
      if (applicationId !== undefined && applicationId.length > 0) void recoverAcceptedEvidence(applicationId);
    });
    root.querySelector<HTMLButtonElement>("[data-recognition-challenge]")?.addEventListener("click", () => {
      const recognitionId = root.querySelector<HTMLInputElement>("[data-recognition-recovery-form] [name='recognitionId']")
        ?.value.trim() ?? "";
      void issueRecognitionChallenge(recognitionId);
    });
    root.querySelector<HTMLButtonElement>("[data-recognition-accepted]")?.addEventListener("click", () => {
      const recognitionId = root.querySelector<HTMLInputElement>("[data-recognition-recovery-form] [name='recognitionId']")
        ?.value.trim() ?? "";
      void loadAcceptedRecognitionAccreditation(recognitionId);
    });
    root.querySelector<HTMLFormElement>("[data-recognition-accreditation-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const raw = form.querySelector<HTMLTextAreaElement>("[name='signedAccreditation']")?.value ?? "";
      form.reset();
      void submitRecognitionAccreditation(state.recognitionId, raw);
    });
    root.querySelector<HTMLInputElement>("[data-recognition-recovery-form] [name='recognitionId']")
      ?.addEventListener("input", (event) => {
        const nextId = (event.currentTarget as HTMLInputElement).value.trim();
        if (nextId === state.recognitionId) return;
        state.recognitionId = nextId;
        state.recognitionChallenge = undefined;
        state.recognitionAdmission = undefined;
        root.querySelector("[data-recognition-challenge-context]")?.remove();
        root.querySelector("[data-recognition-admission]")?.remove();
      });
    root.querySelector<HTMLFormElement>("[data-recognition-recovery-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const value = (name: string) => form.querySelector<HTMLInputElement>(`[name='${name}']`)?.value.trim() ?? "";
      const recognitionId = value("recognitionId");
      const receiptId = value("receiptId");
      const evidenceCommitment = value("evidenceCommitment");
      form.reset();
      void recoverRecognitionProposal(recognitionId, receiptId, evidenceCommitment);
    });

    root.querySelector<HTMLFormElement>("[data-application-registration-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const input = form.querySelector<HTMLTextAreaElement>("[name='signedApplication']");
      if (input === null) return;
      const raw = input.value;
      input.value = "";
      void registerApplication(raw);
    });

    root.querySelector<HTMLButtonElement>("[data-prepare-auditor]")?.addEventListener("click", (event) => {
      const form = (event.currentTarget as HTMLButtonElement).closest<HTMLFormElement>("form");
      if (form === null) return;
      try {
        void prepareAuditor(readAuditorDraft(form));
      } catch (error) {
        setState({ evidenceError: formatApiError(error) });
      }
    });
    root.querySelector<HTMLButtonElement>("[data-reset-auditor]")?.addEventListener("click", () => {
      auditorPreparationRequestId += 1;
      setState({ auditorDraft: undefined, preparedAuditor: undefined, auditorPreparationBusy: false, evidenceError: undefined });
    });
    root.querySelector<HTMLFormElement>("[data-auditor-application-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const field = (name: string) => form.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[name='${name}']`)?.value.trim() ?? "";
      try {
        const prepared = state.preparedAuditor;
        const raw = prepared === undefined
          ? field("auditorSignedApplication")
          : JSON.stringify(signPreparedAuditorApplication(prepared, field("auditorSignature")));
        form.querySelector<HTMLTextAreaElement>("[name='auditorSignedApplication']")!.value = "";
        const signatureInput = form.querySelector<HTMLInputElement>("[name='auditorSignature']");
        if (signatureInput !== null) signatureInput.value = "";
        const scope: AuditorScopeInput = {
          requestProfileId: field("requestProfileId"),
          purpose: field("purpose"),
          credentialScopeCommitment: field("credentialScopeCommitment"),
          allowedAttributes: parseScopeList(field("allowedAttributes")),
          allowedPredicates: parseScopeList(field("allowedPredicates")),
          disclosureLevel: field("disclosureLevel"),
        };
        if (scope.requestProfileId.length === 0 || scope.purpose.length === 0
          || scope.disclosureLevel.length === 0
          || !/^0x[0-9a-f]{64}$/u.test(scope.credentialScopeCommitment)) {
          throw new Error("Auditor requests need a complete scope and 32-byte credential-scope commitment.");
        }
        void registerApplication(raw, scope);
      } catch (error) {
        setState({ evidenceError: formatApiError(error) });
      }
    });
    root.querySelector<HTMLButtonElement>("[data-prepare-issuer]")?.addEventListener("click", (event) => {
      const form = (event.currentTarget as HTMLButtonElement).closest<HTMLFormElement>("form");
      if (form !== null) void prepareMember({ role: "issuer", draft: readIssuerDraft(form) });
    });
    root.querySelector<HTMLButtonElement>("[data-prepare-verifier]")?.addEventListener("click", (event) => {
      const form = (event.currentTarget as HTMLButtonElement).closest<HTMLFormElement>("form");
      if (form === null) return;
      try {
        void prepareMember({ role: "verifier", draft: readVerifierDraft(form) });
      } catch (error) {
        setState({ evidenceError: formatApiError(error) });
      }
    });
    root.querySelector<HTMLButtonElement>("[data-prepare-maintainer]")?.addEventListener("click", (event) => {
      const form = (event.currentTarget as HTMLButtonElement).closest<HTMLFormElement>("form");
      if (form !== null) void prepareMember({ role: "maintainer", draft: readMaintainerDraft(form) });
    });
    for (const button of root.querySelectorAll<HTMLButtonElement>("[data-reset-member]")) {
      button.addEventListener("click", () => {
        memberPreparationRequestId += 1;
        setState({ preparedMember: undefined, memberPreparationBusy: false, evidenceError: undefined });
      });
    }
    for (const role of ["issuer", "verifier", "maintainer"] as const) {
      root.querySelector<HTMLFormElement>(`[data-${role}-application-form]`)?.addEventListener("submit", (event) => {
        event.preventDefault();
        const prepared = state.preparedMember;
        if (prepared?.payload.scope.role !== role) return;
        const form = event.currentTarget as HTMLFormElement;
        const signature = form.querySelector<HTMLInputElement>("[name='memberSignature']");
        if (signature === null) return;
        try {
          const signed = signPreparedMembershipApplication(prepared, signature.value.trim());
          signature.value = "";
          void registerApplication(JSON.stringify(signed), undefined, prepared.payload);
        } catch (error) {
          signature.value = "";
          setState({ evidenceError: formatApiError(error) });
        }
      });
    }
    root.querySelector<HTMLFormElement>("[data-auditor-status-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const authorizationId = form.querySelector<HTMLInputElement>("[name='auditorAuthorizationId']")?.value.trim();
      if (authorizationId !== undefined && authorizationId.length > 0) void refreshAuditorStatus(authorizationId);
    });

    root.querySelector<HTMLButtonElement>("[data-application-challenge]")?.addEventListener("click", () => {
      void issueApplicationChallenge();
    });

    root.querySelector<HTMLFormElement>("[data-application-vp-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const input = form.querySelector<HTMLTextAreaElement>("[name='presentation']");
      if (input === null) return;
      const raw = input.value;
      input.value = "";
      void submitApplicationPresentation(raw);
    });
    const roleLinks = [...root.querySelectorAll<HTMLAnchorElement>(".journey-cards [data-open-workflow]")];
    const syncRoleLinks = () => {
      for (const link of roleLinks) {
        const id = link.dataset.openWorkflow ?? "";
        link.setAttribute("aria-controls", id);
        link.setAttribute("aria-expanded", String(root.querySelector<HTMLDetailsElement>(`#${id}`)?.open === true));
      }
    };
    root.querySelectorAll<HTMLDetailsElement>(".role-workflow").forEach((details) => {
      details.addEventListener("toggle", syncRoleLinks);
    });
    syncRoleLinks();
    root.querySelectorAll<HTMLAnchorElement>("[data-open-workflow]").forEach((link) => {
      link.addEventListener("click", (event) => {
        const target = root.querySelector<HTMLDetailsElement>(`#${link.dataset.openWorkflow ?? ""}`);
        if (target === null) return;
        event.preventDefault();
        if (roleLinks.includes(link)) {
          root.querySelectorAll<HTMLDetailsElement>(".role-workflow").forEach((details) => {
            details.open = details === target;
          });
          syncRoleLinks();
        } else target.open = true;
        target.scrollIntoView({ block: "start", behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
        target.querySelector("summary")?.focus();
      });
    });
    root.querySelector<HTMLInputElement>("[data-record-search]")?.addEventListener("input", (event) => {
      recordSearchQuery = (event.currentTarget as HTMLInputElement).value;
      filterRecordCards();
    });
  };

  const renderInspectionLane = (
    title: string,
    cards: readonly ReturnType<typeof toInspectionCards>[number][],
    unavailable: boolean,
  ): string => `
    <section class="lane">
      <div class="lane-header">
        <h2>${escapeHtml(title)}</h2>
        <span>${unavailable ? "unavailable" : `${cards.length.toString()} active`}</span>
      </div>
      ${unavailable
        ? `<div class="empty-state"><p>Current list unavailable. Do not infer trust from this lane.</p></div>`
        : cards.length === 0
        ? `<div class="empty-state"><p>No active entries in this lane yet.</p></div>`
        : cards.map((card) => `
          <article class="card">
            <h3>${escapeHtml(card.label)}</h3>
            <p>Trust level: <strong>${escapeHtml(card.trustLevel)}</strong></p>
            <details class="record-identifiers"><summary>Scope and DID</summary>
              <p class="technical-id">${escapeHtml(card.scope)}</p>
              <p class="technical-id">${escapeHtml(card.subject)}</p>
            </details>
          </article>
        `).join("")}
    </section>
  `;

  let pendingFocusKey: string | null = null;
  const render = () => {
    const previousSignedEnvelope = root.querySelector<HTMLTextAreaElement>("[data-signed-submit] [name='signedEnvelope']")?.value;
    const focusKey = root.contains(document.activeElement)
      ? document.activeElement?.getAttribute("data-focus-key") : null;
    pendingFocusKey = focusKey ?? pendingFocusKey;
    const openWorkflows = new Set([...root.querySelectorAll<HTMLDetailsElement>(".workflow-disclosure[open]")]
      .map((details) => details.dataset.workflow));
    const advancedOpen = root.querySelector<HTMLDetailsElement>(".advanced-tools")?.open ?? false;
    const previousVpForm = root.querySelector<HTMLFormElement>("[data-application-vp-form]");
    const previousVp = previousVpForm?.querySelector<HTMLTextAreaElement>("[name='presentation']")?.value;
    const previousChallengeHash = previousVpForm?.dataset.challengeHash;
    const cards = state.inspection === undefined ? [] : toInspectionCards(state.inspection);
    const issuerCards = cards.filter((card) => card.target === "issuer");
    const verifierCards = cards.filter((card) => card.target === "verifier");
    const auditorCards = cards.filter((card) => card.target === "auditor");
    const recognitionCards = cards.filter((card) => card.target === "recognition");
    const privateHost = canUsePrivateEvidenceHost(state.apiBase, initialUrl);
    const pending = state.pendingApplication;
    const auditorDraft = state.auditorDraft;
    const preparedAuditor = state.preparedAuditor;
    const auditorLocked = preparedAuditor === undefined ? "" : " disabled";
    const issuerDraft = state.memberDraft?.role === "issuer" ? state.memberDraft.draft : undefined;
    const verifierDraft = state.memberDraft?.role === "verifier" ? state.memberDraft.draft : undefined;
    const maintainerDraft = state.memberDraft?.role === "maintainer" ? state.memberDraft.draft : undefined;
    const preparedIssuer = state.preparedMember?.payload.scope.role === "issuer" ? state.preparedMember : undefined;
    const preparedVerifier = state.preparedMember?.payload.scope.role === "verifier" ? state.preparedMember : undefined;
    const preparedMaintainer = state.preparedMember?.payload.scope.role === "maintainer" ? state.preparedMember : undefined;
    const issuerLocked = preparedIssuer === undefined ? "" : " disabled";
    const verifierLocked = preparedVerifier === undefined ? "" : " disabled";
    const maintainerLocked = preparedMaintainer === undefined ? "" : " disabled";
    const demoApplication = !demoMode || state.inspection === undefined || state.inspection.sourceMode === "local-ledger" ? "" : `
      <form class="form-panel" id="demo-application" data-submit-form>
        <div class="demo-copy">
          <p class="eyebrow">Local fixture</p>
          <h2>Try a local application</h2>
          <p>Choose an application type and a name reviewers will recognize. An admin can review and activate this label-only fixture request next. It does not grant on-chain authority.</p>
        </div>
        <div class="demo-fields">
          <fieldset class="demo-targets"><legend>Application type</legend>
            <div class="demo-target-grid">
              ${TARGET_OPTIONS.map((option) => `<label class="demo-target-option"><input type="radio" name="target" value="${escapeHtml(option.value)}"${demoSelection === option.value ? " checked" : ""} /><span><strong>${escapeHtml(option.label)}</strong><small>${escapeHtml(option.description)}</small></span></label>`).join("")}
            </div>
          </fieldset>
          <label class="label">Name shown to reviewers
            <input class="input" name="label" type="text" placeholder="Example issuer" required />
          </label>
          <button class="button" type="submit"${state.submitting ? " disabled" : ""}>Send demo application</button>
        </div>
      </form>
    `;
    const taskLinks = state.inspection === undefined ? `
      <a href="#connection-details">Check connection</a>
      <a href="#governed-requests">View role requirements</a>
    ` : state.inspection.sourceMode === "local-ledger" ? `
      <a href="#current-authorization-lookup">Look up authorization</a>
      <a href="#current-recognition-lookup">Look up recognition</a>
      <a href="#governed-requests">Prepare membership</a>
      <a href="#connection-details">Workspace settings</a>
    ` : `
      ${demoMode ? `<a href="#demo-application">Try a local demo application</a>` : ""}
      <a href="#governed-requests">Prepare governed membership</a>
      <a href="#trust-records">Explore active records</a>
      <a href="#connection-details">Workspace settings</a>
    `;
    const journeyPicker = `
          <section class="journey-picker" id="governed-requests" aria-labelledby="journey-heading">
            <div class="journey-heading"><p class="eyebrow">Governed requests</p><h2 id="journey-heading">${demoMode && state.inspection !== undefined && state.inspection.sourceMode !== "local-ledger" ? "Applying beyond the demo?" : "What would you like to do?"}</h2>
              <p>Choose a role to see its scope, evidence, and signing steps. Nothing is submitted until you confirm.</p>
            </div>
            <p class="journey-prerequisite">${state.inspection === undefined ? "Connect to a registry source before preparing a governed request." : privateHost ? "You can prepare a request here. The host must authenticate your session before submission." : "Local connection: prepare only. Submission requires an authenticated same-origin host."}</p>
            <div class="journey-cards">
              <a href="#issuer-request" data-open-workflow="issuer-request"><span class="role-mark" aria-hidden="true">I</span><strong>Become an issuer</strong><span>Issue credentials in a defined scope.</span><em>View issuer steps &rarr;</em></a>
              <a href="#verifier-request" data-open-workflow="verifier-request"><span class="role-mark" aria-hidden="true">V</span><strong>Become a verifier</strong><span>Verify a precise scope.</span><em>View verifier steps &rarr;</em></a>
              <a href="#auditor-request" data-open-workflow="auditor-request"><span class="role-mark" aria-hidden="true">A</span><strong>Become an auditor</strong><span>Oversee a defined audit scope.</span><em>View auditor steps &rarr;</em></a>
              <a href="#maintainer-request" data-open-workflow="maintainer-request"><span class="role-mark" aria-hidden="true">M</span><strong>Join maintenance</strong><span>Request committee membership.</span><em>View maintainer steps &rarr;</em></a>
            </div>
            <div class="journey-guide">
              <div class="journey-steps">
                <p class="eyebrow">Your path</p><h3>Four steps to submit a request</h3>
                <ol>
                  <li><strong>Choose a role</strong><span>Confirm the authority and scope.</span></li>
                  <li><strong>Prepare evidence</strong><span>Provide the exact resource and redacted role evidence.</span></li>
                  <li><strong>Sign and submit</strong><span>Sign externally; submit through an authenticated host.</span></li>
                  <li><strong>Keep the receipt</strong><span>Save returned IDs. A receipt is not approval.</span></li>
                </ol>
              </div>
              <aside class="journey-requirements"><p class="eyebrow">Before you start</p><h3>What you’ll need</h3>
                <p>Your subject DID, exact scope or registry resource, and role evidence.</p>
                <p>Private submission needs a same-origin authenticated host and an external signature. This browser never handles private keys.</p>
              </aside>
            </div>
          </section>`;

    const sourceMessage = state.loading
      ? "Checking this source. Records and results are hidden until the check completes."
      : state.inspection?.sourceMode === "local-ledger"
        ? "This response is not independently verified finality or authorization evidence. Broad lists are not offered in this mode; use exact lookup."
        : state.inspection === undefined
          ? "Connect or retry to inspect this source. No trust decision is available."
          : "Fixture records are for exploration, not deployed ledger evidence.";
    const partialFailureMessage = !state.loading && state.inspection?.sourceMode !== "local-ledger"
      && state.inspection?.unavailableLists?.length
      ? ` ${state.inspection.unavailableLists.length} list(s) unavailable; counts shown as n/a.` : "";

    root.innerHTML = `
      <main class="shell app-shell" data-settings-active="${window.location.hash === "#connection-details"}">
        <header class="brand-bar">
          <span class="brand-name"><img class="brand-logo" src="./midnight-logo.svg" alt="Midnight" /><span class="brand-product"><strong class="brand-product-title">Trust Registry</strong><span class="brand-product-context">Applicant portal</span></span></span>
          <details class="mobile-task-menu"><summary>Menu</summary><nav aria-label="Portal tasks">${taskLinks}</nav></details>
        </header>
        <nav class="task-nav" aria-label="Portal tasks">${taskLinks}</nav>
        <section class="hero">
          <div class="hero-intro">
            <p class="eyebrow">Applicant workspace</p>
            <h1>Find your place in the registry</h1>
            <p>${state.inspection === undefined
              ? "Registry data is unavailable. Recheck the connection before inspecting or submitting a request."
              : state.inspection.sourceMode === "local-ledger"
                ? "Look up an exact authorization or recognition, then prepare a governed request. Verify finalized registry state independently before relying on an API claim."
                : demoMode ? "Try a local application, browse records, or prepare a governed request. Demo records are not on-chain trust decisions." : "Browse this registry snapshot or prepare a governed request. Fixture records are not on-chain trust decisions."}</p>
            <div class="hero-actions">
              <a class="button" href="${state.inspection === undefined ? "#connection-details" : state.inspection.sourceMode === "local-ledger" ? "#current-authorization-lookup" : !demoMode ? "#governed-requests" : "#demo-application"}">${state.inspection === undefined ? "Check connection" : state.inspection.sourceMode === "local-ledger" ? "Look up a record" : !demoMode ? "Choose a role" : "Try the demo"}</a>
              ${state.inspection === undefined ? "" : state.inspection.sourceMode === "local-ledger"
                ? `<a class="button secondary" href="#governed-requests">Choose a role</a>`
                : `<a class="button secondary" href="#trust-records">Explore records</a>`}
            </div>
          </div>
          <div class="hero-overview">
            <p class="eyebrow">${state.inspection?.sourceMode === "local-ledger" ? "Registry context" : "Registry snapshot"}</p>
            <div class="panel metrics">
              <div class="metric"><span>Registry</span><strong>${escapeHtml(state.inspection?.summary.registryLabel ?? "Unavailable")}</strong></div>
              <div class="metric"><span>${state.inspection?.sourceMode === "local-ledger" ? "API-reported epoch" : "Current epoch"}</span><strong>${state.inspection?.summary.epochCount === undefined ? "Unavailable" : `#${state.inspection.summary.epochCount.toString()}`}</strong></div>
              ${state.inspection?.sourceMode === "local-ledger" ? "" : `
                <div class="metric"><span>Active issuers</span><strong>${state.inspection === undefined || state.inspection.unavailableLists?.includes("issuer") ? "n/a" : state.inspection.activeIssuers.length.toString()}</strong></div>
                <div class="metric"><span>Active verifiers</span><strong>${state.inspection === undefined || state.inspection.unavailableLists?.includes("verifier") ? "n/a" : state.inspection.activeVerifiers.length.toString()}</strong></div>`}
            </div>
          </div>
          ${state.error === undefined ? "" : `<div class="alert error" role="alert">${escapeHtml(state.error)}</div>`}
          ${state.inspection?.warnings?.map((warning) => `<div class="alert error">${escapeHtml(warning)}</div>`).join("") ?? ""}
          ${state.flash === undefined ? "" : `<div class="alert success" role="status">${escapeHtml(state.flash)}</div>`}
          <div class="source-panel" data-source-state="${state.loading ? "loading" : state.inspection === undefined ? "unavailable" : state.inspection.sourceMode === "local-ledger" ? "local-ledger" : "fixture"}" role="status" aria-live="polite">
            <span class="source-badge">${state.loading ? "Checking" : state.inspection === undefined ? "Unavailable" : state.inspection.sourceMode === "local-ledger" ? "API claim" : "Local fixture"}</span>
            <div class="source-copy"><strong>${state.loading ? "Loading registry data" : state.inspection === undefined ? "No current registry data" : state.inspection.sourceMode === "local-ledger" ? "Current local-ledger API response" : "Demo workspace data"}</strong>
              <span>${sourceMessage}${partialFailureMessage}</span>
            </div>
            ${state.observedAt === undefined || state.loading ? "" : `<span class="source-time">Checked <time datetime="${escapeHtml(state.observedAt)}">${escapeHtml(formatObservationTime(state.observedAt))}</time> (browser clock)</span>`}
            <button class="source-refresh" type="button" data-refresh data-focus-key="refresh"${state.loading ? " disabled" : ""}>Recheck</button>
          </div>
        </section>
        <section class="settings-view" id="connection-details" aria-labelledby="settings-heading">
          <div class="settings-heading">
            <a class="settings-back" href="${state.inspection?.sourceMode === "local-ledger" ? `#current-${lookupActive}-lookup` : "#governed-requests"}">&larr; Back to applicant workspace</a>
            <p class="eyebrow">Configuration</p>
            <h1 id="settings-heading">Workspace settings</h1>
            <p>Check the API source and the registry identity it reports. These are browser observations, not independently verified trust evidence.</p>
          </div>
          <div class="settings-cards">
            <section class="settings-card" aria-labelledby="portal-connection-heading">
              <p class="eyebrow">Connection</p>
              <h2 id="portal-connection-heading">API and source</h2>
              <p>Choose a local API for development, or inspect the same-origin endpoint managed by this host.</p>
            <form class="connection-form" data-api-base-form>
              <label class="label">API base URL
                <input class="input mono" type="url" name="apiBase" data-focus-key="api-base" value="${escapeHtml(state.apiBase)}"${sameOriginApi ? " disabled" : ""} />
              </label>
              <div class="row">
                <button class="button" type="submit" data-focus-key="connect"${sameOriginApi || state.loading ? " disabled" : ""}>Connect</button>
              </div>
            </form>
            <dl class="settings-grid">
              <div><dt>API endpoint</dt><dd class="technical-id">${escapeHtml(state.apiBase)}${sameOriginApi ? " (managed by this host)" : " (local development setting)"}</dd></div>
              <div><dt>Connection</dt><dd>${state.loading ? "Checking" : state.inspection === undefined ? "Unavailable" : "Responding at last check"}</dd></div>
              <div><dt>Source mode</dt><dd>${escapeHtml(state.inspection?.sourceMode ?? (state.inspection === undefined ? "Unavailable" : "Fixture workspace"))}</dd></div>
              <div><dt>Last checked in this browser</dt><dd>${state.observedAt === undefined ? "No successful check" : `<time datetime="${escapeHtml(state.observedAt)}">${escapeHtml(formatObservationTime(state.observedAt))}</time>`}</dd></div>
            </dl>
            <button class="source-refresh" type="button" data-settings-refresh data-focus-key="settings-refresh"${state.loading ? " disabled" : ""}>Recheck connection</button>
            </section>
            <section class="settings-card" aria-labelledby="portal-identity-heading">
              <p class="eyebrow">Read-only</p>
              <h2 id="portal-identity-heading">Deployment identity</h2>
              <dl class="settings-grid">
              <div><dt>Registry ID</dt><dd class="technical-id">${escapeHtml(state.inspection?.summary.registryId ?? "Not reported")}</dd></div>
              <div><dt>Registry DID</dt><dd class="technical-id">${escapeHtml(state.inspection?.summary.registryDid ?? "Not reported")}</dd></div>
              <div><dt>Current epoch ID</dt><dd class="technical-id">${escapeHtml(state.inspection?.summary.currentEpochId ?? "Not reported")}</dd></div>
              ${state.inspection?.sourceMode !== "local-ledger" ? "" : `<div><dt>Node-reported checkpoint hash</dt><dd class="technical-id">${escapeHtml(state.inspection.nodeReportedCheckpointHash ?? "Not reported")}</dd></div>
              <div><dt>Node-reported checkpoint time</dt><dd>${escapeHtml(state.inspection.nodeReportedAt ?? "Not reported")}</dd></div>`}
              <div><dt>Network profile, genesis, contract</dt><dd>Not exposed by this API response</dd></div>
            </dl>
            <p class="settings-callout">Node-reported data and a browser response do not establish finalized ledger state or actor authorization.</p>
            </section>
          </div>
          <div class="settings-footer"><strong>No account profile in this browser</strong><p>Private actions require the authenticated same-origin host and external signing. Connection details are not proof of finality.</p></div>
        </section>
        <section class="content">
          ${demoApplication}
          ${state.inspection?.sourceMode === "local-ledger" ? "" : journeyPicker}
          ${state.inspection?.sourceMode === "local-ledger" ? `
          <section class="lookup-picker" aria-labelledby="lookup-picker-heading">
            <p class="eyebrow">Current local ledger</p>
            <h2 id="lookup-picker-heading">What are you checking?</h2>
            <nav class="lookup-switch" aria-label="Current lookup type">
              <a href="#current-authorization-lookup" aria-controls="current-authorization-lookup"${lookupActive === "authorization" ? ' aria-current="location"' : ""}>Authorization</a>
              <a href="#current-recognition-lookup" aria-controls="current-recognition-lookup"${lookupActive === "recognition" ? ' aria-current="location"' : ""}>External recognition</a>
            </nav>
          </section>
          <section class="form-panel current-lookup-panel" id="current-authorization-lookup"${lookupActive === "authorization" ? "" : " hidden"}>
            <div class="lookup-input">
              <div class="lookup-copy">
                <p class="eyebrow">Authorization lookup</p>
                <h2>Who, for what, in which role?</h2>
                <p>Broad browsing is unavailable here. Enter the exact subject DID, role, and governed resource to request the current record.</p>
              </div>
              <form data-current-authorization>
                <label class="label">Role<select class="select" name="role">
                  ${(["issuer", "verifier", "auditor"] as const).map((role) => `<option value="${role}"${state.currentAuthorizationQuery?.role === role ? " selected" : ""}>${role}</option>`).join("")}
                </select></label>
                <label class="label">Subject DID<input class="input mono" name="subjectDid" value="${escapeHtml(state.currentAuthorizationQuery?.subjectDid ?? "")}" required /></label>
                <label class="label">Governed resource ID<input class="input mono" name="resourceId" value="${escapeHtml(state.currentAuthorizationQuery?.resourceId ?? "")}" required /></label>
                <button class="button" type="submit" data-focus-key="current-authorization-submit"${state.currentAuthorizationBusy ? " disabled" : ""}>Look up current authorization</button>
              </form>
            </div>
            <aside class="lookup-result" aria-label="Current authorization result">
              <h3 class="eyebrow">Result</h3>
              ${state.currentAuthorizationError === undefined ? "" : `<div class="alert error" role="alert">${escapeHtml(state.currentAuthorizationError)}</div>`}
              ${state.currentAuthorizationResult === undefined && state.currentAuthorizationError === undefined ? `<div class="lookup-empty"><h3>No record loaded yet</h3><p>Enter an exact role, DID, and governed resource to inspect the API's current claim.</p></div>` : ""}
              ${state.currentAuthorizationResult === undefined ? "" : `<div class="lookup-claim" data-current-authorization-result role="status">
                <p><strong>Unverified current API claim:</strong> ${escapeHtml(state.currentAuthorizationResult.authorization.status)}.</p>
                <details><summary>Inspect returned authorization</summary><button class="button secondary claim-copy" type="button" data-copy-current-claim>Copy current API claim</button><span class="copy-claim-feedback" data-copy-claim-feedback role="status" aria-live="polite"></span><pre class="mono" tabindex="0" aria-label="Scrollable authorization JSON">${escapeHtml(JSON.stringify(state.currentAuthorizationResult, null, 2))}</pre></details>
              </div>`}
              <div class="lookup-interpretation"><strong>How to interpret a result</strong><p>A returned status is not independently authenticated finality. Do not use it as the sole basis for a trust decision.</p></div>
            </aside>
          </section>
          <section class="form-panel current-lookup-panel" id="current-recognition-lookup"${lookupActive === "recognition" ? "" : " hidden"}>
            <div class="lookup-input">
              <div class="lookup-copy">
                <p class="eyebrow">External recognition lookup</p>
                <h2>Which authority and scope?</h2>
                <p>Enter the external authority, registry, and exact scope. Recognition does not grant local membership.</p>
              </div>
              <form data-current-recognition>
                <label class="label">Recognized authority DID<input class="input mono" name="recognizedAuthorityDid" value="${escapeHtml(state.currentRecognitionDraft?.recognizedAuthorityDid ?? state.currentRecognitionQuery?.recognizedAuthorityDid ?? "")}" required /></label>
                <label class="label">Recognized registry ID<input class="input mono" name="recognizedRegistryId" value="${escapeHtml(state.currentRecognitionDraft?.recognizedRegistryId ?? state.currentRecognitionQuery?.recognizedRegistryId ?? "")}" required /></label>
                <label class="label">Scope resource type<input class="input mono" name="scopeResourceType" value="${escapeHtml(state.currentRecognitionDraft?.scopeResourceType ?? state.currentRecognitionQuery?.scopeResourceType ?? "")}" required /></label>
                <label class="label">Scope resource ID<input class="input mono" name="scopeResourceId" value="${escapeHtml(state.currentRecognitionDraft?.scopeResourceId ?? state.currentRecognitionQuery?.scopeResourceId ?? "")}" required /></label>
                <label class="label">Scope context JSON, if any<textarea class="input mono" name="scopeContext" rows="3" spellcheck="false">${escapeHtml(state.currentRecognitionDraft?.scopeContext ?? (state.currentRecognitionQuery?.scopeContext === undefined ? "" : JSON.stringify(state.currentRecognitionQuery.scopeContext, null, 2)))}</textarea></label>
                <button class="button" type="submit" data-focus-key="current-recognition-submit"${state.currentRecognitionBusy ? " disabled" : ""}>Look up current recognition</button>
              </form>
            </div>
            <aside class="lookup-result" aria-label="Current recognition result">
              <h3 class="eyebrow">Result</h3>
              ${state.currentRecognitionError === undefined ? "" : `<div class="alert error" role="alert">${escapeHtml(state.currentRecognitionError)}</div>`}
              ${state.currentRecognitionResult === undefined && state.currentRecognitionError === undefined ? `<div class="lookup-empty"><h3>No record loaded yet</h3><p>Enter the exact authority, registry, and scope to inspect the API's current claim.</p></div>` : ""}
              ${state.currentRecognitionResult === undefined ? "" : `<div class="lookup-claim" data-current-recognition-result role="status">
                <p><strong>Unverified current API claim:</strong> ${escapeHtml(state.currentRecognitionResult.recognition.status)}.</p>
                <details><summary>Inspect returned recognition</summary><button class="button secondary claim-copy" type="button" data-copy-current-claim>Copy current API claim</button><span class="copy-claim-feedback" data-copy-claim-feedback role="status" aria-live="polite"></span><pre class="mono" tabindex="0" aria-label="Scrollable recognition JSON">${escapeHtml(JSON.stringify(state.currentRecognitionResult, null, 2))}</pre></details>
              </div>`}
              <div class="lookup-interpretation"><strong>How to interpret a result</strong><p>A returned status is not independently authenticated finality or local membership. Verify the finalized registry before relying on it.</p></div>
            </aside>
          </section>
          ${journeyPicker}
          ` : state.inspection === undefined ? `<div class="alert error">Registry mode is unavailable; inspection controls are disabled.</div>` : `
          <section class="form-panel">
            <h2>Historical authorization evidence</h2>
            <p>Look up the exact DID, role, governed resource, and timestamp. The API response is a historical claim, not proof of current trust. Verify its bundle against independent finalized registry history before relying on it.</p>
            <form data-historical-authorization>
              <label class="label">Role<select class="select" name="role">
                ${(["issuer", "verifier", "auditor"] as const).map((role) => `<option value="${role}"${(state.historicalDraft?.role ?? state.historicalQuery?.role ?? "issuer") === role ? " selected" : ""}>${role}</option>`).join("")}
              </select></label>
              <label class="label">Subject DID<input class="input mono" name="subjectDid" value="${escapeHtml(state.historicalDraft?.subjectDid ?? state.historicalQuery?.subjectDid ?? "")}" required /></label>
              <label class="label">Governed resource ID<input class="input mono" name="resourceId" value="${escapeHtml(state.historicalDraft?.resourceId ?? state.historicalQuery?.resourceId ?? "")}" required /></label>
              <label class="label">RFC3339 timestamp<input class="input mono" name="at" placeholder="2026-10-15T00:00:00Z" value="${escapeHtml(state.historicalDraft?.at ?? state.historicalQuery?.at ?? "")}" required /></label>
              <button class="button secondary" type="submit" data-focus-key="historical-authorization-submit"${state.historicalBusy ? " disabled" : ""}>Inspect authorization evidence</button>
            </form>
            ${state.historicalError === undefined ? "" : `<div class="alert error" role="alert">${escapeHtml(state.historicalError)}</div>`}
            ${state.historicalResult === undefined ? "" : `<div class="panel" data-historical-result>
              <p><strong>Unverified API claim:</strong> ${escapeHtml(state.historicalResult.statusAtTime ?? "not yet proposed")} at ${escapeHtml(state.historicalResult.evaluatedAt)}; trusted-at-time flag ${state.historicalResult.trustedAtTime ? "true" : "false"}.</p>
              <p>Evidence epoch <span class="mono">${escapeHtml(state.historicalResult.bundle.epoch.epochId)}</span>; policy <span class="mono">${escapeHtml(state.historicalResult.bundle.policy.policyId)}</span>.</p>
              <button class="button secondary" type="button" data-download-historical-authorization>Download unverified evidence JSON</button>
              <details><summary>Inspect raw proof bundle</summary><pre class="mono">${escapeHtml(JSON.stringify(state.historicalResult.bundle, null, 2))}</pre></details>
            </div>`}
          </section>
          <section class="form-panel">
            <h2>Historical recognition evidence</h2>
            <p>Query an external authority's exact recognized scope at a timestamp. An omitted context matches only a recognition without context. This panel exports an unverified API claim; recognition never grants local issuer, verifier, or maintainer membership.</p>
            <form data-historical-recognition>
              <label class="label">Recognized authority DID<input class="input mono" name="recognizedAuthorityDid" value="${escapeHtml(state.historicalRecognitionDraft?.recognizedAuthorityDid ?? state.historicalRecognitionQuery?.recognizedAuthorityDid ?? "")}" required /></label>
              <label class="label">Recognized registry ID<input class="input mono" name="recognizedRegistryId" value="${escapeHtml(state.historicalRecognitionDraft?.recognizedRegistryId ?? state.historicalRecognitionQuery?.recognizedRegistryId ?? "")}" required /></label>
              <label class="label">Scope resource type<input class="input mono" name="scopeResourceType" value="${escapeHtml(state.historicalRecognitionDraft?.scopeResourceType ?? state.historicalRecognitionQuery?.scopeResourceType ?? "")}" required /></label>
              <label class="label">Scope resource ID<input class="input mono" name="scopeResourceId" value="${escapeHtml(state.historicalRecognitionDraft?.scopeResourceId ?? state.historicalRecognitionQuery?.scopeResourceId ?? "")}" required /></label>
              <label class="label">Scope context JSON, if any<textarea class="input mono" name="scopeContext" rows="3" spellcheck="false">${escapeHtml(state.historicalRecognitionDraft?.scopeContext ?? (state.historicalRecognitionQuery?.scopeContext === undefined ? "" : JSON.stringify(state.historicalRecognitionQuery.scopeContext, null, 2)))}</textarea></label>
              <label class="label">RFC3339 timestamp<input class="input mono" name="at" placeholder="2026-10-15T00:00:00Z" value="${escapeHtml(state.historicalRecognitionDraft?.at ?? state.historicalRecognitionQuery?.at ?? "")}" required /></label>
              <button class="button secondary" type="submit" data-focus-key="historical-recognition-submit"${state.historicalRecognitionBusy ? " disabled" : ""}>Inspect recognition evidence</button>
            </form>
            ${state.historicalRecognitionError === undefined ? "" : `<div class="alert error" role="alert">${escapeHtml(state.historicalRecognitionError)}</div>`}
            ${state.historicalRecognitionResult === undefined ? "" : `<div class="panel" data-historical-recognition-result>
              <p><strong>Unverified API claim:</strong> ${escapeHtml(state.historicalRecognitionResult.statusAtTime ?? "not yet proposed")} at ${escapeHtml(state.historicalRecognitionResult.evaluatedAt)}; recognized-at-time flag ${state.historicalRecognitionResult.trustedAtTime ? "true" : "false"}.</p>
              <p>Evidence epoch <span class="mono">${escapeHtml(state.historicalRecognitionResult.bundle.epoch.epochId)}</span>; policy <span class="mono">${escapeHtml(state.historicalRecognitionResult.bundle.policy.policyId)}</span>.</p>
              <button class="button secondary" type="button" data-download-historical-recognition>Download unverified evidence JSON</button>
              <details><summary>Inspect raw recognition proof bundle</summary><pre class="mono">${escapeHtml(JSON.stringify(state.historicalRecognitionResult.bundle, null, 2))}</pre></details>
            </div>`}
          </section>
          <section class="form-panel">
            <h2>Signed issuer or verifier submission</h2>
            <p>Load the current workspace context, sign an issuer or verifier submission outside this browser, then paste only the signed envelope. No private key belongs here. A stale context must be signed again.</p>
            <button class="button secondary" type="button" data-signed-context${state.signedBusy ? " disabled" : ""}>Load signing context</button>
            ${state.signedContext === undefined ? "" : `<pre class="mono signing-context">${escapeHtml(JSON.stringify(state.signedContext, null, 2))}</pre>`}
            <form data-signed-submit>
              <label class="label">Externally signed envelope
                <textarea class="input mono signed-envelope" name="signedEnvelope" spellcheck="false" autocomplete="off" required></textarea>
              </label>
              <button class="button" type="submit"${state.signedBusy || state.signedContext === undefined ? " disabled" : ""}>Submit signed intent</button>
            </form>
          </section>
          `}
          <section class="form-panel">
            <h2>Issuer membership request</h2>
            <p>Bind one exact credential scope, schema/version, definition, status method, and governed resource type before signing with the applicant DID key.</p>
            <form data-issuer-application-form>
              <h3 class="request-step"><span>01</span> Identify the applicant</h3>
              <label class="label">Application ID<input class="input mono" name="applicationId" value="${escapeHtml(issuerDraft?.applicationId ?? "")}"${issuerLocked} required /></label>
              <label class="label">Authorization ID<input class="input mono" name="authorizationId" value="${escapeHtml(issuerDraft?.authorizationId ?? "")}"${issuerLocked} required /></label>
              <label class="label">Applicant Midnight DID<input class="input mono" name="actorDid" value="${escapeHtml(issuerDraft?.actorDid ?? "")}"${issuerLocked} required /></label>
              <label class="label">Authentication method ID<input class="input mono" name="actorKeyId" value="${escapeHtml(issuerDraft?.actorKeyId ?? "")}"${issuerLocked} required /></label>
              <h3 class="request-step"><span>02</span> Define the exact credential scope</h3>
              <label class="label">Credential scope ID<input class="input mono" name="credentialFamilyId" value="${escapeHtml(issuerDraft?.credentialFamilyId ?? "")}"${issuerLocked} required /></label>
              <label class="label">Schema ID<input class="input mono" name="schemaId" value="${escapeHtml(issuerDraft?.schemaId ?? "")}"${issuerLocked} required /></label>
              <label class="label">Schema version<input class="input mono" name="schemaVersion" value="${escapeHtml(issuerDraft?.schemaVersion ?? "")}" pattern="[0-9]+[.][0-9]+[.][0-9]+"${issuerLocked} required /></label>
              <label class="label">Credential definition ID<input class="input mono" name="credentialDefinitionId" value="${escapeHtml(issuerDraft?.credentialDefinitionId ?? "")}"${issuerLocked} required /></label>
              <label class="label">Status method<input class="input mono" name="statusMethod" value="${escapeHtml(issuerDraft?.statusMethod ?? "")}"${issuerLocked} required /></label>
              <label class="label">Governed resource type<select class="select" name="governedResourceType"${issuerLocked}>
                ${(["credentialFamily", "schema", "schemaVersion", "credentialDefinition", "statusMethodRequirement"] as const).map((type) => `<option value="${type}"${(issuerDraft?.governedResourceType ?? "credentialFamily") === type ? " selected" : ""}>${({ credentialFamily: "Credential scope", schema: "Schema", schemaVersion: "Schema version", credentialDefinition: "Credential definition", statusMethodRequirement: "Status method requirement" })[type]}</option>`).join("")}
              </select></label>
              <h3 class="request-step"><span>03</span> Prepare, sign externally, and register</h3>
              <p class="step-hint">Preparation fixes the exact scope and digest. A changed request needs a fresh digest and signature.</p>
              <button class="button secondary" type="button" data-prepare-issuer${!privateHost || state.evidenceBusy || state.memberPreparationBusy || preparedIssuer !== undefined ? " disabled" : ""}>Prepare signing digest</button>
              ${preparedIssuer === undefined ? "" : `
                <p data-issuer-resource class="mono">Governed resource: ${escapeHtml(preparedIssuer.payload.governedResource.id)}</p>
                <p data-issuer-digest class="mono">Sign digest bytes: ${escapeHtml(preparedIssuer.digest)}</p>
                <pre class="mono signing-context">${escapeHtml(JSON.stringify({ ...preparedIssuer.payload, intent: preparedIssuer.intent }, null, 2))}</pre>
                <label class="label">External JubJub signature (96-byte hex)<input class="input mono" name="memberSignature" pattern="0x[0-9a-f]{192}" autocomplete="off" required /></label>
                <button class="button secondary" type="button" data-reset-member>Change request or refresh context</button>
              `}
              <button class="button" type="submit"${!privateHost || state.evidenceBusy || state.memberPreparationBusy || preparedIssuer === undefined ? " disabled" : ""}>Register issuer application</button>
              <p class="step-hint">After registration, continue to <a href="#pending-evidence" data-open-workflow="pending-evidence">one-use private evidence</a>. Registration alone is not approval.</p>
            </form>
          </section>
          <section class="form-panel">
            <h2>Verifier membership request</h2>
            <p>Bind the full presentation-request purpose, credential scope, allowed claims and predicates, and disclosure level before signing.</p>
            <form data-verifier-application-form>
              <h3 class="request-step"><span>01</span> Identify the applicant</h3>
              <label class="label">Application ID<input class="input mono" name="applicationId" value="${escapeHtml(verifierDraft?.applicationId ?? "")}"${verifierLocked} required /></label>
              <label class="label">Authorization ID<input class="input mono" name="authorizationId" value="${escapeHtml(verifierDraft?.authorizationId ?? "")}"${verifierLocked} required /></label>
              <label class="label">Applicant Midnight DID<input class="input mono" name="actorDid" value="${escapeHtml(verifierDraft?.actorDid ?? "")}"${verifierLocked} required /></label>
              <label class="label">Authentication method ID<input class="input mono" name="actorKeyId" value="${escapeHtml(verifierDraft?.actorKeyId ?? "")}"${verifierLocked} required /></label>
              <h3 class="request-step"><span>02</span> Define the exact request scope</h3>
              <label class="label">Request profile ID<input class="input mono" name="requestProfileId" value="${escapeHtml(verifierDraft?.requestProfileId ?? "")}"${verifierLocked} required /></label>
              <label class="label">Purpose<input class="input" name="purpose" value="${escapeHtml(verifierDraft?.purpose ?? "")}"${verifierLocked} required /></label>
              <label class="label">Credential-scope commitment<input class="input mono" name="credentialScopeCommitment" value="${escapeHtml(verifierDraft?.credentialScopeCommitment ?? "")}" pattern="0x[0-9a-f]{64}"${verifierLocked} required /></label>
              <label class="label">Allowed attributes, one per line<textarea class="input mono" name="allowedAttributes" rows="3"${verifierLocked}>${escapeHtml(verifierDraft?.allowedAttributes.join("\n") ?? "")}</textarea></label>
              <label class="label">Allowed predicates, one per line<textarea class="input mono" name="allowedPredicates" rows="3"${verifierLocked}>${escapeHtml(verifierDraft?.allowedPredicates.join("\n") ?? "")}</textarea></label>
              <label class="label">Disclosure level<input class="input" name="disclosureLevel" value="${escapeHtml(verifierDraft?.disclosureLevel ?? "")}"${verifierLocked} required /></label>
              <h3 class="request-step"><span>03</span> Prepare, sign externally, and register</h3>
              <p class="step-hint">Preparation fixes the exact scope and digest. A changed request needs a fresh digest and signature.</p>
              <button class="button secondary" type="button" data-prepare-verifier${!privateHost || state.evidenceBusy || state.memberPreparationBusy || preparedVerifier !== undefined ? " disabled" : ""}>Prepare signing digest</button>
              ${preparedVerifier === undefined ? "" : `
                <p data-verifier-resource class="mono">Governed resource: ${escapeHtml(preparedVerifier.payload.governedResource.id)}</p>
                <p data-verifier-digest class="mono">Sign digest bytes: ${escapeHtml(preparedVerifier.digest)}</p>
                <pre class="mono signing-context">${escapeHtml(JSON.stringify({ ...preparedVerifier.payload, intent: preparedVerifier.intent }, null, 2))}</pre>
                <label class="label">External JubJub signature (96-byte hex)<input class="input mono" name="memberSignature" pattern="0x[0-9a-f]{192}" autocomplete="off" required /></label>
                <button class="button secondary" type="button" data-reset-member>Change request or refresh context</button>
              `}
              <button class="button" type="submit"${!privateHost || state.evidenceBusy || state.memberPreparationBusy || preparedVerifier === undefined ? " disabled" : ""}>Register verifier application</button>
              <p class="step-hint">After registration, continue to <a href="#pending-evidence" data-open-workflow="pending-evidence">one-use private evidence</a>. Registration alone is not approval.</p>
            </form>
          </section>
          <section class="form-panel">
            <h2>Maintainer membership request</h2>
            <p>The current API registry defines the exact maintainer scope. Sign the prepared digest with the applicant DID authentication key; approval by existing maintainers is still required.</p>
            <form data-maintainer-application-form>
              <h3 class="request-step"><span>01</span> Identify the applicant and exact membership</h3>
              <label class="label">Application ID<input class="input mono" name="applicationId" value="${escapeHtml(maintainerDraft?.applicationId ?? "")}"${maintainerLocked} required /></label>
              <label class="label">Authorization ID<input class="input mono" name="authorizationId" value="${escapeHtml(maintainerDraft?.authorizationId ?? "")}"${maintainerLocked} required /></label>
              <label class="label">Applicant Midnight DID<input class="input mono" name="actorDid" value="${escapeHtml(maintainerDraft?.actorDid ?? "")}"${maintainerLocked} required /></label>
              <label class="label">Authentication method ID<input class="input mono" name="actorKeyId" value="${escapeHtml(maintainerDraft?.actorKeyId ?? "")}"${maintainerLocked} required /></label>
              <h3 class="request-step"><span>02</span> Prepare, sign externally, and register</h3>
              <p class="step-hint">The server supplies the governed registry scope. A changed context needs a fresh digest and signature.</p>
              <button class="button secondary" type="button" data-prepare-maintainer${!privateHost || state.evidenceBusy || state.memberPreparationBusy || preparedMaintainer !== undefined ? " disabled" : ""}>Prepare signing digest</button>
              ${preparedMaintainer === undefined ? "" : `
                <p data-maintainer-resource class="mono">Governed registry: ${escapeHtml(preparedMaintainer.payload.governedResource.id)}</p>
                <p data-maintainer-digest class="mono">Sign digest bytes: ${escapeHtml(preparedMaintainer.digest)}</p>
                <pre class="mono signing-context">${escapeHtml(JSON.stringify({ ...preparedMaintainer.payload, intent: preparedMaintainer.intent }, null, 2))}</pre>
                <label class="label">External JubJub signature (96-byte hex)<input class="input mono" name="memberSignature" pattern="0x[0-9a-f]{192}" autocomplete="off" required /></label>
                <button class="button secondary" type="button" data-reset-member>Change request or refresh context</button>
              `}
              <button class="button" type="submit"${!privateHost || state.evidenceBusy || state.memberPreparationBusy || preparedMaintainer === undefined ? " disabled" : ""}>Register maintainer application</button>
              <p class="step-hint">After registration, continue to <a href="#pending-evidence" data-open-workflow="pending-evidence">one-use private evidence</a>. Existing maintainers still decide membership.</p>
            </form>
          </section>
          <section class="form-panel">
            <h2>Auditor request</h2>
            <p>Describe the complete audit scope and applicant DID. Prepare its canonical resource and signing digest, sign that digest outside this browser, then submit only the signature. A request-profile ID alone is not an auditor scope.</p>
            <form data-auditor-application-form>
              <h3 class="request-step"><span>01</span> Identify the applicant</h3>
              <label class="label">Application ID<input class="input mono" name="applicationId" value="${escapeHtml(auditorDraft?.applicationId ?? "")}"${auditorLocked} /></label>
              <label class="label">Authorization ID<input class="input mono" name="authorizationId" value="${escapeHtml(auditorDraft?.authorizationId ?? "")}"${auditorLocked} /></label>
              <label class="label">Applicant Midnight DID<input class="input mono" name="actorDid" value="${escapeHtml(auditorDraft?.actorDid ?? "")}"${auditorLocked} /></label>
              <label class="label">Authentication method ID<input class="input mono" name="actorKeyId" value="${escapeHtml(auditorDraft?.actorKeyId ?? "")}"${auditorLocked} /></label>
              <h3 class="request-step"><span>02</span> Define the complete audit scope</h3>
              <label class="label">Request profile ID<input class="input mono" name="requestProfileId" value="${escapeHtml(auditorDraft?.requestProfileId ?? "")}"${auditorLocked} required /></label>
              <label class="label">Purpose<input class="input" name="purpose" value="${escapeHtml(auditorDraft?.purpose ?? "")}"${auditorLocked} required /></label>
              <label class="label">Credential-scope commitment<input class="input mono" name="credentialScopeCommitment" value="${escapeHtml(auditorDraft?.credentialScopeCommitment ?? "")}" pattern="0x[0-9a-f]{64}"${auditorLocked} required /></label>
              <label class="label">Allowed attributes, one per line<textarea class="input mono" name="allowedAttributes" rows="3"${auditorLocked}>${escapeHtml(auditorDraft?.allowedAttributes.join("\n") ?? "")}</textarea></label>
              <label class="label">Allowed predicates, one per line<textarea class="input mono" name="allowedPredicates" rows="3"${auditorLocked}>${escapeHtml(auditorDraft?.allowedPredicates.join("\n") ?? "")}</textarea></label>
              <label class="label">Disclosure level<input class="input" name="disclosureLevel" value="${escapeHtml(auditorDraft?.disclosureLevel ?? "")}"${auditorLocked} required /></label>
              <h3 class="request-step"><span>03</span> Prepare, sign externally, and register</h3>
              <p class="step-hint">Preparation fixes the complete scope. A changed request needs a fresh digest and signature.</p>
              <button class="button secondary" type="button" data-prepare-auditor${!privateHost || state.evidenceBusy || state.auditorPreparationBusy || preparedAuditor !== undefined ? " disabled" : ""}>${state.auditorPreparationBusy ? "Preparing…" : "Prepare signing digest"}</button>
              ${preparedAuditor === undefined ? "" : `
                <p data-auditor-resource class="mono">Governed resource: ${escapeHtml(preparedAuditor.payload.governedResource.id)}</p>
                <p data-auditor-digest class="mono">Sign digest bytes: ${escapeHtml(preparedAuditor.digest)}</p>
                <pre data-auditor-signing-context class="mono signing-context">${escapeHtml(JSON.stringify({ ...preparedAuditor.payload, intent: preparedAuditor.intent }, null, 2))}</pre>
                <label class="label">External JubJub signature (96-byte hex)<input class="input mono" name="auditorSignature" pattern="0x[0-9a-f]{192}" autocomplete="off" required /></label>
                <button class="button secondary" type="button" data-reset-auditor>Change request or refresh context</button>
              `}
              ${preparedAuditor === undefined
                ? `<label class="label">Advanced: externally DID-signed auditor application JSON<textarea class="input mono" name="auditorSignedApplication" rows="7" required></textarea></label>`
                : `<textarea name="auditorSignedApplication" hidden></textarea>`}
              <button class="button" type="submit"${!privateHost || state.evidenceBusy || state.auditorPreparationBusy ? " disabled" : ""}>Register auditor application</button>
              <p class="step-hint">After registration, continue to <a href="#pending-evidence" data-open-workflow="pending-evidence">one-use private evidence</a>. An audit request is not an active authorization.</p>
            </form>
            <form data-auditor-status-form>
              <label class="label">Auditor authorization ID
                <input class="input mono" name="auditorAuthorizationId" value="${escapeHtml(state.auditorStatus?.authorizationId ?? "")}" required />
              </label>
              <button class="button secondary" type="submit"${state.auditorStatusBusy ? " disabled" : ""}>Check auditor status</button>
            </form>
            ${state.auditorStatus === undefined ? "" : `<p data-auditor-status>Application: ${escapeHtml(state.auditorStatus.status)}. Current trust: ${state.auditorStatus.currentTrust ? "active" : "not active"}.</p>`}
          </section>
          <section class="form-panel" id="pending-evidence">
            <h2>Pending membership evidence</h2>
            <p>Paste an externally DID-signed issuer, verifier, auditor, or maintainer application to register it, or load an existing pending ID. The server derives policy and resource from trusted state. Registration does not create or approve a ledger grant.</p>
            ${state.evidenceError === undefined ? "" : `<div class="alert error" role="alert">${escapeHtml(state.evidenceError)}</div>`}
            ${state.evidenceFlash === undefined ? "" : `<div class="alert success" role="status">${escapeHtml(state.evidenceFlash)}</div>`}
            ${privateHost ? "" : `<p class="alert error">Private evidence is disabled: serve the portal and authenticated API from the same HTTPS or localhost origin.</p>`}
            <form data-application-registration-form>
              <label class="label">DID-signed application JSON
                <textarea class="input mono" name="signedApplication" rows="6" required></textarea>
              </label>
              <button class="button secondary" type="submit"${!privateHost || state.evidenceBusy ? " disabled" : ""}>Register pending application</button>
            </form>
            <form data-application-binding-form>
              <label class="label">Pending application ID
                <input class="input mono" name="applicationId" type="text" maxlength="256" required />
              </label>
              <button class="button secondary" type="submit"${!privateHost || state.evidenceBusy ? " disabled" : ""}>Load application request</button>
              <button class="button secondary" type="button" data-application-receipt${!privateHost || state.evidenceBusy ? " disabled" : ""}>Recover accepted evidence</button>
            </form>
            ${state.acceptedEvidence === undefined ? "" : `
              <div class="panel" data-accepted-evidence>
                <p>Accepted receipt: <span class="mono">${escapeHtml(state.acceptedEvidence.receipt.receiptId)}</span></p>
                <p>Only the redacted signed evidence below is shared with the governance operator. The VC/VP stays private.</p>
                <pre class="mono">${escapeHtml(JSON.stringify(state.acceptedEvidence.evidence, null, 2))}</pre>
              </div>
            `}
            ${pending === undefined ? "" : `
              <div class="panel">
                <p>Applicant DID: <span class="mono">${escapeHtml(pending.binding.subjectDid)}</span></p>
                <p>Requested role: ${escapeHtml(pending.binding.role)}</p>
                <p>Policy: ${escapeHtml(pending.binding.policyId)} · ${escapeHtml(pending.binding.policyVersion)}</p>
                <p>Governed resource: ${escapeHtml(pending.binding.governedResource.type)}:${escapeHtml(pending.binding.governedResource.id)}</p>
                <p>Scope commitment: <span class="mono">${escapeHtml(pending.binding.scopeCommitment)}</span></p>
                <pre class="mono">${escapeHtml(JSON.stringify(pending.binding.scope, null, 2))}</pre>
                <button class="button secondary" type="button" data-application-challenge${state.evidenceBusy ? " disabled" : ""}>Issue one-use VP challenge</button>
              </div>
              ${pending.challenge === undefined ? "" : `
                <div class="panel">
                  <p>Challenge expires: ${escapeHtml(pending.challenge.expiresAt)}</p>
                  <p>Nonce: <span class="mono">${escapeHtml(pending.challenge.nonce)}</span></p>
                  <p>Challenge hash: <span class="mono">${escapeHtml(pending.challenge.challengeHash)}</span></p>
                  <form data-application-vp-form data-challenge-hash="${escapeHtml(pending.challenge.challengeHash)}">
                    <label class="label">Presentation JSON
                      <textarea class="input mono" name="presentation" rows="6" required></textarea>
                    </label>
                    <button class="button" type="submit"${state.evidenceBusy ? " disabled" : ""}>Submit VP evidence</button>
                  </form>
                </div>
              `}
            `}
          </section>
          <section class="form-panel">
            <h2>Recover external recognition</h2>
            <p>Accredited authorities can request a one-use challenge, sign the authority assertion outside this browser, submit the signed assertion with the accreditation VP, recover the accepted receipt, and check the finalized Compact proposal. Only an authenticated same-origin session can access these private steps. A missing observation never triggers a retry.</p>
            ${state.recognitionRecoveryMessage === undefined ? "" : `<p class="alert" role="status" data-recognition-recovery-result>${escapeHtml(state.recognitionRecoveryMessage)}</p>`}
            <form data-recognition-recovery-form autocomplete="off">
              <label class="label">Recognition ID <input class="input mono" name="recognitionId" value="${escapeHtml(state.recognitionId)}" required autocomplete="off" /></label>
              <button class="button secondary" type="button" data-recognition-challenge${!privateHost || state.recognitionRecoveryBusy ? " disabled" : ""}>Issue authority challenge</button>
              <button class="button secondary" type="button" data-recognition-accepted${!privateHost || state.recognitionRecoveryBusy ? " disabled" : ""}>Recover accepted accreditation</button>
              <label class="label">Admission receipt ID <input class="input mono" name="receiptId" value="${escapeHtml(state.recognitionAdmission?.receiptId ?? "")}" required autocomplete="off" spellcheck="false" /></label>
              <label class="label">Evidence commitment <input class="input mono" name="evidenceCommitment" value="${escapeHtml(state.recognitionAdmission?.evidenceCommitment ?? "")}" required autocomplete="off" spellcheck="false" /></label>
              <button class="button secondary" type="submit"${!privateHost || state.recognitionRecoveryBusy ? " disabled" : ""}>Check finalized proposal</button>
            </form>
            ${state.recognitionChallenge === undefined ? "" : `
              <div class="panel" data-recognition-challenge-context>
                <p>Challenge expires: ${escapeHtml(state.recognitionChallenge.expiresAt)}</p>
                <p>Nonce: <span class="mono">${escapeHtml(state.recognitionChallenge.nonce)}</span></p>
                <p>Challenge hash: <span class="mono">${escapeHtml(state.recognitionChallenge.challengeHash)}</span></p>
                <form data-recognition-accreditation-form autocomplete="off">
                  <label class="label">Externally signed assertion and accreditation VP JSON
                    <textarea class="input mono" name="signedAccreditation" rows="6" required spellcheck="false"></textarea>
                  </label>
                  <button class="button" type="submit"${state.recognitionRecoveryBusy ? " disabled" : ""}>Submit accredited authority evidence</button>
                </form>
              </div>
            `}
            ${state.recognitionAdmission === undefined ? "" : `
              <p data-recognition-admission>Accepted receipt: <span class="mono">${escapeHtml(state.recognitionAdmission.receiptId)}</span>. Evidence commitment: <span class="mono">${escapeHtml(state.recognitionAdmission.evidenceCommitment)}</span>.</p>
            `}
          </section>
          ${state.inspection === undefined || state.inspection.sourceMode === "local-ledger" ? "" : `<section class="records-overview" id="trust-records" aria-labelledby="records-heading">
            <div class="records-heading"><div><p class="eyebrow">Explore the registry</p><h2 id="records-heading">Find an active record</h2><p>Search this fixture snapshot by name, role, scope, or DID. It is not a trust decision.</p></div>
              <label class="record-search">Search active records<input class="input" type="search" data-record-search value="${escapeHtml(recordSearchQuery)}" autocomplete="off" placeholder="Name, role, scope, or DID" /></label>
            </div>
            <p class="record-count" data-record-count aria-live="polite"></p>
            <div class="lanes">
              ${issuerCards.length || state.inspection.unavailableLists?.includes("issuer") ? renderInspectionLane("Active issuers", issuerCards, state.inspection.unavailableLists?.includes("issuer") === true) : ""}
              ${verifierCards.length || state.inspection.unavailableLists?.includes("verifier") ? renderInspectionLane("Active verifiers", verifierCards, state.inspection.unavailableLists?.includes("verifier") === true) : ""}
              ${auditorCards.length || state.inspection.unavailableLists?.includes("auditor") ? renderInspectionLane("Active auditors", auditorCards, state.inspection.unavailableLists?.includes("auditor") === true) : ""}
              ${recognitionCards.length || state.inspection.unavailableLists?.includes("recognition") ? renderInspectionLane("Active recognitions", recognitionCards, state.inspection.unavailableLists?.includes("recognition") === true) : ""}
            </div>
            <p class="records-empty" data-record-no-match hidden>No loaded records match this search.${state.inspection.unavailableLists?.length ? " Unavailable categories were not searched." : " Try a different name, role, scope, or DID."}</p>
            ${cards.length === 0 && !state.inspection.unavailableLists?.length ? `<p class="records-empty">No active records in this fixture yet.</p>` : ""}
          </section>`}
        </section>
      </main>
    `;
    root.querySelectorAll<HTMLElement>(".content > .form-panel").forEach((panel) => {
      if (panel.id === "demo-application") return;
      const heading = panel.querySelector("h2");
      if (heading === null) return;
      const name = heading.textContent ?? "Workflow";
      if (panel.classList.contains("current-lookup-panel")) return;
      const details = document.createElement("details");
      details.className = "workflow-disclosure";
      details.dataset.workflow = name;
      const role = (["issuer", "verifier", "auditor", "maintainer"] as const)
        .find((candidate) => panel.querySelector(`[data-${candidate}-application-form]`) !== null);
      details.open = openWorkflows.has(name) || name === "Pending membership evidence"
        && (pending !== undefined || state.acceptedEvidence !== undefined);
      if (role !== undefined) {
        details.classList.add("role-workflow");
        details.id = `${role}-request`;
        panel.removeAttribute("id");
      } else if (panel.id !== "") {
        details.id = panel.id;
        panel.removeAttribute("id");
      }
      const summary = document.createElement("summary");
      summary.textContent = name;
      if (role !== undefined) summary.dataset.focusKey = `${role}-request-summary`;
      panel.before(details);
      details.append(summary, panel);
    });
    const content = root.querySelector<HTMLElement>(".content");
    const advanced = [...root.querySelectorAll<HTMLDetailsElement>(".workflow-disclosure:not(.role-workflow)")]
      .filter((details) => !details.id.startsWith("current-"));
    if (content !== null && advanced.length > 0) {
      const group = document.createElement("details");
      group.className = "advanced-tools";
      group.open = advancedOpen || advanced.some((details) => details.open);
      const summary = document.createElement("summary");
      summary.textContent = "Advanced evidence and recovery";
      group.append(summary, ...advanced);
      content.append(group);
    }
    if (previousVp !== undefined && previousChallengeHash === state.pendingApplication?.challenge?.challengeHash) {
      const currentVp = root.querySelector<HTMLTextAreaElement>("[data-application-vp-form] [name='presentation']");
      if (currentVp !== null) currentVp.value = previousVp;
    }
    if (previousSignedEnvelope !== undefined) {
      const currentEnvelope = root.querySelector<HTMLTextAreaElement>("[data-signed-submit] [name='signedEnvelope']");
      if (currentEnvelope !== null) currentEnvelope.value = previousSignedEnvelope;
    }
    if (pendingFocusKey !== null) {
      const target = root.querySelector<HTMLElement>(`[data-focus-key="${pendingFocusKey}"]`);
      if (target !== null && !(target instanceof HTMLButtonElement && target.disabled)) {
        target.focus();
        pendingFocusKey = null;
      }
    }
    filterRecordCards();
    bindEvents();
  };

  render();
  window.addEventListener("hashchange", () => {
    const shell = root.querySelector<HTMLElement>(".app-shell");
    if (shell !== null) shell.dataset.settingsActive = String(window.location.hash === "#connection-details");
    const next = window.location.hash === "#current-recognition-lookup" ? "recognition"
      : window.location.hash === "#current-authorization-lookup" ? "authorization" : undefined;
    if (next === undefined || next === lookupActive) return;
    lookupActive = next;
    for (const target of ["authorization", "recognition"] as const) {
      const section = root.querySelector<HTMLElement>(`#current-${target}-lookup`);
      if (section !== null) section.hidden = target !== lookupActive;
      const link = root.querySelector<HTMLAnchorElement>(`.lookup-switch a[href="#current-${target}-lookup"]`);
      if (target === lookupActive) link?.setAttribute("aria-current", "location");
      else link?.removeAttribute("aria-current");
    }
    root.querySelector<HTMLElement>(".lookup-picker")?.scrollIntoView({ block: "start" });
  });
  void refreshInspection();
};
