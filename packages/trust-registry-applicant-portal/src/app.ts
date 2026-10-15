import { TrustRegistryApplicantPortalApiError, TrustRegistryApplicantPortalClient, isCurrentlyActive, normalizeApiBaseUrl } from "./api.js";
import { TARGET_OPTIONS, describeSubmission, toInspectionCards, type PortalSubmissionTarget, type PublicInspection } from "./model.js";
import type { ApplicationChallengeBinding, ApplicationVpHttpIssueResult, ApplicationVpHttpSubmissionResult, RecognitionAdmissionReceipt, TrustRegistryApiMutationContext, TrustRegistryApiSignedMutationRequest } from "@midnight-ntwrk/trust-registry-api";

const STORAGE_KEY = "trust-registry.portal.api-base";

type AppState = {
  apiBase: string;
  error: string | undefined;
  flash: string | undefined;
  inspection: PublicInspection | undefined;
  loading: boolean;
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
  } = {},
): void => {
  const initialUrl = options.initialUrl ?? new URL(window.location.href);
  const storage = options.storage ?? window.localStorage;
  const fetchImpl = options.fetchImpl ?? window.fetch.bind(window);
  // An explicit query parameter is a one-off override for local testing and
  // should not silently replace the persisted default.
  const queryBase = initialUrl.searchParams.get("apiBase");

  const state: AppState = {
    apiBase: normalizeApiBaseUrl(queryBase ?? storage.getItem(STORAGE_KEY) ?? "http://127.0.0.1:4400"),
    error: undefined,
    flash: undefined,
    inspection: undefined,
    loading: false,
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
    recognitionRecoveryBusy: false,
    recognitionRecoveryMessage: undefined,
    recognitionId: "",
    recognitionChallenge: undefined,
    recognitionAdmission: undefined,
  };
  let evidenceRequestId = 0;
  let signedContextRequestId = 0;
  let auditorStatusRequestId = 0;
  let recognitionRequestId = 0;

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

  const registerApplication = async (rawRequest: string, expectedAuditorScope?: AuditorScopeInput) => {
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
        intent?: { target?: unknown };
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
      setState({
        pendingApplication: { binding },
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
    setState({ loading: true, error: undefined, ...(flash === undefined ? {} : { flash }) });
    try {
      const inspection = await client().loadPublicInspection();
      setState({
        error: undefined,
        inspection,
        loading: false,
      });
    } catch (error) {
      setState({
        error: formatApiError(error),
        flash: undefined,
        inspection: undefined,
        loading: false,
      });
    }
  };

  const submitApplication = async (
    target: PortalSubmissionTarget,
    label: string,
  ) => {
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
    root.querySelector<HTMLFormElement>("[data-api-base-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
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
      recognitionRequestId += 1;
      setState({ apiBase, signedBusy: false, signedContext: undefined, pendingApplication: undefined, auditorStatus: undefined, auditorStatusBusy: false, evidenceBusy: false, evidenceError: undefined, evidenceFlash: undefined,
        recognitionId: "", recognitionChallenge: undefined, recognitionAdmission: undefined,
        recognitionRecoveryBusy: false, recognitionRecoveryMessage: undefined });
      void refreshInspection();
    });

    root.querySelector<HTMLButtonElement>("[data-refresh]")?.addEventListener("click", () => {
      void refreshInspection();
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
      const targetInput = form.querySelector<HTMLSelectElement>("[name='target']");
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

    root.querySelector<HTMLFormElement>("[data-auditor-application-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const field = (name: string) => form.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[name='${name}']`)?.value.trim() ?? "";
      const raw = field("auditorSignedApplication");
      form.querySelector<HTMLTextAreaElement>("[name='auditorSignedApplication']")!.value = "";
      try {
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
  };

  const renderInspectionLane = (
    title: string,
    cards: readonly ReturnType<typeof toInspectionCards>[number][],
  ): string => `
    <section class="lane">
      <div class="lane-header">
        <h2>${escapeHtml(title)}</h2>
        <span>${cards.length.toString()} active</span>
      </div>
      ${cards.length === 0
        ? `<div class="empty-state"><p>No active entries in this lane yet.</p></div>`
        : cards.map((card) => `
          <article class="card">
            <h3>${escapeHtml(card.label)}</h3>
            <p>${escapeHtml(card.scope)} · ${escapeHtml(card.trustLevel)}</p>
            <p class="mono">${escapeHtml(card.subject)}</p>
          </article>
        `).join("")}
    </section>
  `;

  const render = () => {
    const previousSignedEnvelope = root.querySelector<HTMLTextAreaElement>("[data-signed-submit] [name='signedEnvelope']")?.value;
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

    root.innerHTML = `
      <main class="shell">
        <section class="hero">
          <p class="eyebrow">Public Trust Entry</p>
          <h1>Trust Registry Applicant Portal</h1>
          <p>Inspect active trust records and submit local demo applications. Pending membership applicants can present challenge-bound evidence through an authenticated same-origin host.</p>
          <div class="toolbar">
            <form class="panel" data-api-base-form>
              <label class="label">
                API base URL
                <input class="input mono" type="url" name="apiBase" value="${escapeHtml(state.apiBase)}" />
              </label>
              <div class="row">
                <button class="button" type="submit"${state.loading ? " disabled" : ""}>Connect</button>
                <button class="button secondary" type="button" data-refresh${state.loading ? " disabled" : ""}>Refresh</button>
              </div>
            </form>
            <div class="panel metrics">
              <div class="metric"><span>Registry</span><strong>${escapeHtml(state.inspection?.summary.registryLabel ?? "Unavailable")}</strong></div>
              <div class="metric"><span>Current epoch</span><strong class="mono">${escapeHtml(state.inspection?.summary.currentEpochId ?? "n/a")}</strong></div>
              <div class="metric"><span>Active issuers</span><strong>${(state.inspection?.activeIssuers.length ?? 0).toString()}</strong></div>
              <div class="metric"><span>Active verifiers</span><strong>${(state.inspection?.activeVerifiers.length ?? 0).toString()}</strong></div>
              <div class="metric"><span>Active auditors</span><strong>${state.inspection?.warnings?.length ? "n/a" : (state.inspection?.activeAuditors.length ?? 0).toString()}</strong></div>
              <div class="metric"><span>Recognitions</span><strong>${(state.inspection?.activeRecognitions.length ?? 0).toString()}</strong></div>
            </div>
          </div>
          ${state.error === undefined ? "" : `<div class="alert error">${escapeHtml(state.error)}</div>`}
          ${state.inspection?.warnings?.map((warning) => `<div class="alert error">${escapeHtml(warning)}</div>`).join("") ?? ""}
          ${state.flash === undefined ? "" : `<div class="alert success">${escapeHtml(state.flash)}</div>`}
        </section>
        <section class="content">
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
          <form class="form-panel" data-submit-form>
            <h2>Local demo application</h2>
            <p>This label-only route is for local fixtures, not governed production admission. Approval and activation remain in the admin console.</p>
            <label class="label">
              Role
              <select class="select" name="target">
                ${TARGET_OPTIONS.map((option) => `<option value="${escapeHtml(option.value)}">${escapeHtml(option.label)} · ${escapeHtml(option.description)}</option>`).join("")}
              </select>
            </label>
            <label class="label">
              Application label
              <input class="input" name="label" type="text" placeholder="degree, age-gate, gaia-x" required />
            </label>
            <button class="button" type="submit"${state.submitting ? " disabled" : ""}>Submit application</button>
          </form>
          <section class="form-panel">
            <h2>Auditor request</h2>
            <p>Describe the exact request scope, sign the matching application outside the browser with the applicant Midnight DID, then submit it through the private evidence host. A request-profile ID alone is not an auditor scope.</p>
            <form data-auditor-application-form>
              <label class="label">Request profile ID<input class="input mono" name="requestProfileId" required /></label>
              <label class="label">Purpose<input class="input" name="purpose" required /></label>
              <label class="label">Credential-scope commitment<input class="input mono" name="credentialScopeCommitment" pattern="0x[0-9a-f]{64}" required /></label>
              <label class="label">Allowed attributes, one per line<textarea class="input mono" name="allowedAttributes" rows="3"></textarea></label>
              <label class="label">Allowed predicates, one per line<textarea class="input mono" name="allowedPredicates" rows="3"></textarea></label>
              <label class="label">Disclosure level<input class="input" name="disclosureLevel" required /></label>
              <label class="label">Externally DID-signed auditor application JSON<textarea class="input mono" name="auditorSignedApplication" rows="7" required></textarea></label>
              <button class="button" type="submit"${!privateHost || state.evidenceBusy ? " disabled" : ""}>Register auditor application</button>
            </form>
            <form data-auditor-status-form>
              <label class="label">Auditor authorization ID
                <input class="input mono" name="auditorAuthorizationId" value="${escapeHtml(state.auditorStatus?.authorizationId ?? "")}" required />
              </label>
              <button class="button secondary" type="submit"${state.auditorStatusBusy ? " disabled" : ""}>Check auditor status</button>
            </form>
            ${state.auditorStatus === undefined ? "" : `<p data-auditor-status>Application: ${escapeHtml(state.auditorStatus.status)}. Current trust: ${state.auditorStatus.currentTrust ? "active" : "not active"}.</p>`}
          </section>
          <section class="form-panel">
            <h2>Pending membership evidence</h2>
            <p>Paste an externally DID-signed issuer, verifier, auditor, or maintainer application to register it, or load an existing pending ID. The server derives policy and resource from trusted state. Registration does not create or approve a ledger grant.</p>
            ${state.evidenceError === undefined ? "" : `<div class="alert error">${escapeHtml(state.evidenceError)}</div>`}
            ${state.evidenceFlash === undefined ? "" : `<div class="alert success">${escapeHtml(state.evidenceFlash)}</div>`}
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
            ${state.recognitionRecoveryMessage === undefined ? "" : `<p class="alert" data-recognition-recovery-result>${escapeHtml(state.recognitionRecoveryMessage)}</p>`}
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
          <div class="lanes">
            ${renderInspectionLane("Active issuers", issuerCards)}
            ${renderInspectionLane("Active verifiers", verifierCards)}
            ${renderInspectionLane("Active auditors", auditorCards)}
            ${renderInspectionLane("Active recognitions", recognitionCards)}
          </div>
        </section>
      </main>
    `;
    if (previousVp !== undefined && previousChallengeHash === state.pendingApplication?.challenge?.challengeHash) {
      const currentVp = root.querySelector<HTMLTextAreaElement>("[data-application-vp-form] [name='presentation']");
      if (currentVp !== null) currentVp.value = previousVp;
    }
    if (previousSignedEnvelope !== undefined) {
      const currentEnvelope = root.querySelector<HTMLTextAreaElement>("[data-signed-submit] [name='signedEnvelope']");
      if (currentEnvelope !== null) currentEnvelope.value = previousSignedEnvelope;
    }
    bindEvents();
  };

  render();
  void refreshInspection();
};
