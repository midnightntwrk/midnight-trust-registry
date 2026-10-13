import { TrustRegistryApplicantPortalApiError, TrustRegistryApplicantPortalClient, normalizeApiBaseUrl } from "./api.js";
import { TARGET_OPTIONS, describeSubmission, toInspectionCards, type PortalSubmissionTarget, type PublicInspection } from "./model.js";
import type { ApplicationChallengeBinding, ApplicationVpHttpIssueResult } from "@midnight-ntwrk/trust-registry-api";

const STORAGE_KEY = "trust-registry.portal.api-base";

type AppState = {
  apiBase: string;
  error: string | undefined;
  flash: string | undefined;
  inspection: PublicInspection | undefined;
  loading: boolean;
  submitting: boolean;
  evidenceBusy: boolean;
  evidenceError: string | undefined;
  evidenceFlash: string | undefined;
  pendingAuditor: { binding: ApplicationChallengeBinding; challenge?: ApplicationVpHttpIssueResult } | undefined;
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
    evidenceBusy: false,
    evidenceError: undefined,
    evidenceFlash: undefined,
    pendingAuditor: undefined,
  };
  let evidenceRequestId = 0;

  const setState = (next: Partial<AppState>) => {
    Object.assign(state, next);
    render();
  };

  const client = () => new TrustRegistryApplicantPortalClient(state.apiBase, fetchImpl);

  const requirePrivateHost = () => {
    if (!canUsePrivateEvidenceHost(state.apiBase, initialUrl)) {
      throw new Error("Private evidence requires an authenticated same-origin HTTPS or localhost host.");
    }
  };

  const loadAuditorBinding = async (applicationId: string) => {
    const requestId = ++evidenceRequestId;
    setState({ evidenceBusy: true, pendingAuditor: undefined, evidenceError: undefined, evidenceFlash: undefined });
    try {
      requirePrivateHost();
      const binding = await client().loadPendingApplicationBinding(applicationId);
      if (requestId !== evidenceRequestId) return;
      if (binding.applicationId !== applicationId || binding.role !== "auditor"
        || binding.scope.role !== "auditor" || binding.governedResource.type !== "requestProfile") {
        throw new Error("This pending application is not a canonical auditor request.");
      }
      setState({ pendingAuditor: { binding } });
    } catch (error) {
      if (requestId === evidenceRequestId) setState({ evidenceError: formatApiError(error) });
    } finally {
      if (requestId === evidenceRequestId) setState({ evidenceBusy: false });
    }
  };

  const issueAuditorChallenge = async () => {
    const pending = state.pendingAuditor;
    if (pending === undefined) return;
    const requestId = ++evidenceRequestId;
    setState({ evidenceBusy: true, pendingAuditor: { binding: pending.binding }, evidenceError: undefined, evidenceFlash: undefined });
    try {
      requirePrivateHost();
      const challenge = await client().issueApplicationChallenge(pending.binding.applicationId);
      if (requestId !== evidenceRequestId) return;
      if (challenge.applicationId !== pending.binding.applicationId) {
        throw new Error("Challenge application ID did not match the pending auditor application.");
      }
      setState({ pendingAuditor: { binding: pending.binding, challenge } });
    } catch (error) {
      if (requestId === evidenceRequestId) setState({ evidenceError: formatApiError(error) });
    } finally {
      if (requestId === evidenceRequestId) setState({ evidenceBusy: false });
    }
  };

  const submitAuditorPresentation = async (rawPresentation: string) => {
    const pending = state.pendingAuditor;
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
        pendingAuditor: { binding: pending.binding },
        evidenceFlash: `Auditor evidence accepted: ${result.receipt.receiptId}. The application still requires governance approval.`,
      });
    } catch (error) {
      if (requestId === evidenceRequestId) {
        setState({ pendingAuditor: { binding: pending.binding }, evidenceError: formatApiError(error) });
      }
    } finally {
      if (requestId === evidenceRequestId) setState({ evidenceBusy: false });
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
      setState({ apiBase, pendingAuditor: undefined, evidenceBusy: false, evidenceError: undefined, evidenceFlash: undefined });
      void refreshInspection();
    });

    root.querySelector<HTMLButtonElement>("[data-refresh]")?.addEventListener("click", () => {
      void refreshInspection();
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

    root.querySelector<HTMLFormElement>("[data-auditor-binding-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const applicationId = form.querySelector<HTMLInputElement>("[name='applicationId']")?.value.trim();
      if (applicationId !== undefined && applicationId.length > 0) void loadAuditorBinding(applicationId);
    });

    root.querySelector<HTMLButtonElement>("[data-auditor-challenge]")?.addEventListener("click", () => {
      void issueAuditorChallenge();
    });

    root.querySelector<HTMLFormElement>("[data-auditor-vp-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const input = form.querySelector<HTMLTextAreaElement>("[name='presentation']");
      if (input === null) return;
      const raw = input.value;
      input.value = "";
      void submitAuditorPresentation(raw);
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
    const previousVpForm = root.querySelector<HTMLFormElement>("[data-auditor-vp-form]");
    const previousVp = previousVpForm?.querySelector<HTMLTextAreaElement>("[name='presentation']")?.value;
    const previousChallengeHash = previousVpForm?.dataset.challengeHash;
    const cards = state.inspection === undefined ? [] : toInspectionCards(state.inspection);
    const issuerCards = cards.filter((card) => card.target === "issuer");
    const verifierCards = cards.filter((card) => card.target === "verifier");
    const auditorCards = cards.filter((card) => card.target === "auditor");
    const recognitionCards = cards.filter((card) => card.target === "recognition");
    const privateHost = canUsePrivateEvidenceHost(state.apiBase, initialUrl);
    const pending = state.pendingAuditor;

    root.innerHTML = `
      <main class="shell">
        <section class="hero">
          <p class="eyebrow">Public Trust Entry</p>
          <h1>Trust Registry Applicant Portal</h1>
          <p>Inspect active trust records and submit local demo applications. Pending auditor applicants can present challenge-bound evidence through an authenticated same-origin host.</p>
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
            <h2>Pending auditor evidence</h2>
            <p>Use an application ID already created by a trusted admission host. Its canonical DID, scope, policy, and resource are loaded from the server, not entered here. This does not create or approve membership.</p>
            ${state.evidenceError === undefined ? "" : `<div class="alert error">${escapeHtml(state.evidenceError)}</div>`}
            ${state.evidenceFlash === undefined ? "" : `<div class="alert success">${escapeHtml(state.evidenceFlash)}</div>`}
            ${privateHost ? "" : `<p class="alert error">Private evidence is disabled: serve the portal and authenticated API from the same HTTPS or localhost origin.</p>`}
            <form data-auditor-binding-form>
              <label class="label">Pending application ID
                <input class="input mono" name="applicationId" type="text" maxlength="256" required />
              </label>
              <button class="button secondary" type="submit"${!privateHost || state.evidenceBusy ? " disabled" : ""}>Load auditor request</button>
            </form>
            ${pending === undefined ? "" : `
              <div class="panel">
                <p>Applicant DID: <span class="mono">${escapeHtml(pending.binding.subjectDid)}</span></p>
                <p>Policy: ${escapeHtml(pending.binding.policyId)} · ${escapeHtml(pending.binding.policyVersion)}</p>
                <p>Governed resource: ${escapeHtml(pending.binding.governedResource.type)}:${escapeHtml(pending.binding.governedResource.id)}</p>
                <p>Scope commitment: <span class="mono">${escapeHtml(pending.binding.scopeCommitment)}</span></p>
                <pre class="mono">${escapeHtml(JSON.stringify(pending.binding.scope, null, 2))}</pre>
                <button class="button secondary" type="button" data-auditor-challenge${state.evidenceBusy ? " disabled" : ""}>Issue one-use VP challenge</button>
              </div>
              ${pending.challenge === undefined ? "" : `
                <div class="panel">
                  <p>Challenge expires: ${escapeHtml(pending.challenge.expiresAt)}</p>
                  <p>Nonce: <span class="mono">${escapeHtml(pending.challenge.nonce)}</span></p>
                  <p>Challenge hash: <span class="mono">${escapeHtml(pending.challenge.challengeHash)}</span></p>
                  <form data-auditor-vp-form data-challenge-hash="${escapeHtml(pending.challenge.challengeHash)}">
                    <label class="label">Presentation JSON
                      <textarea class="input mono" name="presentation" rows="6" required></textarea>
                    </label>
                    <button class="button" type="submit"${state.evidenceBusy ? " disabled" : ""}>Submit VP evidence</button>
                  </form>
                </div>
              `}
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
    if (previousVp !== undefined && previousChallengeHash === state.pendingAuditor?.challenge?.challengeHash) {
      const currentVp = root.querySelector<HTMLTextAreaElement>("[data-auditor-vp-form] [name='presentation']");
      if (currentVp !== null) currentVp.value = previousVp;
    }
    bindEvents();
  };

  render();
  void refreshInspection();
};
