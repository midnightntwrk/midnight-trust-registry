import { TrustRegistryApplicantPortalApiError, TrustRegistryApplicantPortalClient, normalizeApiBaseUrl } from "./api.js";
import { TARGET_OPTIONS, describeSubmission, toInspectionCards, type ApplicantTarget, type PublicInspection } from "./model.js";

const STORAGE_KEY = "trust-registry.portal.api-base";

type AppState = {
  apiBase: string;
  error: string | undefined;
  flash: string | undefined;
  inspection: PublicInspection | undefined;
  loading: boolean;
  submitting: boolean;
};

const escapeHtml = (value: string): string =>
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
  const queryBase = initialUrl.searchParams.get("apiBase");

  const state: AppState = {
    apiBase: normalizeApiBaseUrl(queryBase ?? storage.getItem(STORAGE_KEY) ?? "http://127.0.0.1:4400"),
    error: undefined,
    flash: undefined,
    inspection: undefined,
    loading: false,
    submitting: false,
  };

  const setState = (next: Partial<AppState>) => {
    Object.assign(state, next);
    render();
  };

  const client = () => new TrustRegistryApplicantPortalClient(state.apiBase, fetchImpl);

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
    target: ApplicantTarget,
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
      setState({ apiBase });
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
      void submitApplication(targetInput.value as ApplicantTarget, labelInput.value.trim());
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
    const cards = state.inspection === undefined ? [] : toInspectionCards(state.inspection);
    const issuerCards = cards.filter((card) => card.target === "issuer");
    const verifierCards = cards.filter((card) => card.target === "verifier");
    const recognitionCards = cards.filter((card) => card.target === "recognition");

    root.innerHTML = `
      <main class="shell">
        <section class="hero">
          <p class="eyebrow">Public Trust Entry</p>
          <h1>Trust Registry Applicant Portal</h1>
          <p>Submit a new issuer, verifier, or recognition application, then inspect the registry’s current active trust surface from the same local-first API. This slice intentionally leaves maintainer review actions in the separate admin console.</p>
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
              <div class="metric"><span>Active issuers</span><strong>${(state.inspection?.summary.issuerCounts.active ?? 0).toString()}</strong></div>
              <div class="metric"><span>Active verifiers</span><strong>${(state.inspection?.summary.verifierCounts.active ?? 0).toString()}</strong></div>
              <div class="metric"><span>Recognitions</span><strong>${(state.inspection?.summary.recognitionCounts.active ?? 0).toString()}</strong></div>
            </div>
          </div>
          ${state.error === undefined ? "" : `<div class="alert error">${escapeHtml(state.error)}</div>`}
          ${state.flash === undefined ? "" : `<div class="alert success">${escapeHtml(state.flash)}</div>`}
        </section>
        <section class="content">
          <form class="form-panel" data-submit-form>
            <h2>Apply for membership</h2>
            <p>Applications enter the governed workflow as proposed records. Approval and activation remain in the admin console.</p>
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
          <div class="lanes">
            ${renderInspectionLane("Active issuers", issuerCards)}
            ${renderInspectionLane("Active verifiers", verifierCards)}
            ${renderInspectionLane("Active recognitions", recognitionCards)}
          </div>
        </section>
      </main>
    `;
    bindEvents();
  };

  render();
  void refreshInspection();
};
