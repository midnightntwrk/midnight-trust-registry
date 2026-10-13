import type {
  GovernedMembershipAction,
  GovernedMembershipSignatureRequest,
  PreparedGovernedMembershipAction,
  TrustRegistryApiApplicationAction,
} from "@midnight-ntwrk/trust-registry-api";

import {
  TrustRegistryAdminConsoleApiError,
  TrustRegistryAdminConsoleClient,
  normalizeApiBaseUrl,
} from "./api.js";
import {
  REVIEW_STATUSES,
  REVIEW_STATUS_LABELS,
  buildReviewCards,
  describeMutation,
  executeEpochPublication,
  executeReviewAction,
  getReviewActions,
  groupReviewCards,
  type ReviewBoard,
  type ReviewCard,
  type ReviewStatus,
} from "./model.js";

const STORAGE_KEY = "trust-registry.admin.api-base";

type AppState = {
  apiBase: string;
  board: ReviewBoard | undefined;
  cards: readonly ReviewCard[];
  epochLabel: string;
  error: string | undefined;
  flash: string | undefined;
  governedBusy: boolean;
  governedKey: string | undefined;
  governedPrepared: PreparedGovernedMembershipAction | undefined;
  governedSignersJson: string;
  loading: boolean;
  publishing: boolean;
  selectedKey: string | undefined;
};

const escapeHtml = (value: string): string =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");

const formatApiError = (error: unknown): string => {
  if (error instanceof TrustRegistryAdminConsoleApiError) {
    const title = error.problem.title ?? "request failed";
    const detail = error.problem.detail;
    return detail === undefined ? title : `${title}: ${detail}`;
  }
  return error instanceof Error ? error.message : String(error);
};

const countCards = (
  board: ReviewBoard,
  status: ReviewStatus,
): number =>
  board.summary.issuerCounts[status]
  + board.summary.verifierCounts[status]
  + board.summary.auditorCounts[status]
  + board.summary.recognitionCounts[status];

const governedActionFor = (card: ReviewCard): GovernedMembershipAction | undefined =>
  card.status === "proposed" ? "approve" : card.status === "authorized" ? "activate" : undefined;

const parseSignerInput = (value: string): GovernedMembershipSignatureRequest["signers"] => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("Signer input must be a JSON array of externally produced signatures.");
  }
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 16) {
    throw new Error("Provide between one and sixteen external signer entries.");
  }
  return parsed as GovernedMembershipSignatureRequest["signers"];
};

export const createAdminConsoleApp = (
  root: HTMLElement,
  options: {
    fetchImpl?: typeof fetch;
    initialUrl?: URL;
    storage?: Storage;
    confirm?: (message: string) => boolean | Promise<boolean>;
  } = {},
): void => {
  const initialUrl = options.initialUrl ?? new URL(window.location.href);
  const storage = options.storage ?? window.localStorage;
  const fetchImpl = options.fetchImpl ?? window.fetch.bind(window);
  const confirm = options.confirm ?? window.confirm.bind(window);
  const queryBase = initialUrl.searchParams.get("apiBase");
  const rememberedBase = storage.getItem(STORAGE_KEY);

  const state: AppState = {
    apiBase: normalizeApiBaseUrl(queryBase ?? rememberedBase ?? "http://127.0.0.1:4400"),
    board: undefined,
    cards: [],
    epochLabel: "",
    error: undefined,
    flash: undefined,
    governedBusy: false,
    governedKey: undefined,
    governedPrepared: undefined,
    governedSignersJson: "",
    loading: false,
    publishing: false,
    selectedKey: undefined,
  };

  const setState = (next: Partial<AppState>) => {
    Object.assign(state, next);
    render();
  };

  const getClient = (): TrustRegistryAdminConsoleClient =>
    new TrustRegistryAdminConsoleClient(state.apiBase, fetchImpl);

  const selectedCard = (): ReviewCard | undefined =>
    state.cards.find((card) => card.key === state.selectedKey);

  const refreshBoard = async (flash?: string) => {
    setState({ loading: true, error: undefined, ...(flash === undefined ? {} : { flash }) });
    try {
      const board = await getClient().loadReviewBoard();
      const cards = buildReviewCards(board);
      const nextSelectedKey = state.selectedKey !== undefined
        && cards.some((card) => card.key === state.selectedKey)
        ? state.selectedKey
        : cards[0]?.key;
      setState({
        board,
        cards,
        governedKey: undefined,
        governedPrepared: undefined,
        governedSignersJson: "",
        loading: false,
        selectedKey: nextSelectedKey,
      });
    } catch (error) {
      setState({
        board: undefined,
        cards: [],
        error: formatApiError(error),
        flash: undefined,
        governedKey: undefined,
        governedPrepared: undefined,
        loading: false,
        selectedKey: undefined,
      });
    }
  };

  const runAction = async (
    action: TrustRegistryApiApplicationAction,
  ) => {
    if (state.loading || state.publishing || state.governedBusy) return;
    const card = selectedCard();
    if (card === undefined) {
      return;
    }

    setState({ loading: true, error: undefined, flash: undefined });
    try {
      const result = await executeReviewAction(card, action, confirm, (target, id, confirmedAction) =>
        getClient().mutate(target, id, confirmedAction));
      if (result === null) {
        setState({ loading: false });
        return;
      }
      await refreshBoard(describeMutation(result));
    } catch (error) {
      setState({
        error: formatApiError(error),
        flash: undefined,
        loading: false,
      });
    }
  };

  const publishEpoch = async (label: string) => {
    if (state.loading || state.publishing || state.governedBusy) return;
    setState({ publishing: true, error: undefined, flash: undefined });
    try {
      const result = await executeEpochPublication(label, confirm, (confirmedLabel) =>
        getClient().publishEpoch(confirmedLabel));
      if (result === null) {
        setState({ publishing: false });
        return;
      }
      await refreshBoard(describeMutation(result));
    } catch (error) {
      setState({
        error: formatApiError(error),
        flash: undefined,
        publishing: false,
      });
      return;
    }
    setState({ publishing: false, epochLabel: "" });
  };

  const prepareGoverned = async () => {
    if (state.loading || state.publishing || state.governedBusy) return;
    const card = selectedCard();
    if (card === undefined) return;
    const action = governedActionFor(card);
    if (action === undefined) return;
    setState({ governedBusy: true, governedKey: undefined, governedPrepared: undefined,
      governedSignersJson: "", error: undefined, flash: undefined });
    try {
      const prepared = await getClient().prepareGovernedAction(card.target, card.id, action);
      setState({ governedBusy: false, governedKey: `${card.key}:${action}`, governedPrepared: prepared });
    } catch (error) {
      setState({ governedBusy: false, error: formatApiError(error) });
    }
  };

  const submitGoverned = async () => {
    if (state.loading || state.publishing || state.governedBusy) return;
    const card = selectedCard();
    if (card === undefined) return;
    const action = governedActionFor(card);
    if (action === undefined || state.governedKey !== `${card.key}:${action}`
      || state.governedPrepared === undefined) return;
    const prepared = state.governedPrepared;
    let signers: GovernedMembershipSignatureRequest["signers"];
    try {
      signers = parseSignerInput(state.governedSignersJson);
    } catch (error) {
      setState({ error: formatApiError(error) });
      return;
    }
    if (!(await confirm(`Submit ${signers.length} external signatures to ${action} ${card.target} ${card.id}?`))) return;
    if (state.selectedKey !== card.key || state.governedKey !== `${card.key}:${action}`) return;
    setState({ governedBusy: true, error: undefined, flash: undefined });
    try {
      const receipt = await getClient().submitGovernedAction(card.target, card.id, action, {
        prepared,
        signers,
      });
      await refreshBoard(`Compact ${action} accepted: ${receipt.eventHash}. Network finality is not implied.`);
      setState({ governedBusy: false });
    } catch (error) {
      setState({
        governedBusy: false,
        error: formatApiError(error),
        ...(error instanceof TrustRegistryAdminConsoleApiError && error.problem.status === 409
          ? { governedKey: undefined, governedPrepared: undefined, governedSignersJson: "" }
          : {}),
      });
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
      setState({ apiBase });
      void refreshBoard();
    });

    root.querySelector<HTMLButtonElement>("[data-refresh]")?.addEventListener("click", () => {
      if (state.governedBusy) return;
      void refreshBoard();
    });

    root.querySelector<HTMLInputElement>("[data-epoch-label]")?.addEventListener("input", (event) => {
      state.epochLabel = (event.currentTarget as HTMLInputElement).value;
    });
    root.querySelector<HTMLFormElement>("[data-epoch-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      void publishEpoch(state.epochLabel);
    });

    root.querySelectorAll<HTMLElement>("[data-select-key]").forEach((element) => {
      element.addEventListener("click", () => {
        setState({
          selectedKey: element.dataset.selectKey,
          governedKey: undefined,
          governedPrepared: undefined,
          governedSignersJson: "",
          flash: undefined,
        });
      });
    });

    root.querySelector<HTMLButtonElement>("[data-governed-prepare]")?.addEventListener("click", () => {
      void prepareGoverned();
    });
    root.querySelector<HTMLTextAreaElement>("[data-governed-signers]")?.addEventListener("input", (event) => {
      state.governedSignersJson = (event.currentTarget as HTMLTextAreaElement).value;
    });
    root.querySelector<HTMLFormElement>("[data-governed-submit]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      void submitGoverned();
    });

    root.querySelectorAll<HTMLButtonElement>("[data-action]").forEach((element) => {
      element.addEventListener("click", () => {
        const action = element.dataset.action as TrustRegistryApiApplicationAction | undefined;
        if (action !== undefined) {
          void runAction(action);
        }
      });
    });
  };

  const renderMetrics = (board: ReviewBoard): string => `
    <div class="metrics">
      <div class="metric"><span>Registry</span><strong>${escapeHtml(board.summary.registryLabel)}</strong></div>
      <div class="metric"><span>Current epoch</span><strong class="mono">${escapeHtml(board.summary.currentEpochId)}</strong></div>
      <div class="metric"><span>Proposed</span><strong>${countCards(board, "proposed").toString()}</strong></div>
      <div class="metric"><span>Authorized</span><strong>${countCards(board, "authorized").toString()}</strong></div>
      <div class="metric"><span>Active</span><strong>${countCards(board, "active").toString()}</strong></div>
      <div class="metric"><span>Risk queue</span><strong>${(countCards(board, "suspended") + countCards(board, "revoked")).toString()}</strong></div>
    </div>
  `;

  const renderCard = (card: ReviewCard): string => `
    <button type="button" class="card${card.key === state.selectedKey ? " selected" : ""}" data-select-key="${escapeHtml(card.key)}">
      <div class="card-top">
        <div>
          <h3>${escapeHtml(card.label)}</h3>
          <p>${escapeHtml(card.target)} review</p>
        </div>
        <span class="status-chip ${escapeHtml(card.status)}">${escapeHtml(REVIEW_STATUS_LABELS[card.status])}</span>
      </div>
      <div class="meta-row">
        <span>${escapeHtml(card.scope)}</span>
        <span>${escapeHtml(card.trustLevel)}</span>
      </div>
      <div class="meta-row">
        <code>${escapeHtml(card.subject)}</code>
      </div>
      <div class="meta-row">
        <span>Updated ${escapeHtml(card.updatedAt)}</span>
      </div>
    </button>
  `;

  const renderColumn = (
    status: ReviewStatus,
    cards: readonly ReviewCard[],
  ): string => `
    <section class="column">
      <div class="column-header">
        <h2>${escapeHtml(REVIEW_STATUS_LABELS[status])}</h2>
        <span>${cards.length.toString()} items</span>
      </div>
      ${cards.length === 0
        ? `<div class="empty-state"><p>No ${escapeHtml(REVIEW_STATUS_LABELS[status].toLowerCase())} records.</p></div>`
        : cards.map(renderCard).join("")}
    </section>
  `;

  const renderDetailPanel = (): string => {
    const card = selectedCard();
    if (card === undefined) {
      return `
        <aside class="detail-panel">
          <div class="empty-state">
            <p>Select a record to review its detail and available maintainer actions.</p>
          </div>
        </aside>
      `;
    }

    const governedAction = governedActionFor(card);
    const prepared = governedAction !== undefined
      && state.governedKey === `${card.key}:${governedAction}`
      ? state.governedPrepared : undefined;

    return `
      <aside class="detail-panel">
        <div>
          <p class="eyebrow">Selected Record</p>
          <h2>${escapeHtml(card.label)}</h2>
          <p>${escapeHtml(card.target)} · ${escapeHtml(REVIEW_STATUS_LABELS[card.status])}</p>
        </div>
        <dl>
          ${card.detailRows.map((row) => `
            <div>
              <dt>${escapeHtml(row.label)}</dt>
              <dd><code>${escapeHtml(row.value)}</code></dd>
            </div>
          `).join("")}
          ${card.target === "auditor" || card.target === "verifier" ? `<div><dt>Scope detail</dt><dd>Full request-scope preimage is not available in this snapshot; verify the governed resource ID against authenticated evidence.</dd></div>` : ""}
          <div>
            <dt>Last update</dt>
            <dd>${escapeHtml(card.updatedAt)}</dd>
          </div>
        </dl>
        ${governedAction === undefined ? "" : `
          <section class="governed-panel">
            <p class="eyebrow">Compact quorum</p>
            <h3>External ${escapeHtml(governedAction)} signatures</h3>
            <p>Prepare the current ledger-bound action, have existing maintainers sign its policy-bound digest outside this browser, then submit their public keys and signatures. This console never handles private keys.</p>
            <button class="button secondary" type="button" data-governed-prepare${state.loading || state.publishing || state.governedBusy ? " disabled" : ""}>Prepare ${escapeHtml(governedAction)}</button>
            ${prepared === undefined ? "" : `
              <p>Sign this exact context. A changed sequence or policy requires a fresh preparation.</p>
              <pre class="governed-context mono">${escapeHtml(JSON.stringify(prepared, null, 2))}</pre>
              <form data-governed-submit>
                <label>External signer entries as JSON array
                  <textarea class="input mono governed-signers" data-governed-signers spellcheck="false" placeholder='[{"keyId":"0x...","publicKey":{"x":"...","y":"..."},"signature":"0x..."}]'>${escapeHtml(state.governedSignersJson)}</textarea>
                </label>
                <button class="button" type="submit"${state.loading || state.publishing || state.governedBusy ? " disabled" : ""}>Submit signed ${escapeHtml(governedAction)}</button>
              </form>
            `}
          </section>
        `}
        <p class="eyebrow">Local fixture controls</p>
        <div class="actions">
          ${getReviewActions(card.status).map((action) => `
            <button class="button${action === "archive" ? " ghost" : ""}" data-action="${escapeHtml(action)}"${state.loading || state.publishing || state.governedBusy ? " disabled" : ""}>
              ${escapeHtml(action)}
            </button>
          `).join("") || "<p>No maintainer actions available for this lifecycle state.</p>"}
        </div>
      </aside>
    `;
  };

  const render = () => {
    const groupedCards = groupReviewCards(state.cards);
    root.innerHTML = `
      <main class="shell">
        <section class="hero">
          <div class="hero-copy">
            <div>
              <p class="eyebrow">Governed Review Surface</p>
              <h1>Trust Registry Admin Console</h1>
              <p>Review issuer, verifier, auditor, and recognition proposals. Prepare Compact quorum actions for external signing; local fixture controls remain separate for the workspace demo.</p>
            </div>
          </div>
          <div class="toolbar">
            <form data-api-base-form>
              <label>
                API base URL
                <input class="input mono" type="url" name="apiBase" value="${escapeHtml(state.apiBase)}" />
              </label>
              <div class="actions">
                <button class="button" type="submit"${state.loading || state.governedBusy ? " disabled" : ""}>Connect</button>
                <button class="button secondary" type="button" data-refresh${state.loading || state.governedBusy ? " disabled" : ""}>Refresh</button>
              </div>
            </form>
            <form class="epoch-panel" data-epoch-form>
              <label>
                Publish epoch label
                <input class="input" data-epoch-label type="text" value="${escapeHtml(state.epochLabel)}" placeholder="optional operator label" />
              </label>
              <button class="button" type="submit"${state.loading || state.publishing || state.governedBusy ? " disabled" : ""}>Publish epoch</button>
            </form>
          </div>
          ${state.error === undefined ? "" : `<div class="alert error">${escapeHtml(state.error)}</div>`}
          ${state.flash === undefined ? "" : `<div class="alert success">${escapeHtml(state.flash)}</div>`}
          ${state.board === undefined ? "" : renderMetrics(state.board)}
        </section>
        <section class="workspace">
          <div class="board">
            ${REVIEW_STATUSES.map((status) => renderColumn(status, groupedCards[status])).join("")}
          </div>
          ${renderDetailPanel()}
        </section>
      </main>
    `;
    bindEvents();
  };

  render();
  void refreshBoard();
};
