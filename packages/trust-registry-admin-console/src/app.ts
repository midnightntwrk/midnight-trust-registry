import type { TrustRegistryApiApplicationAction } from "@midnight-ntwrk/trust-registry-api";

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
  error: string | undefined;
  flash: string | undefined;
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
  + board.summary.recognitionCounts[status];

export const createAdminConsoleApp = (
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
  const rememberedBase = storage.getItem(STORAGE_KEY);

  const state: AppState = {
    apiBase: normalizeApiBaseUrl(queryBase ?? rememberedBase ?? "http://127.0.0.1:4400"),
    board: undefined,
    cards: [],
    error: undefined,
    flash: undefined,
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
        loading: false,
        selectedKey: nextSelectedKey,
      });
    } catch (error) {
      setState({
        board: undefined,
        cards: [],
        error: formatApiError(error),
        flash: undefined,
        loading: false,
        selectedKey: undefined,
      });
    }
  };

  const runAction = async (
    action: TrustRegistryApiApplicationAction,
  ) => {
    const card = selectedCard();
    if (card === undefined) {
      return;
    }

    setState({ loading: true, error: undefined, flash: undefined });
    try {
      const result = await getClient().mutate(card.target, card.id, action);
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
    setState({ publishing: true, error: undefined, flash: undefined });
    try {
      const result = await getClient().publishEpoch(label);
      await refreshBoard(describeMutation(result));
      const input = root.querySelector<HTMLInputElement>("[data-epoch-label]");
      if (input !== null) {
        input.value = "";
      }
    } catch (error) {
      setState({
        error: formatApiError(error),
        flash: undefined,
        publishing: false,
      });
      return;
    }
    setState({ publishing: false });
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
      void refreshBoard();
    });

    root.querySelector<HTMLFormElement>("[data-epoch-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const input = root.querySelector<HTMLInputElement>("[data-epoch-label]");
      void publishEpoch(input?.value ?? "");
    });

    root.querySelectorAll<HTMLElement>("[data-select-key]").forEach((element) => {
      element.addEventListener("click", () => {
        setState({
          selectedKey: element.dataset.selectKey,
          flash: undefined,
        });
      });
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
    <article class="card${card.key === state.selectedKey ? " selected" : ""}" data-select-key="${escapeHtml(card.key)}">
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
    </article>
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
          <div>
            <dt>Last update</dt>
            <dd>${escapeHtml(card.updatedAt)}</dd>
          </div>
        </dl>
        <div class="actions">
          ${getReviewActions(card.status).map((action) => `
            <button class="button${action === "archive" ? " ghost" : ""}" data-action="${escapeHtml(action)}"${state.loading ? " disabled" : ""}>
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
              <p>Review issuer, verifier, and recognition proposals from the local governed API. This slice stays local-first: it reads the same workspace-backed trust-registry state that the operator CLI and HTTP mutation surface already govern.</p>
            </div>
          </div>
          <div class="toolbar">
            <form data-api-base-form>
              <label>
                API base URL
                <input class="input mono" type="url" name="apiBase" value="${escapeHtml(state.apiBase)}" />
              </label>
              <div class="actions">
                <button class="button" type="submit"${state.loading ? " disabled" : ""}>Connect</button>
                <button class="button secondary" type="button" data-refresh${state.loading ? " disabled" : ""}>Refresh</button>
              </div>
            </form>
            <form class="epoch-panel" data-epoch-form>
              <label>
                Publish epoch label
                <input class="input" data-epoch-label type="text" placeholder="optional operator label" />
              </label>
              <button class="button" type="submit"${state.publishing ? " disabled" : ""}>Publish epoch</button>
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
