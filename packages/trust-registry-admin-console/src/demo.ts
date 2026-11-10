import { TrustRegistryAdminConsoleClient, normalizeApiBaseUrl } from "./api.js";
import { buildReviewCards, REVIEW_STATUSES, type ReviewBoard, type ReviewCard } from "./model.js";
import { countVotes, DEMO_MAINTAINERS, DEMO_QUORUM, parseDemoVotes, voteOutcome, type DemoVote } from "./demo-state.js";

type ApplicantRole = "issuer" | "verifier" | "auditor";
type DemoRole = "overview" | ApplicantRole | `maintainer-${number}`;

type DemoState = {
  board: ReviewBoard | undefined;
  cards: readonly ReviewCard[];
  busy: boolean;
  error: string | undefined;
  message: string | undefined;
  role: DemoRole;
  selectedKey: string | undefined;
};

const GUIDED_DEMO_REGISTRY_ID = "registry:guided-role-demo:trusted";
const GUIDED_DEMO_REGISTRY_LABEL = "guided-role-demo";
const isGuidedWorkspace = (board: ReviewBoard): boolean =>
  board.sourceMode === "workspace"
    && board.summary.registryId === GUIDED_DEMO_REGISTRY_ID
    && board.summary.registryLabel === GUIDED_DEMO_REGISTRY_LABEL
    && typeof board.workspaceInstanceId === "string"
    && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(board.workspaceInstanceId);
const isGuidedCard = (card: ReviewCard): boolean =>
  card.target === "issuer" || card.target === "verifier" || card.target === "auditor";
const hasKnownStatus = (card: ReviewCard): boolean => REVIEW_STATUSES.includes(card.status);

const applicantRoles: readonly ApplicantRole[] = ["issuer", "verifier", "auditor"];
const isApplicantRole = (value: DemoRole): value is ApplicantRole =>
  applicantRoles.includes(value as ApplicantRole);
const maintainerNumber = (role: DemoRole): (typeof DEMO_MAINTAINERS)[number] | undefined => {
  const match = /^maintainer-([1-5])$/u.exec(role);
  return match === null ? undefined : Number(match[1]) as (typeof DEMO_MAINTAINERS)[number];
};
const roleFromHash = (hash: string): DemoRole => {
  const role = hash.replace(/^#\/?/u, "");
  if (role === "issuer" || role === "verifier" || role === "auditor" || maintainerNumber(role as DemoRole) !== undefined) {
    return role as DemoRole;
  }
  return "overview";
};
const roleLabel = (role: DemoRole): string => {
  const number = maintainerNumber(role);
  return number === undefined
    ? role === "overview" ? "Overview" : `${role[0]!.toUpperCase()}${role.slice(1)} #1`
    : `Maintainer #${number}`;
};

export const createGuidedDemoApp = (
  root: HTMLElement,
  options: {
    initialUrl?: URL;
    storage?: Storage;
    confirm?: (message: string) => boolean | Promise<boolean>;
    client?: TrustRegistryAdminConsoleClient;
  } = {},
): void => {
  const initialUrl = options.initialUrl ?? new URL(window.location.href);
  const storage = options.storage ?? window.localStorage;
  const confirm = options.confirm ?? window.confirm.bind(window);
  const apiBase = normalizeApiBaseUrl(initialUrl.searchParams.get("apiBase") ?? "http://127.0.0.1:4500");
  const client = options.client ?? new TrustRegistryAdminConsoleClient(apiBase, window.fetch.bind(window));
  const isLoopback = ["localhost", "127.0.0.1", "[::1]"].includes(initialUrl.hostname);
  const apiIsLoopback = (() => {
    try {
      const url = new URL(apiBase);
      return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    } catch {
      return false;
    }
  })();
  const state: DemoState = {
    board: undefined, cards: [], busy: false, error: undefined, message: undefined,
    role: roleFromHash(initialUrl.hash), selectedKey: undefined,
  };
  // Only inert slot markers enter the HTML parser; API values are assigned through DOM APIs.
  let dynamicValues: string[] = [];
  const dynamic = (value: string): string => {
    const slot = dynamicValues.length;
    dynamicValues.push(value);
    return `__MTR_DEMO_SLOT_${slot}__`;
  };
  const fillDynamicValues = (): void => {
    const slotPattern = /__MTR_DEMO_SLOT_(\d+)__/gu;
    const substitute = (value: string): string => value.replace(slotPattern, (_match, index: string) =>
      dynamicValues[Number(index)] ?? "");
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      if (node.nodeType === Node.TEXT_NODE) {
        node.textContent = substitute(node.textContent ?? "");
      } else if (node instanceof Element) {
        for (const attribute of Array.from(node.attributes)) {
          if (attribute.value.includes("__MTR_DEMO_SLOT_")) node.setAttribute(attribute.name, substitute(attribute.value));
        }
      }
    }
  };

  const isFixture = (): boolean => isLoopback && apiIsLoopback && state.board !== undefined
    && isGuidedWorkspace(state.board);
  const voteKeyPrefix = (): string =>
    `trust-registry.demo-votes.v2:${state.board?.summary.registryId ?? "unknown"}:${state.board?.workspaceInstanceId ?? "unavailable"}:`;
  const voteKey = (card: ReviewCard): string =>
    `${voteKeyPrefix()}${card.key}:${card.status}:${card.updatedAt}`;
  const votesFor = (card: ReviewCard) => parseDemoVotes(storage.getItem(voteKey(card)));
  const selectedCard = (): ReviewCard | undefined => {
    const explicit = state.cards.find((card) => card.key === state.selectedKey);
    if (explicit?.status === "proposed" || explicit?.status === "authorized") return explicit;
    return state.cards.find((card) => card.status === "proposed")
      ?? state.cards.find((card) => card.status === "authorized")
      ?? explicit ?? state.cards[0];
  };
  const pendingCards = (): readonly ReviewCard[] => state.cards.filter((card) =>
    card.status === "proposed" || card.status === "authorized");

  const renderSidebar = (): string => {
    const navLink = (role: DemoRole, label: string, badge = "") =>
      `<a href="#${role}" data-role="${role}" class="demo-nav-link${state.role === role ? " active" : ""}"${state.role === role ? ' aria-current="page"' : ""}><span>${label}</span>${badge}</a>`;
    const pending = pendingCards().length;
    return `<aside class="demo-sidebar">
      <div class="demo-brand"><img src="./midnight-logo.svg" alt="Midnight" /><strong>Trust Registry</strong></div>
      <div class="demo-environment"><small>Guided workspace</small><strong>Local demo</strong><span>Practice data, not a live registry</span></div>
      <nav aria-label="Demo roles">
        <p class="demo-nav-heading">Journey</p>
        ${navLink("overview", "Overview")}
        <details class="demo-nav-group"${state.role === "overview" || isApplicantRole(state.role) ? " open" : ""}>
          <summary>Applicants</summary>
          <div>${applicantRoles.map((role) => navLink(role, roleLabel(role))).join("")}</div>
        </details>
        <details class="demo-nav-group"${maintainerNumber(state.role) !== undefined ? " open" : ""}>
          <summary>Committee · 3 of 5</summary>
          <div>${DEMO_MAINTAINERS.map((number) => navLink(`maintainer-${number}`, `Maintainer #${number}`,
            pending > 0 ? `<span class="demo-nav-count">${pending}</span>` : "")).join("")}</div>
        </details>
      </nav>
      <div class="demo-sidebar-footer"><a href="${dynamic(`./index.html?demo=1&apiBase=${encodeURIComponent(apiBase)}`)}">Open technical admin console</a><span>Persona switching is not authentication.</span></div>
    </aside>`;
  };

  const renderOverview = (): string => {
    const pending = pendingCards().length;
    const active = state.cards.filter((card) => card.status === "active").length;
    return `<section class="demo-intro"><p class="demo-eyebrow">The guided journey</p><h1>Explore every role, one step at a time.</h1><p>Start as an issuer, verifier, or auditor. Submit a practice request, then switch to three maintainers to decide what happens next.</p></section>
      <div class="demo-steps">
        <a href="#issuer" data-role="issuer" class="demo-step"><span>01 / Apply</span><strong>Choose a role</strong><p>Send a named demo application.</p><b>Start as issuer →</b></a>
        <a href="#maintainer-1" data-role="maintainer-1" class="demo-step"><span>02 / Decide</span><strong>Open the inbox</strong><p>Each maintainer makes one visible decision per stage.</p><b>Review requests →</b></a>
        <div class="demo-step"><span>03 / Observe</span><strong>See the result</strong><p>After three approvals, apply the demo result, then return to the applicant to see the new status.</p></div>
      </div>
      <section class="demo-summary"><h2>Workspace at a glance</h2><div><span><strong>${pending}</strong> awaiting decisions</span><span><strong>${active}</strong> active demo records</span><span><strong>3 / 5</strong> demo majority</span></div></section>`;
  };

  const renderApplicant = (role: ApplicantRole): string => {
    const cards = state.cards.filter((card) => card.target === role);
    return `<section class="demo-intro"><p class="demo-eyebrow">Applicant · ${roleLabel(role)}</p><h1>${role === "issuer" ? "Apply to issue" : role === "verifier" ? "Apply to verify" : "Apply to audit"}</h1><p>${role === "issuer" ? "Submit an issuer request and follow its status." : role === "verifier" ? "Request verifier authorization in the local fixture." : "Request an auditor role in the local fixture."} This does not grant on-chain authority.</p></section>
      <div class="demo-content-grid"><section class="demo-card"><p class="demo-eyebrow">Step 1 · Application</p><h2>Send a request</h2><p>Choose a name the committee can recognize. The demo API creates a proposed fixture record.</p>
        <form id="demo-application-form" data-applicant-role="${role}">
          <label for="demo-label">Display name</label><input id="demo-label" name="label" maxlength="120" required placeholder="Example ${role}" autocomplete="off"${state.busy || !isFixture() ? " disabled" : ""} />
          <button type="submit" class="demo-button primary"${state.busy || !isFixture() ? " disabled" : ""}>Send demo request</button>
        </form>
      </section><section class="demo-card"><p class="demo-eyebrow">Step 2 · Track</p><h2>Your ${role} records</h2>
        ${cards.length === 0 ? '<p class="demo-empty">No requests in this fixture yet. Send one to start the journey.</p>'
          : `<ul class="demo-record-list">${cards.map((card) => `<li><strong>${dynamic(card.label)}</strong><span class="demo-chip ${dynamic(card.status)}">${dynamic(card.status)}</span><p>${card.status === "proposed" ? "Waiting for committee demo votes." : card.status === "authorized" ? "Approved in fixture; activation is next." : card.status === "active" ? "Active in fixture only, not on chain." : "This record is no longer active."}</p></li>`).join("")}</ul>`}
        <a href="#maintainer-1" data-role="maintainer-1" class="demo-text-link">Switch to Maintainer #1 →</a>
      </section></div>`;
  };

  const renderMaintainer = (number: (typeof DEMO_MAINTAINERS)[number]): string => {
    const card = selectedCard();
    const votes = card === undefined ? {} : votesFor(card);
    const counts = countVotes(votes);
    const outcome = voteOutcome(votes);
    const ownVote = votes[number];
    const nextMaintainer = DEMO_MAINTAINERS.find((candidate) => votes[candidate] === undefined);
    return `<section class="demo-intro"><p class="demo-eyebrow">Committee · Maintainer #${number}</p><h1>Your review inbox</h1><p>Review this practice request and choose one vote. Three of five maintainers must agree before the demo record changes.</p></section>
      <div class="demo-content-grid"><section class="demo-card"><div class="demo-card-header"><div><p class="demo-eyebrow">Requests needing decisions</p><h2>Inbox</h2></div><span class="demo-chip">${pendingCards().length} open</span></div>
        ${pendingCards().length === 0 ? `<p class="demo-empty">The inbox is clear. ${card?.status === "active" || card?.status === "archived" ? "The latest demo request has a result." : "Start with an applicant role to create a request."}</p><a href="#${card?.target === "verifier" || card?.target === "auditor" ? card.target : "issuer"}" data-role="${card?.target === "verifier" || card?.target === "auditor" ? card.target : "issuer"}" class="demo-text-link">${card?.status === "active" || card?.status === "archived" ? "View applicant result" : "Start as Issuer #1"} →</a>`
          : `<ul class="demo-inbox">${pendingCards().map((item) => `<li><button type="button" data-select-card="${dynamic(item.key)}" class="${item.key === card?.key ? "selected" : ""}"><span class="demo-inbox-top"><strong>${dynamic(item.label)}</strong><span class="demo-chip ${dynamic(item.status)}">${dynamic(item.status)}</span></span><small>${dynamic(item.target)} · ${item.status === "proposed" ? "authorization" : "activation"} decision</small></button></li>`).join("")}</ul>`}
      </section><section class="demo-card demo-decision"><p class="demo-eyebrow">Selected request</p>${card === undefined || !pendingCards().some((item) => item.key === card.key)
        ? '<h2>No decision selected</h2><p>Applications appear here after submission.</p>'
        : `<h2>${dynamic(card.label)}</h2><p>${dynamic(card.target)} · ${card.status === "proposed" ? "authorize" : "activate"} fixture record</p>
          <div class="demo-review"><strong>What you are reviewing</strong><span>Applicant: ${dynamic(card.label)}</span><span>Requested role: ${dynamic(card.target)}</span><span>Decision: ${card.status === "proposed" ? "allow this applicant in the demo" : "make this approved demo record active"}</span><details><summary>Technical identifiers and demo limits</summary><code>${dynamic(card.id)}</code><span>This practice request does not include signed identity or evidence. It cannot validate a real applicant.</span></details></div>
          <div class="demo-tally"><span><strong>${counts.approve}</strong> approvals</span><span><strong>${counts.reject}</strong> rejections</span><span>Need ${DEMO_QUORUM}</span></div>
          ${ownVote === undefined && outcome === undefined ? `<div class="demo-actions"><button type="button" class="demo-button primary" data-vote="approve"${state.busy || !isFixture() ? " disabled" : ""}>Approve in demo</button><button type="button" class="demo-button secondary" data-vote="reject"${state.busy || !isFixture() ? " disabled" : ""}>Reject in demo</button></div>`
            : ownVote !== undefined ? `<p class="demo-voted">Your demo vote: <strong>${ownVote}</strong>. Each persona votes once per stage.</p>` : '<p class="demo-voted">A majority has been reached. Apply the fixture result below.</p>'}
          ${outcome === undefined ? ownVote === undefined ? '<p class="demo-next">Choose your vote to continue.</p>'
            : nextMaintainer === undefined ? '<p class="demo-next">All five maintainers voted without a majority. Review the demo votes before continuing.</p>'
              : `<a href="#maintainer-${nextMaintainer}" data-role="maintainer-${nextMaintainer}" class="demo-button primary demo-next-link">Continue as Maintainer #${nextMaintainer} →</a>`
            : `<button type="button" class="demo-button primary" data-apply-outcome="${outcome}"${state.busy || !isFixture() ? " disabled" : ""}>Apply ${outcome === "approve" ? card.status === "proposed" ? "authorization" : "activation" : "archive"} to demo</button><p class="demo-disclaimer">This changes practice data only. It is not an official approval.</p>`}
          <details class="demo-limit-details"><summary>How this differs from a real registry</summary><p>Votes live in this browser only. Switching personas is not authentication. Real governance requires independently signed actions and verified ledger results.</p></details>`}
      </section></div>`;
  };

  const render = (): void => {
    dynamicValues = [];
    const title = roleLabel(state.role);
    root.innerHTML = `<div class="demo-shell">${renderSidebar()}<div class="demo-main"><header class="demo-topbar"><div><span>Guided demo</span><span class="demo-divider">/</span><strong>${title}</strong></div><div><span class="demo-source">${isFixture() ? "Local fixture connected" : "Fixture unavailable"}</span><span class="demo-source warning">Simulation only</span></div></header><main class="demo-page">
      ${state.error === undefined ? "" : `<div class="demo-alert error" role="alert">${dynamic(state.error)}</div>`}
      ${state.message === undefined ? "" : `<div class="demo-alert success" role="status">${dynamic(state.message)}</div>`}
      ${!isLoopback || !apiIsLoopback ? '<div class="demo-alert error" role="alert">The guided demo and its API must run over HTTP on loopback only.</div>'
        : state.board === undefined ? state.error === undefined
          ? '<div class="demo-alert error" role="alert">Connect the local fixture API before using this workspace. Run pnpm demo:guided, then reload.</div>' : ""
          : !isFixture() ? '<div class="demo-alert error" role="alert">This API is not the dedicated guided demo workspace. Demo voting and application controls are disabled.</div>' : ""}
      ${state.role === "overview" ? renderOverview() : isApplicantRole(state.role) ? renderApplicant(state.role) : renderMaintainer(maintainerNumber(state.role)!)}
      <footer class="demo-page-footer"><span>Midnight Trust Registry · guided local fixture</span><button type="button" data-refresh>Refresh records</button><button type="button" data-reset-votes>Clear browser demo votes</button></footer>
    </main></div></div>`;
    fillDynamicValues();
    bind();
  };

  const reload = async (): Promise<void> => {
    try {
      const board = await client.loadReviewBoard();
      if (!isGuidedWorkspace(board)) throw new Error("This API is not the dedicated guided demo workspace.");
      state.board = board;
      const cards = buildReviewCards(board);
      if (!cards.every(hasKnownStatus)) throw new Error("The guided demo API returned an unknown record status.");
      state.cards = cards.filter(isGuidedCard);
      if (!state.cards.some((card) => card.key === state.selectedKey)) state.selectedKey = undefined;
      state.error = undefined;
    } catch (error) {
      state.board = undefined;
      state.cards = [];
      state.error = error instanceof Error ? error.message : String(error);
    }
    render();
  };

  const runBusy = async (operation: () => Promise<void>): Promise<void> => {
    if (state.busy || !isFixture()) return;
    state.busy = true;
    state.error = undefined;
    state.message = undefined;
    render();
    try { await operation(); } catch (error) {
      state.error = error instanceof Error ? error.message : String(error);
    } finally {
      state.busy = false;
      render();
    }
  };

  const bind = (): void => {
    root.querySelectorAll<HTMLAnchorElement>("[data-role]").forEach((link) => link.addEventListener("click", (event) => {
      event.preventDefault();
      const role = link.dataset.role as DemoRole;
      window.history.pushState(null, "", `#${role}`);
      state.role = role;
      state.message = undefined;
      if (isFixture()) state.error = undefined;
      render();
    }));
    root.querySelector<HTMLFormElement>("#demo-application-form")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      const role = form.dataset.applicantRole as ApplicantRole;
      const input = form.elements.namedItem("label") as HTMLInputElement;
      const label = input.value.trim();
      if (label.length === 0 || label.length > 120) {
        state.error = "Enter a display name of 1 to 120 characters.";
        render();
        return;
      }
      void runBusy(async () => {
        const submitted = await client.submitDemoApplication(role, label);
        await reload();
        if (submitted.recordKind === "authorization") {
          state.selectedKey = `${role}:${submitted.entry.authorization.authorizationId}`;
        }
        state.message = `Submitted ${label} for the ${role} demo. Switch to Maintainer #1 to review it.`;
      });
    });
    root.querySelectorAll<HTMLButtonElement>("[data-select-card]").forEach((button) => button.addEventListener("click", () => {
      state.selectedKey = button.dataset.selectCard;
      render();
    }));
    root.querySelectorAll<HTMLButtonElement>("[data-vote]").forEach((button) => button.addEventListener("click", () => {
      if (!isFixture() || state.busy) return;
      const number = maintainerNumber(state.role);
      const card = selectedCard();
      const vote = button.dataset.vote as DemoVote;
      if (number === undefined || card === undefined || !pendingCards().some((item) => item.key === card.key)) return;
      const votes = votesFor(card);
      if (votes[number] !== undefined || voteOutcome(votes) !== undefined) return;
      votes[number] = vote;
      storage.setItem(voteKey(card), JSON.stringify(votes));
      state.message = `Maintainer #${number} recorded ${vote === "approve" ? "an" : "a"} ${vote} demo vote. No live registry was changed.`;
      render();
    }));
    root.querySelector<HTMLButtonElement>("[data-apply-outcome]")?.addEventListener("click", () => {
      const card = selectedCard();
      if (card === undefined || !isFixture()) return;
      const expected = voteOutcome(votesFor(card));
      if (expected === undefined) return;
      void runBusy(async () => {
        const fresh = await client.loadReviewBoard();
        const current = buildReviewCards(fresh).filter(isGuidedCard).find((item) => item.key === card.key);
        if (!isGuidedWorkspace(fresh)
          || fresh.workspaceInstanceId !== state.board?.workspaceInstanceId
          || !isGuidedCard(card)
          || (current !== undefined && !hasKnownStatus(current))
          || current?.status !== card.status) {
          throw new Error("The fixture changed. Refresh records and review this request again.");
        }
        const action = expected === "reject" ? "archive" : card.status === "proposed" ? "approve" : "activate";
        if (!(await confirm(`Apply ${action} to the local fixture for ${card.label}? This is not a signed committee action or ledger transaction.`))) return;
        await client.mutate(card.target, card.id, action);
        await reload();
        state.message = `${card.label}: ${action} applied to the local fixture. ${action === "approve" ? "A new activation vote is now required." : "Switch to the applicant role to inspect the result."}`;
      });
    });
    root.querySelector<HTMLButtonElement>("[data-refresh]")?.addEventListener("click", () => { void reload(); });
    root.querySelector<HTMLButtonElement>("[data-reset-votes]")?.addEventListener("click", () => {
      if (!isFixture()) return;
      const prefix = voteKeyPrefix();
      void Promise.resolve(confirm("Clear this browser's demo votes? Registry fixture records will remain unchanged.")).then((approved) => {
        if (!approved) return;
        const keys = Array.from({ length: storage.length }, (_, index) => storage.key(index));
        for (const key of keys) {
          if (key?.startsWith(prefix)) storage.removeItem(key);
        }
        state.message = "Browser demo votes cleared. Fixture records were not changed.";
        render();
      });
    });
  };

  const syncRoleFromLocation = (): void => {
    state.role = roleFromHash(window.location.hash);
    state.message = undefined;
    render();
  };
  window.addEventListener("popstate", syncRoleFromLocation);
  window.addEventListener("hashchange", syncRoleFromLocation);
  render();
  if (isLoopback && apiIsLoopback) void reload();
};

const root = document.querySelector<HTMLElement>("#app");
if (root !== null) createGuidedDemoApp(root);
