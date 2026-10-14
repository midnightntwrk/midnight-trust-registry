import type {
  TrustRegistryApiMutationContext,
  TrustRegistryApiSignedMutationRequest,
  GovernedMembershipAction,
  GovernedMembershipSignatureRequest,
  GovernedThresholds,
  PreparedGovernedMembershipAction,
  PreparedGovernedPolicyAction,
  TrustRegistryApiApplicationAction,
} from "@midnight-ntwrk/trust-registry-api";

import {
  TrustRegistryAdminConsoleApiError,
  TrustRegistryAdminConsoleClient,
  normalizeApiBaseUrl,
  type GovernedProposalRole,
  type PreparedGovernedProposal,
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
  signedBusy: boolean;
  signedContext: TrustRegistryApiMutationContext | undefined;
  proposalRole: GovernedProposalRole;
  proposalAuthorizationId: string;
  proposalEvidenceJson: string;
  proposalPrepared: PreparedGovernedProposal | undefined;
  proposalSignersJson: string;
  proposalVerifierSignature: string;
  policyThresholds: GovernedThresholds;
  policyPhase: "thresholds" | "evidence-verifier" | undefined;
  policyPrepared: PreparedGovernedPolicyAction | undefined;
  policyPreparedThresholds: GovernedThresholds | undefined;
  policySignersJson: string;
  policyRegistrationPending: boolean;
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
  card.status === "proposed" ? "approve"
    : card.status === "authorized" ? "activate"
      : card.status === "active" ? "suspend"
        : card.status === "suspended" ? "revoke" : undefined;

const assertExactFields = (value: unknown, fields: readonly string[], label: string): void => {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) {
    throw new Error(`${label} must contain only the redacted ${fields.join(", ")} fields.`);
  }
};

const assertRedactedEvidence = (value: unknown): void => {
  assertExactFields(value, ["envelope", "commitment", "signature"], "Application evidence");
  const submission = value as Record<string, unknown>;
  if (typeof submission.commitment !== "string") {
    throw new Error("Application evidence commitment must be a string.");
  }
  assertExactFields(submission.envelope, [
    "version", "registryId", "applicationId", "subjectDid", "role", "policyId", "policyVersion",
    "scopeCommitment", "governedResource", "evidenceVerifierDid", "verifiedAt", "expiresAt",
    "challengeHash", "presentationHash", "claimsCommitment",
  ], "Application evidence envelope");
  const envelope = submission.envelope as Record<string, unknown>;
  for (const [key, field] of Object.entries(envelope)) {
    if (key !== "governedResource" && typeof field !== "string") {
      throw new Error(`Application evidence ${key} must be a string.`);
    }
  }
  assertExactFields(envelope.governedResource,
    ["type", "id"], "Governed resource");
  const resource = envelope.governedResource as Record<string, unknown>;
  if (typeof resource.type !== "string" || typeof resource.id !== "string") {
    throw new Error("Governed resource values must be strings.");
  }
  assertExactFields(submission.signature, ["keyId", "algorithm", "value"], "Evidence signature");
  const signature = submission.signature as Record<string, unknown>;
  if (Object.values(signature).some((field) => typeof field !== "string")) {
    throw new Error("Evidence signature values must be strings.");
  }
};

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
  for (const signer of parsed) {
    assertExactFields(signer, ["keyId", "publicKey", "signature"], "External signer");
    assertExactFields(signer.publicKey, ["x", "y"], "External signer public key");
    if (typeof signer.keyId !== "string" || typeof signer.signature !== "string"
      || typeof signer.publicKey.x !== "string" || typeof signer.publicKey.y !== "string") {
      throw new Error("External signer identifiers, public coordinates, and signature must be strings.");
    }
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
    signedBusy: false,
    signedContext: undefined,
    proposalRole: "issuer",
    proposalAuthorizationId: "",
    proposalEvidenceJson: "",
    proposalPrepared: undefined,
    proposalSignersJson: "",
    proposalVerifierSignature: "",
    policyThresholds: { default: "2", emergency: "2", archival: "2" },
    policyPhase: undefined,
    policyPrepared: undefined,
    policyPreparedThresholds: undefined,
    policySignersJson: "",
    policyRegistrationPending: false,
    selectedKey: undefined,
  };
  let signedContextRequestId = 0;

  const setState = (next: Partial<AppState>) => {
    Object.assign(state, next);
    render();
  };

  const getClient = (): TrustRegistryAdminConsoleClient =>
    new TrustRegistryAdminConsoleClient(state.apiBase, fetchImpl);

  const loadSignedContext = async () => {
    if (state.signedBusy) return;
    const requestId = ++signedContextRequestId;
    setState({ signedBusy: true, signedContext: undefined, error: undefined, flash: undefined });
    try {
      const signedContext = await getClient().loadMutationContext();
      if (requestId === signedContextRequestId) setState({ signedContext });
    } catch (error) {
      if (requestId === signedContextRequestId) setState({ error: formatApiError(error) });
    } finally {
      if (requestId === signedContextRequestId) setState({ signedBusy: false });
    }
  };

  const submitSignedAction = async (raw: string) => {
    if (state.signedBusy || state.signedContext === undefined) return;
    let candidate: unknown;
    try {
      candidate = JSON.parse(raw);
    } catch {
      setState({ error: "Signed mutation envelope must be valid JSON." });
      return;
    }
    if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
      setState({ error: "Paste an externally signed maintainer action envelope." });
      return;
    }
    const parsed = candidate as Partial<TrustRegistryApiSignedMutationRequest>;
    if (parsed.intent === null || typeof parsed.intent !== "object"
      || parsed.intent?.actorRole !== "maintainer"
      || parsed.signature === null || typeof parsed.signature !== "object"
      || parsed.operation === null || typeof parsed.operation !== "object"
      || parsed.operation?.operation === "submit") {
      setState({ error: "Paste an externally signed maintainer action envelope." });
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
    if (!await confirm(`Submit signed ${parsed.operation.operation} for ${intent.targetId}?`)) return;
    if (state.apiBase !== apiBase || state.signedContext !== context) {
      setState({ error: "Signing context changed. Load a fresh context and sign again." });
      return;
    }
    setState({ signedBusy: true, error: undefined, flash: undefined });
    try {
      const result = await getClient().submitSignedMutation(parsed as TrustRegistryApiSignedMutationRequest);
      if (state.apiBase !== apiBase) return;
      state.signedContext = undefined;
      await refreshBoard(`Signed ${result.operation.operation} accepted. Load a new context for the next action.`);
    } catch (error) {
      if (state.apiBase === apiBase) setState({ signedContext: undefined, error: formatApiError(error) });
    } finally {
      setState({ signedBusy: false });
    }
  };

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
        proposalPrepared: undefined,
        policyPhase: undefined,
        policyPrepared: undefined,
        policyPreparedThresholds: undefined,
        policySignersJson: "",
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
        proposalPrepared: undefined,
        policyPhase: undefined,
        policyPrepared: undefined,
        policyPreparedThresholds: undefined,
        policySignersJson: "",
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

  const preparePolicyAction = async (phase: "thresholds" | "evidence-verifier") => {
    if (state.loading || state.publishing || state.governedBusy) return;
    const thresholds = { ...state.policyThresholds };
    if (phase === "thresholds" && Object.values(thresholds).some((value) =>
      !/^(0|[1-9][0-9]*)$/u.test(value))) {
      setState({ error: "Thresholds must be canonical nonnegative integers." });
      return;
    }
    setState({ governedBusy: true, policyPhase: undefined, policyPrepared: undefined,
      policyPreparedThresholds: undefined, policySignersJson: "", error: undefined, flash: undefined });
    try {
      const prepared = phase === "thresholds"
        ? await getClient().prepareThresholdRevision(thresholds)
        : await getClient().prepareEvidenceVerifierRegistration();
      setState({ governedBusy: false, policyPhase: phase, policyPrepared: prepared,
        policyPreparedThresholds: phase === "thresholds" ? thresholds : undefined });
    } catch (error) {
      setState({ governedBusy: false, error: formatApiError(error) });
    }
  };

  const submitPolicyAction = async () => {
    if (state.loading || state.publishing || state.governedBusy
      || state.policyPrepared === undefined || state.policyPhase === undefined) return;
    const prepared = state.policyPrepared;
    const phase = state.policyPhase;
    const thresholds = state.policyPreparedThresholds;
    let signers: GovernedMembershipSignatureRequest["signers"];
    try {
      signers = parseSignerInput(state.policySignersJson);
      if (phase === "thresholds" && (thresholds === undefined
        || Object.keys(thresholds).some((key) =>
          thresholds[key as keyof GovernedThresholds] !== state.policyThresholds[key as keyof GovernedThresholds]))) {
        throw new Error("Threshold values changed. Prepare a fresh action before signing.");
      }
    } catch (error) {
      setState({ error: formatApiError(error) });
      return;
    }
    if (!(await confirm(`Submit ${signers.length} external signatures for ${phase}?`))) return;
    if (state.policyPrepared !== prepared || state.policyPhase !== phase) return;
    setState({ governedBusy: true, error: undefined, flash: undefined });
    try {
      const receipt = phase === "thresholds"
        ? await getClient().submitThresholdRevision({ thresholds: thresholds!, prepared, signers })
        : await getClient().submitEvidenceVerifierRegistration({ prepared, signers });
      const pending = phase === "thresholds";
      setState({ policyPhase: undefined, policyPrepared: undefined, policyPreparedThresholds: undefined,
        policySignersJson: "", policyRegistrationPending: pending });
      await refreshBoard(pending
        ? `Policy revision accepted: ${receipt.eventHash}. Register the evidence-verifier key under the new policy before accepting new applications.`
        : `Evidence-verifier registration accepted: ${receipt.eventHash}. Network finality is not implied.`);
      setState({ governedBusy: false });
    } catch (error) {
      setState({ governedBusy: false, error: formatApiError(error),
        ...(error instanceof TrustRegistryAdminConsoleApiError && error.problem.status === 409
          ? { policyPhase: undefined, policyPrepared: undefined, policyPreparedThresholds: undefined,
            policySignersJson: "" }
          : {}) });
    }
  };

  const prepareProposal = async () => {
    if (state.loading || state.publishing || state.governedBusy) return;
    const role = state.proposalRole;
    const id = state.proposalAuthorizationId.trim();
    if (id.length === 0) {
      setState({ error: `Enter the exact ${role} ${role === "maintainer" ? "membership" : "authorization"} ID.` });
      return;
    }
    const evidenceJson = state.proposalEvidenceJson;
    let evidence: unknown;
    try {
      evidence = JSON.parse(evidenceJson);
      assertRedactedEvidence(evidence);
    } catch {
      setState({ error: "Application evidence must be a redacted envelope, commitment, and signature JSON object without raw VC/VP fields." });
      return;
    }
    if ((evidence as { envelope: { role: string } }).envelope.role !== role) {
      setState({ error: "Application evidence role must match the selected proposal role." });
      return;
    }
    setState({ governedBusy: true, proposalPrepared: undefined, proposalSignersJson: "",
      proposalVerifierSignature: "", error: undefined, flash: undefined });
    try {
      const prepared = await getClient().prepareProposal(role, id, evidence);
      setState({ governedBusy: false, proposalPrepared:
        state.proposalRole === role && state.proposalAuthorizationId.trim() === id
          && state.proposalEvidenceJson === evidenceJson
          ? prepared : undefined });
    } catch (error) {
      setState({ governedBusy: false, error: formatApiError(error) });
    }
  };

  const submitProposal = async () => {
    if (state.loading || state.publishing || state.governedBusy || state.proposalPrepared === undefined) return;
    const role = state.proposalRole;
    const id = state.proposalAuthorizationId.trim();
    const evidenceJson = state.proposalEvidenceJson;
    const verifierSignature = state.proposalVerifierSignature;
    let evidence: unknown;
    let signers: GovernedMembershipSignatureRequest["signers"];
    try {
      evidence = JSON.parse(evidenceJson);
      assertRedactedEvidence(evidence);
      if ((evidence as { envelope: { role: string } }).envelope.role !== role) {
        throw new Error("Application evidence role must match the selected proposal role.");
      }
      signers = parseSignerInput(state.proposalSignersJson);
      if (!/^0x[0-9a-f]+$/u.test(verifierSignature)) {
        throw new Error("Provide the registered evidence-verifier JubJub signature as hex.");
      }
    } catch (error) {
      setState({ error: formatApiError(error) });
      return;
    }
    const prepared = state.proposalPrepared;
    if (prepared === undefined) return;
    if (!(await confirm(`Submit ${signers.length} maintainer signatures and evidence-verifier signature for ${role} ${id}?`))) return;
    if (state.proposalPrepared !== prepared || state.proposalRole !== role || state.proposalAuthorizationId.trim() !== id
      || state.proposalEvidenceJson !== evidenceJson || state.proposalVerifierSignature !== verifierSignature) return;
    setState({ governedBusy: true, error: undefined, flash: undefined });
    try {
      const receipt = await getClient().submitProposal(role, id, {
        evidence,
        prepared,
        signers,
        evidenceVerifierSignature: verifierSignature,
      });
      await refreshBoard(`Compact ${role} proposal accepted: ${receipt.eventHash}. Network finality is not implied.`);
      setState({ governedBusy: false, proposalAuthorizationId: "", proposalEvidenceJson: "",
        proposalPrepared: undefined, proposalSignersJson: "", proposalVerifierSignature: "" });
    } catch (error) {
      setState({ governedBusy: false, error: formatApiError(error),
        ...(error instanceof TrustRegistryAdminConsoleApiError && error.problem.status === 409
          ? { proposalPrepared: undefined, proposalSignersJson: "", proposalVerifierSignature: "" }
          : {}) });
    }
  };

  const resolveProposal = async () => {
    if (state.loading || state.publishing || state.governedBusy) return;
    const role = state.proposalRole;
    const id = state.proposalAuthorizationId.trim();
    if (id.length === 0) {
      setState({ error: `Enter the exact ${role} ${role === "maintainer" ? "membership" : "authorization"} ID.` });
      return;
    }
    let evidence: unknown;
    try {
      evidence = JSON.parse(state.proposalEvidenceJson);
      assertRedactedEvidence(evidence);
    } catch {
      setState({ error: "Application evidence must be a redacted envelope, commitment, and signature JSON object without raw VC/VP fields." });
      return;
    }
    if ((evidence as { envelope: { role: string } }).envelope.role !== role) {
      setState({ error: "Application evidence role must match the selected proposal role." });
      return;
    }
    setState({ governedBusy: true, error: undefined, flash: undefined });
    try {
      const result = await getClient().resolveProposal(role, id, evidence);
      setState({ governedBusy: false, flash: result.state === "observed"
        ? `Compact ${role} proposal observed: ${result.eventHash}. Network finality is not implied.`
        : "Proposal not observed. This does not prove failure; do not resubmit automatically." });
    } catch (error) {
      setState({ governedBusy: false, error: formatApiError(error) });
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
      signedContextRequestId += 1;
      setState({ apiBase, signedBusy: false, signedContext: undefined,
        policyPhase: undefined, policyPrepared: undefined, policyPreparedThresholds: undefined,
        policySignersJson: "", policyRegistrationPending: false });
      void refreshBoard();
    });

    root.querySelector<HTMLButtonElement>("[data-refresh]")?.addEventListener("click", () => {
      if (state.governedBusy) return;
      void refreshBoard();
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
      void submitSignedAction(raw);
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

    root.querySelectorAll<HTMLInputElement>("[data-policy-threshold]").forEach((input) => {
      input.addEventListener("input", () => {
        const field = input.dataset.policyThreshold as keyof GovernedThresholds;
        state.policyThresholds[field] = input.value;
        state.policyPhase = undefined;
        state.policyPrepared = undefined;
        state.policyPreparedThresholds = undefined;
        root.querySelector("[data-policy-context]")?.remove();
        root.querySelector("[data-policy-submit]")?.remove();
      });
    });
    root.querySelector<HTMLButtonElement>("[data-policy-prepare-thresholds]")?.addEventListener("click", () => {
      void preparePolicyAction("thresholds");
    });
    root.querySelector<HTMLButtonElement>("[data-policy-prepare-verifier]")?.addEventListener("click", () => {
      void preparePolicyAction("evidence-verifier");
    });
    root.querySelector<HTMLTextAreaElement>("[data-policy-signers]")?.addEventListener("input", (event) => {
      state.policySignersJson = (event.currentTarget as HTMLTextAreaElement).value;
    });
    root.querySelector<HTMLFormElement>("[data-policy-submit]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      void submitPolicyAction();
    });

    root.querySelector<HTMLInputElement>("[data-proposal-id]")?.addEventListener("input", (event) => {
      state.proposalAuthorizationId = (event.currentTarget as HTMLInputElement).value;
      state.proposalPrepared = undefined;
      root.querySelector("[data-proposal-submit]")?.remove();
      root.querySelector("[data-proposal-context]")?.remove();
    });
    root.querySelector<HTMLSelectElement>("[data-proposal-role]")?.addEventListener("change", (event) => {
      setState({ proposalRole: (event.currentTarget as HTMLSelectElement).value as GovernedProposalRole,
        proposalPrepared: undefined, proposalSignersJson: "", proposalVerifierSignature: "" });
    });
    root.querySelector<HTMLTextAreaElement>("[data-proposal-evidence]")?.addEventListener("input", (event) => {
      state.proposalEvidenceJson = (event.currentTarget as HTMLTextAreaElement).value;
      state.proposalPrepared = undefined;
      root.querySelector("[data-proposal-submit]")?.remove();
      root.querySelector("[data-proposal-context]")?.remove();
    });
    root.querySelector<HTMLFormElement>("[data-proposal-prepare]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      void prepareProposal();
    });
    root.querySelector<HTMLButtonElement>("[data-proposal-resolve]")?.addEventListener("click", () => {
      void resolveProposal();
    });
    root.querySelector<HTMLTextAreaElement>("[data-proposal-signers]")?.addEventListener("input", (event) => {
      state.proposalSignersJson = (event.currentTarget as HTMLTextAreaElement).value;
    });
    root.querySelector<HTMLInputElement>("[data-proposal-verifier-signature]")?.addEventListener("input", (event) => {
      state.proposalVerifierSignature = (event.currentTarget as HTMLInputElement).value;
    });
    root.querySelector<HTMLFormElement>("[data-proposal-submit]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      void submitProposal();
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
    const previousSignedEnvelope = root.querySelector<HTMLTextAreaElement>("[data-signed-submit] [name='signedEnvelope']")?.value;
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
        <section class="proposal-panel governed-panel">
          <div>
            <p class="eyebrow">Signed workspace action</p>
            <h2>Submit an external maintainer intent</h2>
            <p>Load the current workspace context, sign a maintainer action outside this browser, and paste only the signed envelope. This local workspace path is separate from Compact quorum governance and never handles private keys.</p>
          </div>
          <button class="button secondary" type="button" data-signed-context${state.signedBusy ? " disabled" : ""}>Load signing context</button>
          ${state.signedContext === undefined ? "" : `<pre class="governed-context mono">${escapeHtml(JSON.stringify(state.signedContext, null, 2))}</pre>`}
          <form data-signed-submit>
            <label>Externally signed envelope
              <textarea class="input mono governed-signers" name="signedEnvelope" spellcheck="false" autocomplete="off" required></textarea>
            </label>
            <button class="button" type="submit"${state.signedBusy || state.signedContext === undefined ? " disabled" : ""}>Submit signed action</button>
          </form>
        </section>
        <section class="proposal-panel governed-panel">
          <div>
            <p class="eyebrow">Membership application</p>
            <h2>Submit a governed proposal</h2>
            <p>Use a redacted, signed evidence envelope from the applicant. Maintainers and the registered evidence verifier sign outside this browser; no private keys or raw VC/VP claims belong here.</p>
          </div>
          <form data-proposal-prepare>
            <label>Proposal role
              <select class="input" data-proposal-role${state.governedBusy ? " disabled" : ""}>
                ${(["issuer", "verifier", "auditor", "maintainer"] as const).map((role) =>
                  `<option value="${role}"${state.proposalRole === role ? " selected" : ""}>${role}</option>`).join("")}
              </select>
            </label>
            <label>${state.proposalRole === "maintainer" ? "Maintainer membership" : "Authorization"} ID
              <input class="input mono" data-proposal-id value="${escapeHtml(state.proposalAuthorizationId)}" placeholder="exact ${state.proposalRole === "maintainer" ? "membership" : "authorization"} ID" autocomplete="off"${state.governedBusy ? " disabled" : ""} />
            </label>
            <label>Redacted application evidence JSON
              <textarea class="input mono proposal-evidence" data-proposal-evidence spellcheck="false" placeholder='{"envelope":{...},"commitment":"0x...","signature":{...}}'${state.governedBusy ? " disabled" : ""}>${escapeHtml(state.proposalEvidenceJson)}</textarea>
            </label>
            <button class="button secondary" type="submit"${state.loading || state.publishing || state.governedBusy ? " disabled" : ""}>Prepare ${state.proposalRole} proposal</button>
            <button class="button secondary" type="button" data-proposal-resolve${state.loading || state.publishing || state.governedBusy ? " disabled" : ""}>Recover proposal receipt</button>
          </form>
          ${state.proposalPrepared === undefined ? "" : `
            <p>Sign this exact policy, sequence, and evidence context. If the ledger or evidence changes, prepare again.</p>
            <pre class="governed-context mono" data-proposal-context>${escapeHtml(JSON.stringify(state.proposalPrepared, null, 2))}</pre>
            <form data-proposal-submit>
              <label>External maintainer signer entries as JSON array
                <textarea class="input mono governed-signers" data-proposal-signers spellcheck="false"${state.governedBusy ? " disabled" : ""}>${escapeHtml(state.proposalSignersJson)}</textarea>
              </label>
              <label>Registered evidence-verifier JubJub signature (hex)
                <input class="input mono" data-proposal-verifier-signature value="${escapeHtml(state.proposalVerifierSignature)}" autocomplete="off" spellcheck="false"${state.governedBusy ? " disabled" : ""} />
              </label>
              <button class="button" type="submit"${state.loading || state.publishing || state.governedBusy ? " disabled" : ""}>Submit signed proposal</button>
            </form>
          `}
        </section>
        <section class="proposal-panel governed-panel">
          <div>
            <p class="eyebrow">Governance policy</p>
            <h2>Revise maintainer quorum</h2>
            <p>Prepare a threshold revision for external maintainer signatures. After Compact accepts it, separately register the evidence-verifier key under the new policy. Neither step implies network finality.</p>
            ${state.policyRegistrationPending ? `<p class="alert error">Policy revision accepted locally; evidence-verifier registration is still required before new applications.</p>` : ""}
          </div>
          <div class="actions">
            ${(["default", "emergency", "archival"] as const).map((field) => `
              <label>${field} threshold
                <input class="input mono" type="number" min="1" max="5" step="1" data-policy-threshold="${field}" value="${escapeHtml(state.policyThresholds[field])}"${state.governedBusy ? " disabled" : ""} />
              </label>
            `).join("")}
          </div>
          <div class="actions">
            <button class="button secondary" type="button" data-policy-prepare-thresholds${state.loading || state.publishing || state.governedBusy ? " disabled" : ""}>Prepare threshold revision</button>
            <button class="button secondary" type="button" data-policy-prepare-verifier${state.loading || state.publishing || state.governedBusy ? " disabled" : ""}>Prepare evidence-verifier registration</button>
          </div>
          ${state.policyPrepared === undefined ? "" : `
            <p>Sign this exact ${state.policyPhase === "thresholds" ? "old-policy revision" : "new-policy registration"} context outside the browser. Changed policy or sequence requires fresh signatures.</p>
            <pre class="governed-context mono" data-policy-context>${escapeHtml(JSON.stringify(state.policyPrepared, null, 2))}</pre>
            <form data-policy-submit>
              <label>External maintainer signer entries as JSON array
                <textarea class="input mono governed-signers" data-policy-signers spellcheck="false"${state.governedBusy ? " disabled" : ""}>${escapeHtml(state.policySignersJson)}</textarea>
              </label>
              <button class="button" type="submit"${state.loading || state.publishing || state.governedBusy ? " disabled" : ""}>Submit signed ${state.policyPhase === "thresholds" ? "revision" : "registration"}</button>
            </form>
          `}
        </section>
        <section class="workspace">
          <div class="board">
            ${REVIEW_STATUSES.map((status) => renderColumn(status, groupedCards[status])).join("")}
          </div>
          ${renderDetailPanel()}
        </section>
      </main>
    `;
    if (previousSignedEnvelope !== undefined) {
      const currentEnvelope = root.querySelector<HTMLTextAreaElement>("[data-signed-submit] [name='signedEnvelope']");
      if (currentEnvelope !== null) currentEnvelope.value = previousSignedEnvelope;
    }
    bindEvents();
  };

  render();
  void refreshBoard();
};
