import { Buffer } from "node:buffer";
import { once } from "node:events";
import { isAbsolute } from "node:path";

import { createLocalNetworkDeploymentActionReader, getLocalNetworkProfile } from "@midnight-ntwrk/trust-registry-integration";

import {
  createSnapshotFileSource,
  createWorkspaceFileSource,
} from "./source.js";
import {
  assertLocalApiImageSourceRevision,
  assertApprovedDeploymentImage,
  assertApprovedPlanCoversGovernanceCount,
  createApprovedLocalLedgerRuntimeSource,
  loadApprovedLocalLedgerRuntimePlan,
  loadApprovedLocalLedgerRuntimePlanWithDigest,
} from "./local-ledger-runtime.js";
import { createTrustRegistryApiServer } from "./server.js";
import { localApiOrigin, observeLocalApiCurrentReads } from "./local-ledger-api-observation.js";
import { createPortalStaticHandler } from "./portal-static.js";
import {
  resolveCompactProposalEvidenceSnapshot,
  type FinalizedProposalLedgerReader,
  type ProposalRole,
} from "./compact-proposal-observation.js";
import { FileProposalSubmissionJournal } from "./proposal-submission-journal.js";
import { assessProposalRecoveryCandidate } from "./proposal-recovery-candidate.js";
import { draftProposalRecoveryDecision, loadApprovedProposalRecoveryDecision,
  proposalRecoveryCandidateDigest } from "./proposal-recovery-decision.js";

const PROPOSAL_ROLES = ["issuer", "verifier", "auditor", "maintainer", "recognition"] as const;

const HELP_TEXT = `Usage:
  trust-registry-api serve (--snapshot PATH | --workspace PATH | --local-ledger-plan PATH) [--host HOST] [--port PORT]
    [--local-ledger-signature PATH --local-ledger-keyring DIRECTORY --local-ledger-reviewer FINGERPRINT]
    [--cluster-bind]
    [--serve-portals]
    [--unsafe-demo-mutations]
  trust-registry-api check-local-ledger-plan --local-ledger-plan PATH --local-ledger-signature PATH
    --local-ledger-keyring DIRECTORY --local-ledger-reviewer FINGERPRINT
  trust-registry-api observe-local-ledger-api --local-ledger-plan PATH --local-ledger-signature PATH
    --local-ledger-keyring DIRECTORY --local-ledger-reviewer FINGERPRINT --api-origin http://127.0.0.1:PORT
  trust-registry-api observe-local-proposal --local-ledger-plan PATH --local-ledger-signature PATH
    --local-ledger-keyring DIRECTORY --local-ledger-reviewer FINGERPRINT
    --role issuer|verifier|auditor|maintainer|recognition --authorization-id ID
  trust-registry-api init-local-proposal-journal --local-ledger-plan PATH --local-ledger-signature PATH
    --local-ledger-keyring DIRECTORY --local-ledger-reviewer FINGERPRINT
    --submission-journal ABSOLUTE_PATH
  trust-registry-api reconcile-local-proposal --local-ledger-plan PATH --local-ledger-signature PATH
    --local-ledger-keyring DIRECTORY --local-ledger-reviewer FINGERPRINT
    --role issuer|verifier|auditor|maintainer|recognition --authorization-id ID
    --submission-journal ABSOLUTE_PATH
  trust-registry-api inspect-local-proposal-recovery --local-ledger-plan PATH --local-ledger-signature PATH
    --local-ledger-keyring DIRECTORY --local-ledger-reviewer FINGERPRINT
    --role issuer|verifier|auditor|maintainer|recognition --authorization-id ID
    --submission-journal ABSOLUTE_PATH
  trust-registry-api draft-local-proposal-recovery-decision --local-ledger-plan PATH --local-ledger-signature PATH
    --local-ledger-keyring DIRECTORY --local-ledger-reviewer FINGERPRINT
    --role issuer|verifier|auditor|maintainer|recognition --authorization-id ID
    --submission-journal ABSOLUTE_PATH --finality-evidence ABSOLUTE_PATH --evidence-reference REF
  trust-registry-api verify-local-proposal-recovery-decision --local-ledger-plan PATH --local-ledger-signature PATH
    --local-ledger-keyring DIRECTORY --local-ledger-reviewer FINGERPRINT
    --role issuer|verifier|auditor|maintainer|recognition --authorization-id ID
    --submission-journal ABSOLUTE_PATH --finality-evidence ABSOLUTE_PATH
    --recovery-decision ABSOLUTE_PATH --recovery-signature ABSOLUTE_PATH

Snapshot and workspace modes are fixture-only and require a loopback host.
Cluster binding requires signed local-ledger mode; it is not release qualification.
--serve-portals serves packaged admin/applicant assets from the API origin.
The plan check performs signed-pin and finalized snapshot readback without a listener.
It is not independent finality proof or release qualification.
The API observation compares current HTTP reads with the signed-plan source.
It is not actor-journey, process-identity, independent-finality, or release evidence.
An absent local proposal is not proof of failed submission and never permits retry.
Initialize an empty private journal against the signed deployment before submission.
Reconciliation requires that binding and updates only an exact-matching entry after verified readback.
Recovery inspection is read-only. Its candidate report never permits retry or journal release.
Draft and verify are also read-only: they do not authenticate chain finality or release a reservation.

Examples:
  trust-registry-api serve --snapshot ./tmp/demo-snapshot.json
  trust-registry-api serve --workspace ./tmp/operator-workspace.json --port 4400
  trust-registry-api serve --local-ledger-plan /run/trust-registry/api-plan.json --local-ledger-signature /run/trust-registry/api-plan.sig --local-ledger-keyring /run/trust-registry/reviewer-keyring --local-ledger-reviewer 0123456789ABCDEF0123456789ABCDEF01234567
  trust-registry-api serve --local-ledger-plan /run/trust-registry/api-plan.json --local-ledger-signature /run/trust-registry/api-plan.sig --local-ledger-keyring /run/trust-registry/reviewer-keyring --local-ledger-reviewer 0123456789ABCDEF0123456789ABCDEF01234567 --host 0.0.0.0 --cluster-bind
`;

export type TrustRegistryApiCliOptions = {
  command: "serve" | "check-local-ledger-plan" | "observe-local-ledger-api"
    | "observe-local-proposal" | "init-local-proposal-journal" | "reconcile-local-proposal"
    | "inspect-local-proposal-recovery" | "draft-local-proposal-recovery-decision"
    | "verify-local-proposal-recovery-decision";
  host: string;
  port: number;
  snapshotPath?: string;
  workspacePath?: string;
  localLedgerPlanPath?: string;
  localLedgerSignaturePath?: string;
  localLedgerKeyringDirectory?: string;
  localLedgerReviewerFingerprint?: string;
  apiOrigin?: string;
  proposalRole?: ProposalRole;
  authorizationId?: string;
  submissionJournalPath?: string;
  finalityEvidencePath?: string;
  evidenceReference?: string;
  recoveryDecisionPath?: string;
  recoverySignaturePath?: string;
  clusterBind?: boolean;
  servePortals?: boolean;
  unsafeDemoMutations?: boolean;
};

export const parseTrustRegistryApiCliArgs = (
  argv: readonly string[],
): TrustRegistryApiCliOptions => {
  const args = [...argv];
  const command = args.shift() ?? "serve";
  if (command === "--help" || command === "-h" || command === "help") {
    throw new Error(HELP_TEXT);
  }
  if (command !== "serve" && command !== "check-local-ledger-plan"
    && command !== "observe-local-ledger-api" && command !== "observe-local-proposal"
    && command !== "init-local-proposal-journal" && command !== "reconcile-local-proposal"
    && command !== "inspect-local-proposal-recovery"
    && command !== "draft-local-proposal-recovery-decision"
    && command !== "verify-local-proposal-recovery-decision") {
    throw new Error(`unknown command: ${command}\n\n${HELP_TEXT}`);
  }

  const options: TrustRegistryApiCliOptions = {
    command,
    host: "127.0.0.1",
    port: 4400,
  };
  const seen = new Set<string>();

  while (args.length > 0) {
    const arg = args.shift();
    if (arg !== "--help" && arg !== "-h" && arg !== undefined) {
      if (seen.has(arg)) throw new Error(`duplicate argument: ${arg}`);
      seen.add(arg);
    }
    switch (arg) {
      case "--host": {
        const host = args.shift();
        if (host === undefined) {
          throw new Error(`--host requires a value\n\n${HELP_TEXT}`);
        }
        options.host = host;
        break;
      }
      case "--port": {
        const port = args.shift();
        if (port === undefined) {
          throw new Error(`--port requires a value\n\n${HELP_TEXT}`);
        }
        options.port = Number.parseInt(port, 10);
        break;
      }
      case "--snapshot": {
        const snapshotPath = args.shift();
        if (snapshotPath === undefined) {
          throw new Error(`--snapshot requires a value\n\n${HELP_TEXT}`);
        }
        options.snapshotPath = snapshotPath;
        break;
      }
      case "--workspace": {
        const workspacePath = args.shift();
        if (workspacePath === undefined) {
          throw new Error(`--workspace requires a value\n\n${HELP_TEXT}`);
        }
        options.workspacePath = workspacePath;
        break;
      }
      case "--local-ledger-plan":
      case "--local-ledger-signature":
      case "--local-ledger-keyring":
      case "--local-ledger-reviewer": {
        const value = args.shift();
        if (value === undefined || value.length === 0) {
          throw new Error(`${arg} requires a value\n\n${HELP_TEXT}`);
        }
        if (arg === "--local-ledger-plan") options.localLedgerPlanPath = value;
        if (arg === "--local-ledger-signature") options.localLedgerSignaturePath = value;
        if (arg === "--local-ledger-keyring") options.localLedgerKeyringDirectory = value;
        if (arg === "--local-ledger-reviewer") options.localLedgerReviewerFingerprint = value;
        break;
      }
      case "--api-origin": {
        const origin = args.shift();
        if (origin === undefined || origin.length === 0) {
          throw new Error(`--api-origin requires a value\n\n${HELP_TEXT}`);
        }
        options.apiOrigin = localApiOrigin(origin);
        break;
      }
      case "--role": {
        const role = args.shift();
        if (role === undefined || !PROPOSAL_ROLES.some((candidate) => candidate === role)) {
          throw new Error(`--role requires an issuer, verifier, auditor, maintainer, or recognition value\n\n${HELP_TEXT}`);
        }
        options.proposalRole = role as ProposalRole;
        break;
      }
      case "--authorization-id": {
        const id = args.shift();
        if (id === undefined || id.length === 0 || id.length > 256 || id.trim() !== id || id.includes("\0")) {
          throw new Error(`--authorization-id requires a canonical ID of at most 256 characters\n\n${HELP_TEXT}`);
        }
        options.authorizationId = id;
        break;
      }
      case "--submission-journal": {
        const path = args.shift();
        if (path === undefined || !isAbsolute(path)) {
          throw new Error(`--submission-journal requires an absolute path\n\n${HELP_TEXT}`);
        }
        options.submissionJournalPath = path;
        break;
      }
      case "--finality-evidence":
      case "--recovery-decision":
      case "--recovery-signature": {
        const path = args.shift();
        if (path === undefined || !isAbsolute(path)) {
          throw new Error(`${arg} requires an absolute path\n\n${HELP_TEXT}`);
        }
        if (arg === "--finality-evidence") options.finalityEvidencePath = path;
        if (arg === "--recovery-decision") options.recoveryDecisionPath = path;
        if (arg === "--recovery-signature") options.recoverySignaturePath = path;
        break;
      }
      case "--evidence-reference": {
        const reference = args.shift();
        if (reference === undefined || !/^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,511}$/u.test(reference)
          || reference.toLowerCase().startsWith("demo:")) {
          throw new Error(`--evidence-reference requires a printable stable identifier\n\n${HELP_TEXT}`);
        }
        options.evidenceReference = reference;
        break;
      }
      case "--unsafe-demo-mutations":
        options.unsafeDemoMutations = true;
        break;
      case "--cluster-bind":
        options.clusterBind = true;
        break;
      case "--serve-portals":
        options.servePortals = true;
        break;
      case "--help":
      case "-h":
        throw new Error(HELP_TEXT);
      default:
        throw new Error(`unknown argument: ${arg}\n\n${HELP_TEXT}`);
    }
  }

  if ([options.snapshotPath, options.workspacePath, options.localLedgerPlanPath]
    .filter((value) => value !== undefined).length !== 1) {
    throw new Error(
      `exactly one of --snapshot, --workspace, or --local-ledger-plan is required\n\n${HELP_TEXT}`,
    );
  }
  const localEvidence = [options.localLedgerSignaturePath, options.localLedgerKeyringDirectory,
    options.localLedgerReviewerFingerprint];
  if (options.localLedgerPlanPath !== undefined
    ? localEvidence.some((value) => value === undefined) || options.unsafeDemoMutations === true
    : localEvidence.some((value) => value !== undefined)) {
    throw new Error("Local-ledger mode requires complete reviewer evidence and forbids demo mutations");
  }
  const recoveryCommand = command === "inspect-local-proposal-recovery"
    || command === "draft-local-proposal-recovery-decision"
    || command === "verify-local-proposal-recovery-decision";
  if (command === "check-local-ledger-plan" || command === "observe-local-ledger-api"
    || command === "observe-local-proposal" || command === "init-local-proposal-journal"
    || command === "reconcile-local-proposal" || recoveryCommand) {
    const allowed = new Set(["--local-ledger-plan", "--local-ledger-signature",
      "--local-ledger-keyring", "--local-ledger-reviewer"]);
    if (command === "observe-local-ledger-api") allowed.add("--api-origin");
    if (command === "observe-local-proposal" || command === "reconcile-local-proposal"
      || recoveryCommand) {
      allowed.add("--role");
      allowed.add("--authorization-id");
    }
    if (command === "reconcile-local-proposal" || command === "init-local-proposal-journal"
      || recoveryCommand) {
      allowed.add("--submission-journal");
    }
    if (command === "draft-local-proposal-recovery-decision"
      || command === "verify-local-proposal-recovery-decision") allowed.add("--finality-evidence");
    if (command === "draft-local-proposal-recovery-decision") allowed.add("--evidence-reference");
    if (command === "verify-local-proposal-recovery-decision") {
      allowed.add("--recovery-decision");
      allowed.add("--recovery-signature");
    }
    if (options.localLedgerPlanPath === undefined || [...seen].some((arg) => !allowed.has(arg))) {
      throw new Error("Local readback accepts only complete signed local-ledger evidence");
    }
    if (command === "observe-local-ledger-api" && options.apiOrigin === undefined) {
      throw new Error("Local API observation requires --api-origin");
    }
    if ((command === "observe-local-proposal" || command === "reconcile-local-proposal"
      || recoveryCommand)
      && (options.proposalRole === undefined || options.authorizationId === undefined
        || (command !== "observe-local-proposal" && options.submissionJournalPath === undefined))) {
      throw new Error("Local proposal readback requires --role and --authorization-id; journal operations also require --submission-journal");
    }
    if ((command === "draft-local-proposal-recovery-decision"
      || command === "verify-local-proposal-recovery-decision") && options.finalityEvidencePath === undefined) {
      throw new Error("Recovery decision commands require --finality-evidence");
    }
    if (command === "draft-local-proposal-recovery-decision" && options.evidenceReference === undefined) {
      throw new Error("Recovery decision draft requires --evidence-reference");
    }
    if (command === "verify-local-proposal-recovery-decision"
      && (options.recoveryDecisionPath === undefined || options.recoverySignaturePath === undefined)) {
      throw new Error("Recovery decision verification requires --recovery-decision and --recovery-signature");
    }
    if (command === "init-local-proposal-journal" && options.submissionJournalPath === undefined) {
      throw new Error("Local journal initialization requires --submission-journal");
    }
    return options;
  }
  if (options.apiOrigin !== undefined || options.proposalRole !== undefined
    || options.authorizationId !== undefined || options.submissionJournalPath !== undefined
    || options.finalityEvidencePath !== undefined || options.evidenceReference !== undefined
    || options.recoveryDecisionPath !== undefined || options.recoverySignaturePath !== undefined) {
    throw new Error("Observation arguments are not accepted by the serve command");
  }
  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
    throw new Error(`invalid port: ${String(options.port)}\n\n${HELP_TEXT}`);
  }
  if (options.host.trim().length === 0) {
    throw new Error(`--host must not be empty\n\n${HELP_TEXT}`);
  }
  if (options.clusterBind === true
    && (options.localLedgerPlanPath === undefined || options.host !== "0.0.0.0")) {
    throw new Error("--cluster-bind requires signed local-ledger mode on 0.0.0.0");
  }
  if (options.servePortals === true && options.localLedgerPlanPath === undefined) {
    throw new Error("--serve-portals requires signed local-ledger mode");
  }
  if (options.localLedgerPlanPath !== undefined
    && options.clusterBind !== true && !["127.0.0.1", "::1"].includes(options.host)) {
    throw new Error("Unqualified local-ledger mode requires a loopback host");
  }
  if (
    options.unsafeDemoMutations === true
    && !["127.0.0.1", "::1"].includes(options.host)
  ) {
    throw new Error("--unsafe-demo-mutations requires a loopback host");
  }
  if (options.localLedgerPlanPath === undefined
    && !["127.0.0.1", "::1"].includes(options.host)) {
    throw new Error("Fixture-backed API modes require a loopback host");
  }

  return options;
};

const loadCurrentProposalRecoveryCandidate = async (options: TrustRegistryApiCliOptions) => {
  const { plan, planSha256 } = await loadApprovedLocalLedgerRuntimePlanWithDigest({
    planPath: options.localLedgerPlanPath!,
    signaturePath: options.localLedgerSignaturePath!,
    keyringDirectory: options.localLedgerKeyringDirectory!,
    reviewerFingerprint: options.localLedgerReviewerFingerprint!,
    requireApiRuntimePin: true,
    requireApprovalChain: true,
  });
  const source = await createApprovedLocalLedgerRuntimeSource(plan);
  const snapshot = await source.loadSnapshot();
  const journal = new FileProposalSubmissionJournal(options.submissionJournalPath!);
  const { attempt, bindingDigest } = await journal.readBoundAttempt(
    snapshot.registry.registryId, plan.contractAddress, plan.expectedGenesisHash,
    options.proposalRole!, options.authorizationId!,
  );
  if (attempt === null) throw new Error("No private proposal reservation exists for recovery inspection");
  const reader = await createLocalNetworkDeploymentActionReader(plan);
  const view = await reader.readCurrentFinalizedLedger(plan.contractAddress);
  if (view === null) throw new Error("Pinned finalized local ledger view is unavailable");
  assertApprovedDeploymentImage(plan, view);
  assertApprovedPlanCoversGovernanceCount(plan, view.ledger.governanceActionCount);
  return assessProposalRecoveryCandidate({
    attempt, view, registryId: snapshot.registry.registryId, contractAddress: plan.contractAddress,
    planExpectedGenesisHash: plan.expectedGenesisHash, planSourceRevision: plan.sourceRevision,
    approvedPlanSha256: planSha256, journalBindingDigest: bindingDigest,
  });
};

export const runTrustRegistryApiCli = async (
  argv: readonly string[] = process.argv.slice(2),
): Promise<void> => {
  const options = parseTrustRegistryApiCliArgs(argv);
  if (options.command === "check-local-ledger-plan") {
    const plan = await loadApprovedLocalLedgerRuntimePlan({
      planPath: options.localLedgerPlanPath!,
      signaturePath: options.localLedgerSignaturePath!,
      keyringDirectory: options.localLedgerKeyringDirectory!,
      reviewerFingerprint: options.localLedgerReviewerFingerprint!,
      requireApiRuntimePin: true,
      requireApprovalChain: true,
    });
    const source = await createApprovedLocalLedgerRuntimeSource(plan);
    await source.loadSnapshot();
    process.stdout.write(`Signed local plan and finalized snapshot match (${plan.sourceRevision}); not release qualification.\n`);
    return;
  }
  if (options.command === "observe-local-ledger-api") {
    const { plan, planSha256 } = await loadApprovedLocalLedgerRuntimePlanWithDigest({
      planPath: options.localLedgerPlanPath!,
      signaturePath: options.localLedgerSignaturePath!,
      keyringDirectory: options.localLedgerKeyringDirectory!,
      reviewerFingerprint: options.localLedgerReviewerFingerprint!,
      requireApiRuntimePin: true,
      requireApprovalChain: true,
    });
    const source = await createApprovedLocalLedgerRuntimeSource(plan);
    const result = await observeLocalApiCurrentReads({ source, apiOrigin: options.apiOrigin!,
      expectedPlanSha256: planSha256 });
    process.stdout.write(`${JSON.stringify({ ...result, planSourceRevision: plan.sourceRevision,
      planSha256, planNotAfter: plan.notAfter,
      planContractAddress: plan.contractAddress,
      planExpectedGenesisHash: plan.expectedGenesisHash }, null, 2)}\n`);
    return;
  }
  if (options.command === "observe-local-proposal") {
    const plan = await loadApprovedLocalLedgerRuntimePlan({
      planPath: options.localLedgerPlanPath!,
      signaturePath: options.localLedgerSignaturePath!,
      keyringDirectory: options.localLedgerKeyringDirectory!,
      reviewerFingerprint: options.localLedgerReviewerFingerprint!,
      requireApiRuntimePin: true,
      requireApprovalChain: true,
    });
    const source = await createApprovedLocalLedgerRuntimeSource(plan);
    const snapshot = await source.loadSnapshot();
    const proposal = await resolveCompactProposalEvidenceSnapshot(
      source.readFinalizedProposalLedger, snapshot.registry.registryId,
      options.proposalRole!, options.authorizationId!,
      Buffer.from(plan.contractAddress.slice(2), "hex"),
    );
    const observation = proposal === null ? null : {
      eventHash: proposal.eventHash,
      evidenceCommitment: proposal.evidenceCommitment,
    };
    process.stdout.write(`${JSON.stringify({
      format: "tr-local-proposal-observation-v1",
      networkId: getLocalNetworkProfile().networkId,
      registryId: snapshot.registry.registryId,
      contractAddress: plan.contractAddress,
      role: options.proposalRole,
      authorizationId: options.authorizationId,
      status: observation === null ? "not-observed" : "present-and-verified",
      observation,
      retryPermitted: false,
      releaseQualified: false,
    }, null, 2)}\n`);
    return;
  }
  if (options.command === "reconcile-local-proposal") {
    const plan = await loadApprovedLocalLedgerRuntimePlan({
      planPath: options.localLedgerPlanPath!,
      signaturePath: options.localLedgerSignaturePath!,
      keyringDirectory: options.localLedgerKeyringDirectory!,
      reviewerFingerprint: options.localLedgerReviewerFingerprint!,
      requireApiRuntimePin: true,
      requireApprovalChain: true,
    });
    const source = await createApprovedLocalLedgerRuntimeSource(plan);
    const snapshot = await source.loadSnapshot();
    const journal = new FileProposalSubmissionJournal(options.submissionJournalPath!);
    await journal.assertDeploymentBinding(
      snapshot.registry.registryId, plan.contractAddress, plan.expectedGenesisHash,
    );
    const attempt = await journal.reconcile(options.proposalRole!, options.authorizationId!, async (role, id) => {
      const proposal = await resolveCompactProposalEvidenceSnapshot(
        source.readFinalizedProposalLedger, snapshot.registry.registryId, role, id,
        Buffer.from(plan.contractAddress.slice(2), "hex"),
      );
      return proposal === null ? null : {
        eventHash: proposal.eventHash,
        evidenceCommitment: proposal.evidenceCommitment,
      };
    });
    process.stdout.write(`${JSON.stringify({
      format: "tr-local-proposal-reconciliation-v1",
      networkId: getLocalNetworkProfile().networkId,
      registryId: snapshot.registry.registryId,
      contractAddress: plan.contractAddress,
      role: attempt.role,
      authorizationId: attempt.authorizationId,
      status: attempt.state === "observed" ? "observed" : "not-observed",
      state: attempt.state,
      eventHash: attempt.eventHash,
      evidenceCommitment: attempt.evidenceCommitment,
      retryPermitted: false,
      releaseQualified: false,
    }, null, 2)}\n`);
    return;
  }
  if (options.command === "inspect-local-proposal-recovery") {
    const result = await loadCurrentProposalRecoveryCandidate(options);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  if (options.command === "draft-local-proposal-recovery-decision") {
    const candidate = await loadCurrentProposalRecoveryCandidate(options);
    const draft = await draftProposalRecoveryDecision({ candidate,
      finalityEvidencePath: options.finalityEvidencePath!,
      evidenceReference: options.evidenceReference!,
      reviewerFingerprint: options.localLedgerReviewerFingerprint! });
    process.stdout.write(draft);
    return;
  }
  if (options.command === "verify-local-proposal-recovery-decision") {
    const candidate = await loadCurrentProposalRecoveryCandidate(options);
    const result = await loadApprovedProposalRecoveryDecision({ candidate,
      decisionPath: options.recoveryDecisionPath!,
      signaturePath: options.recoverySignaturePath!,
      finalityEvidencePath: options.finalityEvidencePath!,
      keyringDirectory: options.localLedgerKeyringDirectory!,
      reviewerFingerprint: options.localLedgerReviewerFingerprint! });
    process.stdout.write(`${JSON.stringify({ format: "tr-local-proposal-recovery-verification-v1",
      decisionSha256: result.decisionSha256,
      candidateSha256: proposalRecoveryCandidateDigest(candidate),
      reviewerFingerprint: result.decision.reviewerFingerprint,
      evidenceReference: result.decision.evidenceReference,
      finalityEvidenceSha256: result.decision.finalityEvidenceSha256,
      draftedAt: result.decision.draftedAt,
      finalityAuthenticated: false, releaseQualified: false, retryPermitted: false }, null, 2)}\n`);
    return;
  }
  if (options.command === "init-local-proposal-journal") {
    const plan = await loadApprovedLocalLedgerRuntimePlan({
      planPath: options.localLedgerPlanPath!,
      signaturePath: options.localLedgerSignaturePath!,
      keyringDirectory: options.localLedgerKeyringDirectory!,
      reviewerFingerprint: options.localLedgerReviewerFingerprint!,
      requireApiRuntimePin: true,
      requireApprovalChain: true,
    });
    const source = await createApprovedLocalLedgerRuntimeSource(plan);
    const snapshot = await source.loadSnapshot();
    const journal = new FileProposalSubmissionJournal(options.submissionJournalPath!);
    await journal.bindDeployment(snapshot.registry.registryId, plan.contractAddress, plan.expectedGenesisHash);
    process.stdout.write(`${JSON.stringify({
      format: "tr-local-proposal-journal-binding-v1",
      registryId: snapshot.registry.registryId,
      contractAddress: plan.contractAddress,
      status: "bound",
      releaseQualified: false,
    }, null, 2)}\n`);
    return;
  }
  const portalHandler = options.servePortals === true
    ? await createPortalStaticHandler("/app/portals")
    : undefined;
  let readFinalizedProposalLedger: FinalizedProposalLedgerReader | undefined;
  let localPlanSha256: string | undefined;
  const source = options.localLedgerPlanPath !== undefined
    ? await (async () => {
      const approved = await loadApprovedLocalLedgerRuntimePlanWithDigest({
        planPath: options.localLedgerPlanPath!,
        signaturePath: options.localLedgerSignaturePath!,
        keyringDirectory: options.localLedgerKeyringDirectory!,
        reviewerFingerprint: options.localLedgerReviewerFingerprint!,
        requireApiRuntimePin: options.clusterBind === true,
        requireApprovalChain: true,
      });
      const { plan } = approved;
      localPlanSha256 = approved.planSha256;
      if (options.clusterBind === true) {
        await assertLocalApiImageSourceRevision(plan.sourceRevision);
      }
      const localSource = await createApprovedLocalLedgerRuntimeSource(plan);
      await localSource.loadSnapshot();
      readFinalizedProposalLedger = localSource.readFinalizedProposalLedger;
      return localSource;
    })()
    : options.snapshotPath !== undefined
      ? createSnapshotFileSource(options.snapshotPath)
      : createWorkspaceFileSource(options.workspacePath!);

  const server = createTrustRegistryApiServer({
    source,
    ...(localPlanSha256 === undefined ? {} : { localPlanSha256 }),
    ...(readFinalizedProposalLedger === undefined ? {} : { readFinalizedProposalLedger }),
    ...(portalHandler === undefined ? {} : { nonApiGetHandler: portalHandler }),
    ...(options.clusterBind === true ? { corsPolicy: "none" as const } : {}),
    ...(options.unsafeDemoMutations === undefined ? {} : { allowUnsafeDemoMutations: options.unsafeDemoMutations }),
  });

  if (options.clusterBind === true) {
    server.headersTimeout = 10_000;
    server.requestTimeout = 15_000;
    server.keepAliveTimeout = 5_000;
    server.timeout = 20_000;
    server.maxConnections = 16;
  }

  server.listen(options.port, options.host);
  await once(server, "listening");
  process.stdout.write(
    `trust-registry-api listening on http://${options.host}:${options.port.toString()}\n`,
  );

  const shutdown = async (): Promise<void> => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error !== undefined) {
          reject(error);
          return;
        }
        resolve();
      });
    });
  };

  process.once("SIGINT", () => {
    void shutdown().catch((error) => {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`${message}\n`);
      process.exitCode = 1;
    });
  });
  process.once("SIGTERM", () => {
    void shutdown().catch((error) => {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`${message}\n`);
      process.exitCode = 1;
    });
  });

  await once(server, "close");
};
