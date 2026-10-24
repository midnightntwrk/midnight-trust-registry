import { once } from "node:events";

import {
  createSnapshotFileSource,
  createWorkspaceFileSource,
} from "./source.js";
import {
  assertLocalApiImageSourceRevision,
  createApprovedLocalLedgerRuntimeSource,
  loadApprovedLocalLedgerRuntimePlan,
} from "./local-ledger-runtime.js";
import { createTrustRegistryApiServer } from "./server.js";
import { localApiOrigin, observeLocalApiCurrentReads } from "./local-ledger-api-observation.js";
import { createPortalStaticHandler } from "./portal-static.js";
import {
  resolveCompactProposalObservation,
  type FinalizedProposalLedgerReader,
  type ProposalRole,
} from "./compact-proposal-observation.js";

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

Snapshot and workspace modes are fixture-only and require a loopback host.
Cluster binding requires signed local-ledger mode; it is not release qualification.
--serve-portals serves packaged admin/applicant assets from the API origin.
The plan check performs signed-pin and finalized snapshot readback without a listener.
It is not independent finality proof or release qualification.
The API observation compares current HTTP reads with the signed-plan source.
It is not actor-journey, process-identity, independent-finality, or release evidence.
An absent local proposal is not proof of failed submission and never permits retry.

Examples:
  trust-registry-api serve --snapshot ./tmp/demo-snapshot.json
  trust-registry-api serve --workspace ./tmp/operator-workspace.json --port 4400
  trust-registry-api serve --local-ledger-plan /run/trust-registry/api-plan.json --local-ledger-signature /run/trust-registry/api-plan.sig --local-ledger-keyring /run/trust-registry/reviewer-keyring --local-ledger-reviewer 0123456789ABCDEF0123456789ABCDEF01234567
  trust-registry-api serve --local-ledger-plan /run/trust-registry/api-plan.json --local-ledger-signature /run/trust-registry/api-plan.sig --local-ledger-keyring /run/trust-registry/reviewer-keyring --local-ledger-reviewer 0123456789ABCDEF0123456789ABCDEF01234567 --host 0.0.0.0 --cluster-bind
`;

export type TrustRegistryApiCliOptions = {
  command: "serve" | "check-local-ledger-plan" | "observe-local-ledger-api" | "observe-local-proposal";
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
    && command !== "observe-local-ledger-api" && command !== "observe-local-proposal") {
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
  if (command === "check-local-ledger-plan" || command === "observe-local-ledger-api"
    || command === "observe-local-proposal") {
    const allowed = new Set(["--local-ledger-plan", "--local-ledger-signature",
      "--local-ledger-keyring", "--local-ledger-reviewer"]);
    if (command === "observe-local-ledger-api") allowed.add("--api-origin");
    if (command === "observe-local-proposal") {
      allowed.add("--role");
      allowed.add("--authorization-id");
    }
    if (options.localLedgerPlanPath === undefined || [...seen].some((arg) => !allowed.has(arg))) {
      throw new Error("Local readback accepts only complete signed local-ledger evidence");
    }
    if (command === "observe-local-ledger-api" && options.apiOrigin === undefined) {
      throw new Error("Local API observation requires --api-origin");
    }
    if (command === "observe-local-proposal"
      && (options.proposalRole === undefined || options.authorizationId === undefined)) {
      throw new Error("Local proposal observation requires --role and --authorization-id");
    }
    return options;
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
    });
    const source = await createApprovedLocalLedgerRuntimeSource(plan);
    await source.loadSnapshot();
    process.stdout.write(`Signed local plan and finalized snapshot match (${plan.sourceRevision}); not release qualification.\n`);
    return;
  }
  if (options.command === "observe-local-ledger-api") {
    const plan = await loadApprovedLocalLedgerRuntimePlan({
      planPath: options.localLedgerPlanPath!,
      signaturePath: options.localLedgerSignaturePath!,
      keyringDirectory: options.localLedgerKeyringDirectory!,
      reviewerFingerprint: options.localLedgerReviewerFingerprint!,
      requireApiRuntimePin: true,
    });
    const source = await createApprovedLocalLedgerRuntimeSource(plan);
    const result = await observeLocalApiCurrentReads({ source, apiOrigin: options.apiOrigin! });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  if (options.command === "observe-local-proposal") {
    const plan = await loadApprovedLocalLedgerRuntimePlan({
      planPath: options.localLedgerPlanPath!,
      signaturePath: options.localLedgerSignaturePath!,
      keyringDirectory: options.localLedgerKeyringDirectory!,
      reviewerFingerprint: options.localLedgerReviewerFingerprint!,
      requireApiRuntimePin: true,
    });
    const source = await createApprovedLocalLedgerRuntimeSource(plan);
    const snapshot = await source.loadSnapshot();
    const observation = await resolveCompactProposalObservation(
      source.readFinalizedProposalLedger, snapshot.registry.registryId,
      options.proposalRole!, options.authorizationId!,
    );
    process.stdout.write(`${JSON.stringify({
      format: "tr-local-proposal-observation-v1",
      networkId: "undeployed",
      registryId: snapshot.registry.registryId,
      contractAddress: plan.contractAddress,
      role: options.proposalRole,
      authorizationId: options.authorizationId,
      status: observation === null ? "not-observed" : "observed",
      observation,
      retryPermitted: false,
      releaseQualified: false,
    }, null, 2)}\n`);
    return;
  }
  const portalHandler = options.servePortals === true
    ? await createPortalStaticHandler("/app/portals")
    : undefined;
  let readFinalizedProposalLedger: FinalizedProposalLedgerReader | undefined;
  const source = options.localLedgerPlanPath !== undefined
    ? await (async () => {
      const plan = await loadApprovedLocalLedgerRuntimePlan({
        planPath: options.localLedgerPlanPath!,
        signaturePath: options.localLedgerSignaturePath!,
        keyringDirectory: options.localLedgerKeyringDirectory!,
        reviewerFingerprint: options.localLedgerReviewerFingerprint!,
        requireApiRuntimePin: options.clusterBind === true,
      });
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
