import { once } from "node:events";

import {
  createSnapshotFileSource,
  createWorkspaceFileSource,
} from "./source.js";
import {
  createApprovedLocalLedgerRuntimeSource,
  loadApprovedLocalLedgerRuntimePlan,
} from "./local-ledger-runtime.js";
import { createTrustRegistryApiServer } from "./server.js";

const HELP_TEXT = `Usage:
  trust-registry-api serve (--snapshot PATH | --workspace PATH | --local-ledger-plan PATH) [--host HOST] [--port PORT]
    [--local-ledger-signature PATH --local-ledger-keyring DIRECTORY --local-ledger-reviewer FINGERPRINT]
    [--unsafe-demo-mutations]

Examples:
  trust-registry-api serve --snapshot ./tmp/demo-snapshot.json
  trust-registry-api serve --workspace ./tmp/operator-workspace.json --port 4400
  trust-registry-api serve --local-ledger-plan /run/trust-registry/api-plan.json --local-ledger-signature /run/trust-registry/api-plan.sig --local-ledger-keyring /run/trust-registry/reviewer-keyring --local-ledger-reviewer 0123456789ABCDEF0123456789ABCDEF01234567
`;

export type TrustRegistryApiCliOptions = {
  host: string;
  port: number;
  snapshotPath?: string;
  workspacePath?: string;
  localLedgerPlanPath?: string;
  localLedgerSignaturePath?: string;
  localLedgerKeyringDirectory?: string;
  localLedgerReviewerFingerprint?: string;
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
  if (command !== "serve") {
    throw new Error(`unknown command: ${command}\n\n${HELP_TEXT}`);
  }

  const options: TrustRegistryApiCliOptions = {
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
      case "--unsafe-demo-mutations":
        options.unsafeDemoMutations = true;
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
  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
    throw new Error(`invalid port: ${String(options.port)}\n\n${HELP_TEXT}`);
  }
  if (options.host.trim().length === 0) {
    throw new Error(`--host must not be empty\n\n${HELP_TEXT}`);
  }
  if (
    options.unsafeDemoMutations === true
    && !["127.0.0.1", "::1"].includes(options.host)
  ) {
    throw new Error("--unsafe-demo-mutations requires a loopback host");
  }

  return options;
};

export const runTrustRegistryApiCli = async (
  argv: readonly string[] = process.argv.slice(2),
): Promise<void> => {
  const options = parseTrustRegistryApiCliArgs(argv);
  const source = options.localLedgerPlanPath !== undefined
    ? await (async () => {
      const plan = await loadApprovedLocalLedgerRuntimePlan({
        planPath: options.localLedgerPlanPath!,
        signaturePath: options.localLedgerSignaturePath!,
        keyringDirectory: options.localLedgerKeyringDirectory!,
        reviewerFingerprint: options.localLedgerReviewerFingerprint!,
      });
      const localSource = await createApprovedLocalLedgerRuntimeSource(plan);
      await localSource.loadSnapshot();
      return localSource;
    })()
    : options.snapshotPath !== undefined
      ? createSnapshotFileSource(options.snapshotPath)
      : createWorkspaceFileSource(options.workspacePath!);

  const server = createTrustRegistryApiServer({
    source,
    ...(options.unsafeDemoMutations === undefined ? {} : { allowUnsafeDemoMutations: options.unsafeDemoMutations }),
  });

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
