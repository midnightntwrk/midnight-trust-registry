import { once } from "node:events";

import {
  createSnapshotFileSource,
  createWorkspaceFileSource,
} from "./source.js";
import { createTrustRegistryApiServer } from "./server.js";

const HELP_TEXT = `Usage:
  trust-registry-api serve (--snapshot PATH | --workspace PATH) [--host HOST] [--port PORT]

Examples:
  trust-registry-api serve --snapshot ./tmp/demo-snapshot.json
  trust-registry-api serve --workspace ./tmp/operator-workspace.json --port 4400
`;

export type TrustRegistryApiCliOptions = {
  host: string;
  port: number;
  snapshotPath?: string;
  workspacePath?: string;
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

  while (args.length > 0) {
    const arg = args.shift();
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
      case "--help":
      case "-h":
        throw new Error(HELP_TEXT);
      default:
        throw new Error(`unknown argument: ${arg}\n\n${HELP_TEXT}`);
    }
  }

  if (
    (options.snapshotPath === undefined && options.workspacePath === undefined)
    || (
      options.snapshotPath !== undefined
      && options.workspacePath !== undefined
    )
  ) {
    throw new Error(
      `exactly one of --snapshot or --workspace is required\n\n${HELP_TEXT}`,
    );
  }
  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
    throw new Error(`invalid port: ${String(options.port)}\n\n${HELP_TEXT}`);
  }
  if (options.host.trim().length === 0) {
    throw new Error(`--host must not be empty\n\n${HELP_TEXT}`);
  }

  return options;
};

export const runTrustRegistryApiCli = async (
  argv: readonly string[] = process.argv.slice(2),
): Promise<void> => {
  const options = parseTrustRegistryApiCliArgs(argv);
  const source =
    options.snapshotPath !== undefined
      ? createSnapshotFileSource(options.snapshotPath)
      : createWorkspaceFileSource(options.workspacePath!);

  const server = createTrustRegistryApiServer({
    source,
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
