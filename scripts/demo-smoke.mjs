#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const parseArgs = () => {
  const options = {
    keepArtifacts: false,
    workspacePath: path.join(
      repoRoot,
      "artifacts/trust-registry/demo-smoke/workspace.json",
    ),
  };
  const args = process.argv.slice(2);

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--":
        break;
      case "--workspace":
        options.workspacePath = path.resolve(repoRoot, args[++index]);
        break;
      case "--keep-artifacts":
        options.keepArtifacts = true;
        break;
      case "--help":
        console.log(
          [
            "Usage: node scripts/demo-smoke.mjs [options]",
            "",
            "Options:",
            "  --workspace <path>   Workspace file path for the smoke run.",
            "  --keep-artifacts     Keep generated demo files instead of deleting them.",
          ].join("\n"),
        );
        process.exit(0);
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return options;
};

const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });

  if (result.status !== 0) {
    throw new Error(
      [
        `${command} ${args.join(" ")} failed with exit code ${result.status}`,
        result.stdout,
        result.stderr,
      ]
        .filter(Boolean)
        .join("\n"),
    );
  }

  return result.stdout;
};

const findFreePort = async () =>
  await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("expected a TCP address"));
        return;
      }
      const { port } = address;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(port);
      });
    });
  });

const waitForHealth = async (url, child) => {
  const startedAt = Date.now();
  while (Date.now() - startedAt < 20_000) {
    if (child.exitCode !== null) {
      throw new Error(`demo api exited early with code ${child.exitCode}`);
    }

    try {
      const response = await fetch(`${url}/health`);
      if (response.ok) {
        return await response.json();
      }
    } catch {
      // retry until the server binds its port
    }

    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  throw new Error("timed out waiting for demo api health endpoint");
};

const requestJson = async (url, init) => {
  const response = await fetch(url, init);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(
      `${init?.method ?? "GET"} ${url} failed with ${response.status}: ${JSON.stringify(payload)}`,
    );
  }
  return payload;
};

const { keepArtifacts, workspacePath } = parseArgs();
const workspaceDir = path.dirname(workspacePath);
const snapshotPath = path.join(workspaceDir, "demo-snapshot.json");

fs.mkdirSync(workspaceDir, { recursive: true });

run("pnpm", ["--filter", "@midnight-ntwrk/trust-registry-cli", "run", "build"]);
run("pnpm", ["--filter", "@midnight-ntwrk/trust-registry-api", "run", "build"]);
run("pnpm", ["--filter", "@midnight-ntwrk/trust-registry-admin-console", "run", "build"]);
run("pnpm", ["--filter", "@midnight-ntwrk/trust-registry-applicant-portal", "run", "build"]);

run("node", [
  "packages/trust-registry-cli/bin/trust-registry.mjs",
  "init-workspace",
  "--workspace",
  workspacePath,
  "--label",
  "demo-smoke",
]);
run("node", [
  "packages/trust-registry-cli/bin/trust-registry.mjs",
  "init-demo",
  "--output",
  snapshotPath,
  "--label",
  "demo-smoke-snapshot",
]);

const port = await findFreePort();
const apiArgs = [
  "packages/trust-registry-api/bin/trust-registry-api.mjs",
  "serve",
  "--workspace",
  workspacePath,
  "--port",
  String(port),
];
const apiProcess = spawn("node", apiArgs, {
  cwd: repoRoot,
  env: process.env,
  stdio: ["ignore", "pipe", "pipe"],
});

let stdout = "";
let stderr = "";
apiProcess.stdout.on("data", (chunk) => {
  stdout += String(chunk);
});
apiProcess.stderr.on("data", (chunk) => {
  stderr += String(chunk);
});

const baseUrl = `http://127.0.0.1:${port}`;

try {
  const health = await waitForHealth(baseUrl, apiProcess);
  if (health.sourceMode !== "workspace") {
    throw new Error(`expected workspace source mode, got ${health.sourceMode}`);
  }

  const summary = await requestJson(`${baseUrl}/v1/registry/summary`);
  if (summary.registryLabel !== "demo-smoke") {
    throw new Error(`expected registry label demo-smoke, got ${summary.registryLabel}`);
  }

  const submit = await requestJson(`${baseUrl}/v1/applications`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      target: "issuer",
      label: "passport-demo",
    }),
  });
  const issuerId = submit.entry?.authorization?.authorizationId;
  if (!issuerId) {
    throw new Error("demo submit did not return an issuer authorization id");
  }

  for (const action of ["approve", "activate"]) {
    await requestJson(`${baseUrl}/v1/applications/issuer/${issuerId}/${action}`, {
      method: "POST",
    });
  }

  const epoch = await requestJson(`${baseUrl}/v1/epochs/publish`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      label: "demo-smoke-current",
    }),
  });
  if (!epoch.currentEpochId) {
    throw new Error("epoch publish did not return a current epoch id");
  }

  const activeIssuers = await requestJson(
    `${baseUrl}/v1/authorizations/issuer?status=active`,
  );
  if (activeIssuers.total < 1) {
    throw new Error("expected at least one active issuer after activation");
  }

  const evidence = await requestJson(
    `${baseUrl}/v1/authorizations/issuer/${issuerId}/evidence`,
  );
  if (evidence.authorization?.authorizationId !== issuerId) {
    throw new Error("issuer evidence did not round-trip through the api");
  }

  const snapshot = JSON.parse(fs.readFileSync(snapshotPath, "utf8"));
  if (snapshot.registryLabel !== "demo-smoke-snapshot") {
    throw new Error("demo snapshot was not created with the expected label");
  }

  const adminIndex = path.join(
    repoRoot,
    "packages/trust-registry-admin-console/dist/index.html",
  );
  const applicantIndex = path.join(
    repoRoot,
    "packages/trust-registry-applicant-portal/dist/index.html",
  );
  if (!fs.existsSync(adminIndex) || !fs.existsSync(applicantIndex)) {
    throw new Error("demo ui builds are missing expected dist/index.html assets");
  }
} catch (error) {
  throw new Error(
    [
      error instanceof Error ? error.message : String(error),
      stdout && `[demo-smoke] api stdout:\n${stdout}`,
      stderr && `[demo-smoke] api stderr:\n${stderr}`,
    ]
      .filter(Boolean)
      .join("\n\n"),
  );
} finally {
  apiProcess.kill("SIGTERM");
  await new Promise((resolve) => {
    apiProcess.once("exit", () => resolve());
    setTimeout(() => resolve(), 2_000);
  });

  if (!keepArtifacts) {
    fs.rmSync(workspaceDir, { force: true, recursive: true });
  }
}

console.log(
  `[demo-smoke] Verified CLI/API demo flow and local UI build artifacts on port ${port}.`,
);
