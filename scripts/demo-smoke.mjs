#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import { request as httpRequest } from "node:http";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";

import { assertUiIndexResponse, collectEmittedModuleAssets } from "./demo-smoke-assets.mjs";
import { describeChildExit, stopChild } from "./demo-smoke-process.mjs";

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const parseArgs = () => {
  const options = {
    keepArtifacts: false,
    workspacePath: undefined,
  };
  const args = process.argv.slice(2);

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--":
        break;
      case "--workspace":
        if (!args[index + 1] || args[index + 1].startsWith("--")) {
          throw new Error("--workspace requires a path");
        }
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
        `${command} ${args.join(" ")} failed with ${result.signal ? `signal ${result.signal}` : `exit code ${result.status}`}`,
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
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`demo api exited early with ${describeChildExit(child)}`);
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

const requestRawPath = async (url, pathname) =>
  await new Promise((resolve, reject) => {
    const address = new URL(url);
    const request = httpRequest({
      hostname: address.hostname,
      port: Number(address.port),
      path: pathname,
    }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { body += chunk; });
      response.on("end", () => resolve({ status: response.statusCode, body }));
      response.on("error", reject);
      response.on("aborted", () => reject(new Error(`Static asset response aborted for ${pathname}`)));
      response.on("close", () => {
        if (!response.complete) reject(new Error(`Static asset response closed early for ${pathname}`));
      });
    });
    request.on("error", reject);
    request.setTimeout(5_000, () => request.destroy(new Error(`Static asset request timed out for ${pathname}`)));
    request.end();
  });

const waitForUi = async (url, child, title, distDir) => {
  const startedAt = Date.now();
  while (Date.now() - startedAt < 20_000) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`${title} exited early with ${describeChildExit(child)}`);
    }

    let response;
    try {
      response = await fetch(url);
    } catch (error) {
      if (!(error instanceof TypeError)) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 250));
      continue;
    }

    assertUiIndexResponse(response, title);
    const html = await response.text();
    if (!html.includes(`<title>${title}</title>`)) {
      throw new Error(`${title} served an unexpected index.html`);
    }
    const modules = collectEmittedModuleAssets(distDir, title);
    for (const [asset, contentType] of [
      ...modules.map((file) => [file, file.endsWith(".json") ? "application/json" : "text/javascript"]),
      ["styles.css", "text/css"],
    ]) {
      const assetPath = asset.split("/").map(encodeURIComponent).join("/");
      const assetResponse = await fetch(`${url}/${assetPath}`);
      if (!assetResponse.ok || !assetResponse.headers.get("content-type")?.startsWith(contentType)) {
        throw new Error(`${title} did not serve ${asset} with ${contentType} (HTTP ${assetResponse.status})`);
      }
      if ((asset === "index.js" || asset === "styles.css") && !(await assetResponse.text()).trim()) {
        throw new Error(`${title} served an empty ${asset}`);
      }
    }
    const siblingDir = fs.mkdtempSync(`${distDir}-other-`);
    const secretPath = path.join(siblingDir, "secret.txt");
    const linkName = `outside-${randomUUID()}.txt`;
    const linkPath = path.join(distDir, linkName);
    try {
      fs.writeFileSync(secretPath, "outside-dist-secret\n");
      fs.symlinkSync(secretPath, linkPath);
      const absoluteIndex = await requestRawPath(url, `${url}/index.html`);
      if (absoluteIndex.status !== 200 || !absoluteIndex.body.includes(`<title>${title}</title>`)) {
        throw new Error(`${title} did not serve an absolute-form index request`);
      }
      for (const target of [
        `${url}?redirect=/styles.css`,
        "/index.html#fragment",
        `${url.replace(/^http:/u, "HTTP:")}/index.html`,
      ]) {
        const result = await requestRawPath(url, target);
        if (result.status !== 200 || !result.body.includes(`<title>${title}</title>`)) {
          throw new Error(`${title} did not serve index.html for ${target}`);
        }
      }
      for (const [pathname, expectedStatus] of [
        [`/%2e%2e/${path.basename(siblingDir)}/secret.txt`, 403],
        [`${url}/%2e%2e/${path.basename(siblingDir)}/secret.txt`, 403],
        [`/%2e%2e/%2e%2e/${path.basename(siblingDir)}/secret.txt`, 403],
        [`/${linkName}`, 403],
        ["/missing-static-asset.txt", 404],
        ["/%zz", 400],
      ]) {
        const result = await requestRawPath(url, pathname);
        if (result.body.includes("outside-dist-secret")) {
          throw new Error(`${title} exposed a file outside dist through ${pathname}`);
        }
        if (result.status !== expectedStatus) {
          throw new Error(`${title} served ${pathname} with HTTP ${result.status}, expected ${expectedStatus}`);
        }
      }
    } finally {
      fs.rmSync(linkPath, { force: true });
      fs.rmSync(siblingDir, { recursive: true, force: true });
    }
    return;
  }

  throw new Error(`timed out waiting for ${title} at ${url}`);
};

const options = parseArgs();
const { keepArtifacts } = options;
const defaultWorkspaceRoot = path.join(repoRoot, "artifacts/trust-registry/demo-smoke");
if (options.workspacePath === undefined) {
  fs.mkdirSync(defaultWorkspaceRoot, { recursive: true });
}
const workspaceDir = options.workspacePath === undefined
  ? fs.mkdtempSync(path.join(defaultWorkspaceRoot, "run-"))
  : path.dirname(options.workspacePath);
const workspacePath = options.workspacePath ?? path.join(workspaceDir, "workspace.json");
const snapshotPath = path.join(workspaceDir, "demo-snapshot.json");
const workspaceDirExisted = options.workspacePath !== undefined && fs.existsSync(workspaceDir);
let existingWorkspaceAncestor = workspaceDir;
if (options.workspacePath !== undefined) {
  while (!fs.existsSync(existingWorkspaceAncestor)) {
    existingWorkspaceAncestor = path.dirname(existingWorkspaceAncestor);
  }
}

for (const target of [workspacePath, snapshotPath]) {
  if (fs.existsSync(target)) {
    throw new Error(`refusing to overwrite existing demo smoke file: ${target}; choose a new --workspace path`);
  }
}

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
const uiProcesses = [];
apiProcess.stdout.on("data", (chunk) => {
  stdout += String(chunk);
});
apiProcess.stderr.on("data", (chunk) => {
  stderr += String(chunk);
});

const baseUrl = `http://127.0.0.1:${port}`;

let primaryError;
const cleanupProblems = [];
let retainedWorkspacePath;
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

  for (const [name, scriptPath, title] of [
    ["admin console", "packages/trust-registry-admin-console/scripts/serve.mjs", "Trust Registry Admin Console"],
    ["applicant portal", "packages/trust-registry-applicant-portal/scripts/serve.mjs", "Trust Registry Applicant Portal"],
  ]) {
    const uiPort = await findFreePort();
    const child = spawn("node", [scriptPath, "--port", String(uiPort)], {
      cwd: repoRoot,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const service = { name, child, stdout: "", stderr: "" };
    child.stdout.on("data", (chunk) => {
      service.stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      service.stderr += String(chunk);
    });
    uiProcesses.push(service);
    const distDir = path.resolve(repoRoot, path.dirname(scriptPath), "../dist");
    await waitForUi(`http://127.0.0.1:${uiPort}`, child, title, distDir);
  }
} catch (error) {
  primaryError = error;
} finally {
  const children = [{ name: "api", child: apiProcess }, ...uiProcesses];
  const stopped = await Promise.allSettled(children.map(({ child }) => stopChild(child)));
  for (const [index, outcome] of stopped.entries()) {
    const name = children[index].name;
    if (outcome.status === "rejected") cleanupProblems.push(`${name} cleanup failed: ${String(outcome.reason)}`);
    else if (outcome.value.timedOut) cleanupProblems.push(`${name} did not exit after SIGKILL`);
    else if (outcome.value.forced) cleanupProblems.push(`${name} required SIGKILL during cleanup`);
  }

  if (!keepArtifacts) {
    for (const createdFile of [workspacePath, snapshotPath]) {
      try {
        fs.rmSync(createdFile, { force: true });
      } catch (error) {
        cleanupProblems.push(`could not remove ${createdFile}: ${String(error)}`);
      }
    }
    if (!workspaceDirExisted) {
      try {
        if (options.workspacePath === undefined) fs.rmSync(workspaceDir, { force: true, recursive: true });
        else {
          let createdDir = workspaceDir;
          while (createdDir !== existingWorkspaceAncestor) {
            try {
              fs.rmdirSync(createdDir);
            } catch (error) {
              if (error?.code !== "ENOTEMPTY") throw error;
              retainedWorkspacePath = createdDir;
              break;
            }
            createdDir = path.dirname(createdDir);
          }
        }
      } catch (error) {
        cleanupProblems.push(`could not remove generated directory ${workspaceDir}: ${String(error)}`);
      }
    }
  }
}

if (primaryError !== undefined || cleanupProblems.length > 0) {
  throw new Error([
    primaryError === undefined ? "demo smoke cleanup failed" : primaryError instanceof Error ? primaryError.message : String(primaryError),
    stdout && `[demo-smoke] api stdout:\n${stdout}`,
    stderr && `[demo-smoke] api stderr:\n${stderr}`,
    ...uiProcesses.flatMap((service) => [
      service.stdout && `[demo-smoke] ${service.name} stdout:\n${service.stdout}`,
      service.stderr && `[demo-smoke] ${service.name} stderr:\n${service.stderr}`,
    ]),
    ...cleanupProblems.map((problem) => `[demo-smoke] cleanup: ${problem}`),
    (fs.existsSync(workspaceDir) || retainedWorkspacePath !== undefined) && `[demo-smoke] artifacts: ${retainedWorkspacePath ?? workspaceDir}`,
  ].filter(Boolean).join("\n\n"), { cause: primaryError });
}

console.log(
  `[demo-smoke] Verified CLI/API demo flow and both served UI surfaces on ephemeral loopback ports.${keepArtifacts || retainedWorkspacePath !== undefined ? ` Artifacts: ${retainedWorkspacePath ?? workspaceDir}` : ""}`,
);
