import { existsSync, mkdirSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspace = resolve(root, "artifacts/trust-registry/guided-role-demo-workspace.json");
const apiPort = 4500;
const uiPort = 4273;

if (!existsSync(workspace)) {
  mkdirSync(dirname(workspace), { recursive: true });
  const init = spawnSync(process.execPath, [
    "packages/trust-registry-cli/bin/trust-registry.mjs",
    "init-workspace", "--workspace", workspace,
  ], { cwd: root, stdio: "inherit" });
  if (init.status !== 0) process.exit(init.status ?? 1);
}

const children = [];
let stopping = false;
const stop = () => {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill("SIGTERM");
};

const start = (name, args) => {
  const child = spawn(process.execPath, args, { cwd: root, stdio: "inherit" });
  children.push(child);
  child.on("exit", (code) => {
    if (stopping) return;
    process.stderr.write(`${name} stopped (${code ?? "signal"}); stopping the guided demo.\n`);
    stop();
    process.exitCode = code === 0 ? 1 : code ?? 1;
  });
};

process.on("SIGINT", stop);
process.on("SIGTERM", stop);
start("fixture API", [
  "packages/trust-registry-api/bin/trust-registry-api.mjs", "serve",
  "--workspace", workspace, "--unsafe-demo-mutations", "--port", String(apiPort),
]);
start("guided UI", [
  "packages/trust-registry-admin-console/scripts/serve.mjs", "--port", String(uiPort),
]);

const url = `http://127.0.0.1:${uiPort}/demo.html?apiBase=${encodeURIComponent(`http://127.0.0.1:${apiPort}`)}`;
process.stdout.write(`\nGuided Trust Registry demo: ${url}\n`);
process.stdout.write("Choose Issuer #1, submit a request, then switch to Maintainers #1, #2 and #3. Press Ctrl+C to stop both services.\n\n");
