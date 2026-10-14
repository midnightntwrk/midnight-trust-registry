import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const provingInputs = new Set([
  ".compact-version",
  "contracts/trust-registry/src/trust-registry.compact",
  "contracts/trust-registry/package.json",
  "pnpm-workspace.yaml",
  "scripts/compile-compact.mjs",
]);

export const provingInputsChanged = (paths, eventName) =>
  !["push", "pull_request"].includes(eventName)
  || paths.some((path) => provingInputs.has(path));

export const changedPaths = () => {
  try {
    return execFileSync("git", ["diff", "--name-only", "HEAD^1", "HEAD"], {
      encoding: "utf8",
    }).trim().split("\n").filter(Boolean);
  } catch {
    // An unavailable parent must not silently disable proving validation.
    return [".compact-version"];
  }
};

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const required = provingInputsChanged(changedPaths(), process.env.GITHUB_EVENT_NAME ?? "workflow_dispatch");
  const value = required ? "true" : "false";
  if (process.argv.includes("--github-output")) {
    if (!process.env.GITHUB_OUTPUT) throw new Error("GITHUB_OUTPUT is required");
    appendFileSync(process.env.GITHUB_OUTPUT, `required=${value}\n`);
  }
  process.stdout.write(`Proving-key validation required: ${value}\n`);
}
