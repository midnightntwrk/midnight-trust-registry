import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const provingInputs = new Set([
  ".compact-version",
  "contracts/trust-registry/src/trust-registry.compact",
  "contracts/trust-registry/package.json",
  "scripts/compile-compact.mjs",
]);

const relevantOverrides = (config) => Object.fromEntries(
  Object.entries(config?.overrides ?? {}).filter(([name]) => name.startsWith("@midnight-ntwrk/")),
);

export const workspaceConfigAffectsProving = (before, after) =>
  JSON.stringify((before?.packages ?? []).filter((path) => path !== "docs-site"))
    !== JSON.stringify((after?.packages ?? []).filter((path) => path !== "docs-site"))
  || before?.preferWorkspacePackages !== after?.preferWorkspacePackages
  || JSON.stringify(relevantOverrides(before)) !== JSON.stringify(relevantOverrides(after));

export const provingInputsChanged = (paths, eventName, workspaceRelevant = true) =>
  !["push", "pull_request"].includes(eventName)
  || paths.some((path) => provingInputs.has(path))
  || (workspaceRelevant && paths.includes("pnpm-workspace.yaml"));

const workspaceChangeIsRelevant = () => {
  try {
    const before = yaml.load(execFileSync("git", ["show", "HEAD^1:pnpm-workspace.yaml"], { encoding: "utf8" }));
    const after = yaml.load(readFileSync("pnpm-workspace.yaml", "utf8"));
    return workspaceConfigAffectsProving(before, after);
  } catch {
    return true;
  }
};

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
  const paths = changedPaths();
  const workspaceRelevant = paths.includes("pnpm-workspace.yaml") && workspaceChangeIsRelevant();
  const required = provingInputsChanged(paths, process.env.GITHUB_EVENT_NAME ?? "workflow_dispatch", workspaceRelevant);
  const value = required ? "true" : "false";
  if (process.argv.includes("--github-output")) {
    if (!process.env.GITHUB_OUTPUT) throw new Error("GITHUB_OUTPUT is required");
    appendFileSync(process.env.GITHUB_OUTPUT, `required=${value}\n`);
  }
  process.stdout.write(`Proving-key validation required: ${value}\n`);
}
