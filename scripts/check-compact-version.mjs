import { appendFileSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const requiredWorkflows = [
  ".github/workflows/ci.yaml",
  ".github/workflows/milestone-light.yaml",
  ".github/workflows/quality.yaml",
  ".github/workflows/publish.yml",
];
const outputReference = "${{ steps.compact-version.outputs.version }}";

export function checkCompactVersion(directory = root) {
  const pin = readFileSync(resolve(directory, ".compact-version"), "utf8");
  if (!/^\d+\.\d+\.\d+\n$/.test(pin)) {
    throw new Error(".compact-version must contain one stable semver and a newline");
  }
  const version = pin.trimEnd();

  const workflowDirectory = resolve(directory, ".github/workflows");
  const workflows = new Set(requiredWorkflows);
  for (const file of readdirSync(workflowDirectory)) {
    if (!/\.ya?ml$/u.test(file)) continue;
    const path = `.github/workflows/${file}`;
    if (readFileSync(resolve(directory, path), "utf8").includes("setup-compact-action@")) {
      workflows.add(path);
    }
  }

  for (const path of workflows) {
    const workflow = readFileSync(resolve(directory, path), "utf8");
    const setupVersions = [...workflow.matchAll(/^\s*compact-version:\s*(.+)$/gm)].map((match) => match[1]);
    if (
      !workflow.includes("id: compact-version") ||
      !workflow.includes("setup-compact-action@") ||
      !workflow.includes("run: node scripts/check-compact-version.mjs --github-output") ||
      !workflow.includes("run: node scripts/check-compact-version.mjs --check-installed") ||
      setupVersions.length === 0 ||
      setupVersions.some((value) => value !== outputReference) ||
      /^\s*COMPACT_COMPILER_VERSION\s*:/m.test(workflow) ||
      workflow.includes("env.COMPACT_COMPILER_VERSION") ||
      workflow.includes(`compact-version: ${version}`)
    ) {
      throw new Error(`${path} must read the checked-in Compact version for setup`);
    }
  }

  const quality = readFileSync(resolve(directory, ".github/workflows/quality.yaml"), "utf8");
  const cacheKeys = [...quality.matchAll(/^\s*key:\s*(.+)$/gm)]
    .map((match) => match[1])
    .filter((key) => key.startsWith("tr-turbo-v1-"));
  const restoreKeys = [...quality.matchAll(/^\s+tr-turbo-v1-[^\n]+$/gm)]
    .map((match) => match[0].trim());
  if (
    cacheKeys.length < 2 ||
    restoreKeys.length < 1 ||
    [...cacheKeys, ...restoreKeys].some((key) => !key.includes(`compact-${outputReference}-`))
  ) {
    throw new Error("Quality Turbo cache and restore keys must include the checked-in Compact version");
  }

  const turbo = JSON.parse(readFileSync(resolve(directory, "turbo.json"), "utf8"));
  if (!turbo.globalDependencies?.includes(".compact-version")) {
    throw new Error("Turbo must invalidate cached outputs when .compact-version changes");
  }

  const nix = readFileSync(resolve(directory, "nix/packages/compact-toolchain.nix"), "utf8");
  if (
    !nix.includes("builtins.readFile ../../.compact-version") ||
    !nix.includes("builtins.match") ||
    nix.includes(`version = "${version}";`)
  ) {
    throw new Error("Nix Compact toolchain must read .compact-version");
  }

  return version;
}

if (process.argv[1] && realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))) {
  try {
    const version = checkCompactVersion();
    if (process.argv[2] === "--github-output") {
      if (!process.env.GITHUB_OUTPUT) {
        throw new Error("GITHUB_OUTPUT is required for --github-output");
      }
      appendFileSync(process.env.GITHUB_OUTPUT, `version=${version}\n`);
    } else if (process.argv[2] === "--check-installed") {
      let installed;
      try {
        installed = execFileSync("compact", ["compile", "--version"], { encoding: "utf8" }).trim();
      } catch (error) {
        if (error.code === "ENOENT") {
          throw new Error("Compact compiler not found; enter the Nix development shell");
        }
        throw error;
      }
      if (installed !== version) {
        throw new Error(`Installed Compact ${installed} does not match pin ${version}`);
      }
    } else if (process.argv.length > 2) {
      throw new Error(`Unknown argument: ${process.argv[2]}`);
    }
    console.log(`Compact compiler pin: ${version}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
