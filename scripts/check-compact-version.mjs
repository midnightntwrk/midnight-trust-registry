import { appendFileSync, existsSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
const requiredWorkflows = [
  ".github/workflows/ci.yaml",
  ".github/workflows/milestone-light.yaml",
  ".github/workflows/quality.yaml",
  ".github/workflows/publish.yml",
];
const outputReference = "${{ steps.compact-version.outputs.version }}";
const pinCommand = "node scripts/check-compact-version.mjs --github-output";
const installedCommand = "node scripts/check-compact-version.mjs --check-installed";

const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const setupStep = (step) => typeof step?.uses === "string"
  && /\/setup-compact-action@/iu.test(step.uses);
const trustedSetupStep = (step) => step.uses.toLowerCase().startsWith("midnightntwrk/setup-compact-action@");
const unconditionalStep = (step) => step.if === undefined;

const readWorkflow = (directory, path, yaml, required = true) => {
  let workflow;
  try {
    workflow = yaml.load(readFileSync(resolve(directory, path), "utf8"));
  } catch (error) {
    throw new Error(`${path}: invalid workflow YAML: ${error.message}`, { cause: error });
  }
  if (!isRecord(workflow) || !isRecord(workflow.jobs)) {
    if (required) throw new Error(`${path} must contain workflow jobs`);
    return null;
  }
  return workflow;
};

const workflowJobs = (workflow) => Object.values(workflow.jobs).filter(isRecord);
const jobSteps = (job) => Array.isArray(job.steps) ? job.steps.filter(isRecord) : [];
const hasLegacyCompilerReference = (value, seen = new WeakSet()) => {
  if (typeof value === "string") return value.includes("env.COMPACT_COMPILER_VERSION");
  if (!isRecord(value) && !Array.isArray(value)) return false;
  if (seen.has(value)) return false;
  seen.add(value);
  return Object.entries(value).some(([key, child]) =>
    key === "COMPACT_COMPILER_VERSION" || hasLegacyCompilerReference(child, seen));
};

const checkWorkflowSetup = (workflow, path) => {
  let setupCount = 0;
  for (const job of workflowJobs(workflow)) {
    const steps = jobSteps(job);
    for (const [index, step] of steps.entries()) {
      if (step.with?.["compact-version"] !== undefined
        && step.with["compact-version"] !== outputReference) {
        throw new Error(`${path} must read the checked-in Compact version for setup`);
      }
      if (!setupStep(step)) continue;
      setupCount += 1;
      const pinIndex = steps.findIndex((candidate) => unconditionalStep(candidate) && candidate.id === "compact-version"
        && typeof candidate.run === "string" && candidate.run.trim() === pinCommand);
      const installedIndex = steps.findIndex((candidate, offset) => offset > index && unconditionalStep(candidate)
        && typeof candidate.run === "string" && candidate.run.trim() === installedCommand);
      const installIndex = steps.findIndex((candidate, offset) => offset > installedIndex && unconditionalStep(candidate)
        && typeof candidate.run === "string" && candidate.run.trim().startsWith("pnpm install "));
      const semanticIndex = steps.findIndex((candidate, offset) => offset > installIndex && unconditionalStep(candidate)
        && typeof candidate.run === "string" && candidate.run.trim() === "pnpm run check:compact-version");
      if (!trustedSetupStep(step) || !unconditionalStep(step)
        || pinIndex < 0 || pinIndex >= index || installedIndex < 0 || installIndex < 0 || semanticIndex < 0
        || step.with?.["compact-version"] !== outputReference
        || step.env?.GITHUB_TOKEN !== "${{ github.token }}") {
        throw new Error(`${path} must read the checked-in Compact version for setup`);
      }
    }
  }
  if (setupCount === 0 || hasLegacyCompilerReference(workflow)) {
    throw new Error(`${path} must read the checked-in Compact version for setup`);
  }
};

export function readCompactPin(directory = root) {
  const pin = readFileSync(resolve(directory, ".compact-version"), "utf8");
  if (!/^\d+\.\d+\.\d+\n$/.test(pin)) {
    throw new Error(".compact-version must contain one stable semver and a newline");
  }
  return pin.trimEnd();
}

export function checkCompactVersion(directory = root) {
  const version = readCompactPin(directory);
  const yaml = require("js-yaml");

  const workflowDirectory = resolve(directory, ".github/workflows");
  const workflows = new Set(requiredWorkflows);
  for (const file of readdirSync(workflowDirectory)) {
    if (!/\.ya?ml$/u.test(file)) continue;
    const path = `.github/workflows/${file}`;
    const workflow = readWorkflow(directory, path, yaml, false);
    if (workflow && workflowJobs(workflow).some((job) => jobSteps(job).some(setupStep))) {
      workflows.add(path);
    }
  }

  for (const path of workflows) {
    checkWorkflowSetup(readWorkflow(directory, path, yaml), path);
  }

  const quality = readWorkflow(directory, ".github/workflows/quality.yaml", yaml);
  const cacheSteps = workflowJobs(quality).flatMap(jobSteps)
    .filter((step) => typeof step.uses === "string" && /^actions\/cache\/(?:restore|save)@/u.test(step.uses));
  const cacheKeys = cacheSteps.map((step) => step.with?.key)
    .filter((key) => typeof key === "string" && key.startsWith("tr-turbo-v1-"));
  const restoreKeys = cacheSteps.filter((step) => step.uses.startsWith("actions/cache/restore@"))
    .flatMap((step) => typeof step.with?.["restore-keys"] === "string"
    ? step.with["restore-keys"].split("\n").map((key) => key.trim()).filter((key) => key.startsWith("tr-turbo-v1-"))
    : []);
  if (
    cacheKeys.length < 2 ||
    restoreKeys.length < 1 ||
    [...cacheKeys, ...restoreKeys].some((key) => !key.includes(`compact-${outputReference}-`))
  ) {
    throw new Error("Quality Turbo cache and restore keys must include the checked-in Compact version");
  }

  const turbo = JSON.parse(readFileSync(resolve(directory, "turbo.json"), "utf8"));
  if (
    !turbo.globalDependencies?.includes(".compact-version")
    || !turbo.globalDependencies?.includes("scripts/compile-compact.mjs")
  ) {
    throw new Error("Turbo must invalidate cached outputs when the Compact pin or compile wrapper changes");
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
    const version = process.argv.length === 2 ? checkCompactVersion() : readCompactPin();
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
      if (process.env.COMPACT_DIRECTORY) {
        const compiler = resolve(process.env.COMPACT_DIRECTORY, "bin/compactc");
        if (existsSync(compiler)) {
          const compilerVersion = execFileSync(compiler, ["--version"], { encoding: "utf8" }).trim();
          if (compilerVersion !== version) {
            throw new Error(`Compact compiler ${compilerVersion} does not match pin ${version}`);
          }
        }
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
