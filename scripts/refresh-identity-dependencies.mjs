#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { workspaceCatalog } from "./trust-registry-workspace-catalog.mjs";

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const dependencySections = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
];
const didPackageNames = new Set([
  "@midnight-ntwrk/midnight-did",
  "@midnight-ntwrk/midnight-did-contract",
  "@midnight-ntwrk/midnight-did-domain",
  "@midnight-ntwrk/midnight-did-jubjub-schnorr",
]);
const vcPackageNames = new Set([
  "@midnight-ntwrk/credential-compact",
  "@midnight-ntwrk/credential-did-midnight",
]);

const parseArgs = () => {
  const options = {
    didVersion: "latest",
    vcVersion: "latest",
    refreshDid: true,
    refreshVc: true,
    runInstall: true,
    validate: "light",
  };
  const args = process.argv.slice(2);

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--":
        break;
      case "--did-version":
        options.didVersion = args[++index] ?? "";
        break;
      case "--vc-version":
        options.vcVersion = args[++index] ?? "";
        break;
      case "--skip-did":
        options.refreshDid = false;
        break;
      case "--skip-vc":
        options.refreshVc = false;
        break;
      case "--skip-install":
        options.runInstall = false;
        break;
      case "--validate":
        options.validate = args[++index] ?? "";
        break;
      case "--help":
        console.log(
          [
            "Usage: node scripts/refresh-identity-dependencies.mjs [options]",
            "",
            "Options:",
            "  --did-version <tag|version>  DID package version or dist-tag. Defaults to latest.",
            "  --vc-version <tag|version>   VC package version or dist-tag. Defaults to latest.",
            "  --skip-did                   Leave published DID package versions untouched.",
            "  --skip-vc                    Leave published VC package versions untouched.",
            "  --skip-install               Skip pnpm install after manifest updates.",
            "  --validate <mode>            none, light, integration, or all. Defaults to light.",
          ].join("\n"),
        );
        process.exit(0);
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!["none", "light", "integration", "all"].includes(options.validate)) {
    throw new Error(`Unsupported --validate mode: ${options.validate}`);
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

  return result.stdout.trim();
};

const readJson = (relativePath) =>
  JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), "utf8"));

const writeJson = (relativePath, value) => {
  fs.writeFileSync(
    path.join(repoRoot, relativePath),
    `${JSON.stringify(value, null, 2)}\n`,
  );
};

const resolvePublishedVersion = (packageName, requestedVersion) => {
  const resolved = run("npm", [
    "view",
    `${packageName}@${requestedVersion}`,
    "version",
    "--registry",
    "https://registry.npmjs.org",
  ]);
  if (!resolved) {
    throw new Error(`Could not resolve ${packageName} version for ${requestedVersion}`);
  }
  return resolved;
};

const resolvePackageFamilyVersion = (packageNames, primaryPackageName, requestedVersion) => {
  const resolvedVersion = resolvePublishedVersion(primaryPackageName, requestedVersion);
  for (const packageName of packageNames) {
    if (packageName !== primaryPackageName) {
      resolvePublishedVersion(packageName, resolvedVersion);
    }
  }
  return resolvedVersion;
};

const updatePackageVersion = (relativePath, packageNames, resolvedVersion) => {
  const packageJson = readJson(relativePath);
  let changed = false;

  for (const section of dependencySections) {
    const dependencies = packageJson[section];
    if (!dependencies || typeof dependencies !== "object") {
      continue;
    }
    for (const packageName of packageNames) {
      if (dependencies[packageName] !== undefined && dependencies[packageName] !== resolvedVersion) {
        dependencies[packageName] = resolvedVersion;
        changed = true;
      }
    }
  }

  if (changed) {
    writeJson(relativePath, packageJson);
    console.log(
      `[refresh-identity-dependencies] Updated ${relativePath} dependencies -> ${resolvedVersion}`,
    );
  }
};

const updateWorkspaceOverrides = (packageNames, resolvedVersion) => {
  const workspaceFile = path.join(repoRoot, "pnpm-workspace.yaml");
  let source = fs.readFileSync(workspaceFile, "utf8");
  for (const packageName of packageNames) {
    const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const overrideLine = new RegExp(`^(\\s*"${escaped}":\\s*).+$`, "m");
    if (!overrideLine.test(source)) {
      throw new Error(`Missing pnpm override for ${packageName}`);
    }
    source = source.replace(overrideLine, (_line, prefix) => `${prefix}${resolvedVersion}`);
  }
  fs.writeFileSync(workspaceFile, source);
};

const options = parseArgs();
const packageJsonPaths = [
  "package.json",
  ...workspaceCatalog.map(({ workspace }) => path.join(workspace, "package.json")),
];
const resolvedDidVersion = options.refreshDid
  ? resolvePackageFamilyVersion(didPackageNames, "@midnight-ntwrk/midnight-did", options.didVersion)
  : undefined;
const resolvedVcVersion = options.refreshVc
  ? resolvePackageFamilyVersion(vcPackageNames, "@midnight-ntwrk/credential-compact", options.vcVersion)
  : undefined;

if (resolvedDidVersion !== undefined) {
  for (const relativePath of packageJsonPaths) {
    updatePackageVersion(relativePath, didPackageNames, resolvedDidVersion);
  }
  updateWorkspaceOverrides(didPackageNames, resolvedDidVersion);
}

if (resolvedVcVersion !== undefined) {
  for (const relativePath of packageJsonPaths) {
    updatePackageVersion(relativePath, vcPackageNames, resolvedVcVersion);
  }
  updateWorkspaceOverrides(vcPackageNames, resolvedVcVersion);
}

if (options.runInstall) {
  run("pnpm", ["install", "--no-frozen-lockfile"]);
  console.log("[refresh-identity-dependencies] pnpm install completed.");
}

if (options.validate === "light" || options.validate === "all") {
  run("./run.sh", ["--light"]);
  console.log("[refresh-identity-dependencies] ./run.sh --light passed.");
}

if (options.validate === "integration" || options.validate === "all") {
  run("./run.sh", ["integration"]);
  console.log("[refresh-identity-dependencies] ./run.sh integration passed.");
}
