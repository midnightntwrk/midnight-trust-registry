#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { workspaceCatalog } from "./trust-registry-workspace-catalog.mjs";

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const workspaceRoot = path.dirname(repoRoot);
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

const parseArgs = () => {
  const options = {
    didVersion: "latest",
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
            "  --skip-did                   Leave published DID package versions untouched.",
            "  --skip-vc                    Skip vendored VC tarball refresh from the workspace root.",
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

const resolveDidVersion = (requestedVersion) => {
  const resolved = run("npm", [
    "view",
    `@midnight-ntwrk/midnight-did@${requestedVersion}`,
    "version",
    "--registry",
    "https://registry.npmjs.org",
  ]);
  if (!resolved) {
    throw new Error(`Could not resolve DID version for ${requestedVersion}`);
  }
  return resolved;
};

const updateDidPackageVersion = (relativePath, resolvedVersion) => {
  const packageJson = readJson(relativePath);
  let changed = false;

  for (const section of dependencySections) {
    const dependencies = packageJson[section];
    if (!dependencies || typeof dependencies !== "object") {
      continue;
    }
    for (const packageName of didPackageNames) {
      if (dependencies[packageName] !== undefined && dependencies[packageName] !== resolvedVersion) {
        dependencies[packageName] = resolvedVersion;
        changed = true;
      }
    }
  }

  if (relativePath === "package.json" && packageJson.pnpm?.overrides) {
    for (const packageName of didPackageNames) {
      if (
        packageJson.pnpm.overrides[packageName] !== undefined
        && packageJson.pnpm.overrides[packageName] !== resolvedVersion
      ) {
        packageJson.pnpm.overrides[packageName] = resolvedVersion;
        changed = true;
      }
    }
  }

  if (changed) {
    writeJson(relativePath, packageJson);
    console.log(
      `[refresh-identity-dependencies] Updated ${relativePath} DID dependencies -> ${resolvedVersion}`,
    );
  }
};

const refreshVcTarballs = () => {
  const syncScript = path.join(workspaceRoot, "scripts/sync-package-tarballs.sh");
  if (!fs.existsSync(syncScript)) {
    throw new Error(
      `VC refresh requires ${syncScript}. Run from midnight-identity-workspace or pass --skip-vc.`,
    );
  }

  run(syncScript, ["--source", "vc", "--destination", "midnight-trust-registry"], {
    cwd: workspaceRoot,
  });
  console.log("[refresh-identity-dependencies] Refreshed vendored VC tarballs from the workspace root.");
};

const options = parseArgs();

if (options.refreshDid) {
  const resolvedDidVersion = resolveDidVersion(options.didVersion);
  const packageJsonPaths = [
    "package.json",
    ...workspaceCatalog.map(({ workspace }) => path.join(workspace, "package.json")),
  ];
  for (const relativePath of packageJsonPaths) {
    updateDidPackageVersion(relativePath, resolvedDidVersion);
  }
}

if (options.refreshVc) {
  refreshVcTarballs();
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
