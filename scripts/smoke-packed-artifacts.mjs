#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  artifactDirectory,
  artifactWorkspaces,
  packageManifestCatalog,
} from "./trust-registry-workspace-catalog.mjs";

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const parseArgs = () => {
  const options = {
    artifactsDir: artifactDirectory,
  };
  const args = process.argv.slice(2);

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--":
        break;
      case "--artifacts-dir":
        options.artifactsDir = args[++index];
        break;
      case "--help":
        console.log(
          [
            "Usage: node scripts/smoke-packed-artifacts.mjs [options]",
            "",
            "Options:",
            `  --artifacts-dir <dir>  Tarball directory. Defaults to ${artifactDirectory}.`,
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

const seedVendoredTarballs = (consumerRoot) => {
  const sourceDir = path.join(
    repoRoot,
    "tooling/vendor/midnight-verifiable-credentials",
  );
  const destinationDir = path.join(
    consumerRoot,
    "node_modules/tooling/vendor/midnight-verifiable-credentials",
  );
  fs.mkdirSync(destinationDir, { recursive: true });
  for (const fileName of fs.readdirSync(sourceDir)) {
    if (fileName.endsWith(".tgz")) {
      fs.copyFileSync(
        path.join(sourceDir, fileName),
        path.join(destinationDir, fileName),
      );
    }
  }
};

const ensureArtifacts = (artifactsPath) => {
  const tarballs = fs
    .readdirSync(artifactsPath, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".tgz"));
  if (tarballs.length === artifactWorkspaces.length) {
    return;
  }

  run("node", ["scripts/pack-artifacts.mjs", "--output-dir", artifactsPath], {
    cwd: repoRoot,
  });
};

const { artifactsDir } = parseArgs();
const resolvedArtifactsDir = path.resolve(repoRoot, artifactsDir);
fs.mkdirSync(resolvedArtifactsDir, { recursive: true });
ensureArtifacts(resolvedArtifactsDir);

const tarballPaths = fs
  .readdirSync(resolvedArtifactsDir)
  .filter((fileName) => fileName.endsWith(".tgz"))
  .sort()
  .map((fileName) => path.join(resolvedArtifactsDir, fileName));

if (tarballPaths.length !== artifactWorkspaces.length) {
  throw new Error(
    `Expected ${artifactWorkspaces.length} tarballs in ${resolvedArtifactsDir}, found ${tarballPaths.length}`,
  );
}

const smokeRoot = fs.mkdtempSync(path.join(os.tmpdir(), "trust-registry-pack-smoke-"));

try {
  fs.writeFileSync(
    path.join(smokeRoot, "package.json"),
    `${JSON.stringify({ name: "trust-registry-pack-smoke", private: true, type: "module" }, null, 2)}\n`,
  );
  seedVendoredTarballs(smokeRoot);

  run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", ...tarballPaths], {
    cwd: smokeRoot,
  });

  const smokeImports = artifactWorkspaces.flatMap((workspace) =>
    packageManifestCatalog.get(workspace)?.smokeImports ?? [],
  );

  fs.writeFileSync(
    path.join(smokeRoot, "smoke.mjs"),
    [
      `const imports = ${JSON.stringify(smokeImports, null, 2)};`,
      "for (const specifier of imports) {",
      "  await import(specifier);",
      "  console.log(`[smoke-packed-artifacts] imported ${specifier}`);",
      "}",
    ].join("\n"),
  );

  run("node", ["smoke.mjs"], { cwd: smokeRoot });
  run(path.join(smokeRoot, "node_modules/.bin/trust-registry"), ["--help"], {
    cwd: smokeRoot,
  });
} finally {
  fs.rmSync(smokeRoot, { force: true, recursive: true });
}

console.log("[smoke-packed-artifacts] Local artifact tarballs install and import cleanly.");
