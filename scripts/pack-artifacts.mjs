#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
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
    outputDir: artifactDirectory,
  };
  const args = process.argv.slice(2);

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--":
        break;
      case "--output-dir":
        options.outputDir = args[++index];
        break;
      case "--help":
        console.log(
          [
            "Usage: node scripts/pack-artifacts.mjs [options]",
            "",
            "Options:",
            `  --output-dir <dir>  Directory for packed tarballs. Defaults to ${artifactDirectory}.`,
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

const parsePackFilename = (workspace, stdout) => {
  try {
    const parsed = JSON.parse(stdout);
    const [packument] = Array.isArray(parsed) ? parsed : [parsed];
    const filename = packument?.filename;
    if (!filename) {
      throw new Error("missing filename");
    }
    return filename;
  } catch (error) {
    throw new Error(
      `${workspace}: pnpm pack did not return parseable JSON (${error.message})`,
    );
  }
};

const { outputDir } = parseArgs();
const resolvedOutputDir = path.resolve(repoRoot, outputDir);
fs.mkdirSync(resolvedOutputDir, { recursive: true });

const packed = [];

for (const workspace of artifactWorkspaces) {
  const isContractWorkspace = workspace.startsWith("contracts/");
  const stdout = isContractWorkspace
    ? run("npm", [
      "pack",
      "--json",
      "--ignore-scripts",
      "--pack-destination",
      resolvedOutputDir,
    ], {
      cwd: path.join(repoRoot, workspace),
    })
    : run("pnpm", [
      "--filter",
      `./${workspace}`,
      "pack",
      "--json",
      "--pack-destination",
      resolvedOutputDir,
    ]);
  const filename = parsePackFilename(workspace, stdout);
  packed.push({
    workspace,
    packageName: packageManifestCatalog.get(workspace)?.name ?? workspace,
    filename: path.isAbsolute(filename)
      ? filename
      : path.join(resolvedOutputDir, filename),
  });
}

for (const entry of packed) {
  console.log(
    `[pack-artifacts] ${entry.workspace} -> ${path.relative(repoRoot, entry.filename)}`,
  );
}

console.log(
  `[pack-artifacts] Packed ${packed.length} artifact tarballs into ${path.relative(repoRoot, resolvedOutputDir)}`,
);
