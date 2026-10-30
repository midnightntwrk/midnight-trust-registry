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

const parsePackument = (workspace, stdout) => {
  try {
    const parsed = JSON.parse(stdout);
    const [packument] = Array.isArray(parsed) ? parsed : [parsed];
    const filename = packument?.filename;
    if (!filename) {
      throw new Error("missing filename");
    }
    return packument;
  } catch (error) {
    throw new Error(
      `${workspace}: pnpm pack did not return parseable JSON (${error.message})`,
    );
  }
};

const packContractStreaming = (workspace, outputDir) => {
  const packageDir = path.join(repoRoot, workspace);
  const packument = parsePackument(workspace, run("pnpm", [
    "--config.ignore-scripts=true", "--filter", `./${workspace}`, "pack", "--dry-run", "--json",
  ]));
  const manifest = fs.readFileSync(path.join(packageDir, "package.json"), "utf8");
  const { name, version } = JSON.parse(manifest);
  const filename = `${name.replace(/^@/, "").replace("/", "-")}-${version}.tgz`;
  if (packument.name !== name || packument.version !== version
    || path.basename(packument.filename) !== filename || !Array.isArray(packument.files)) {
    throw new Error(`${workspace}: dry-run package identity or file list is invalid`);
  }
  const files = packument.files.map(({ path: file }) => file);
  if (files.length === 0 || new Set(files).size !== files.length || !files.includes("package.json")) {
    throw new Error(`${workspace}: dry-run package file list is empty or duplicated`);
  }
  for (const file of files) {
    if (typeof file !== "string" || file.length === 0 || file.includes("\n")
      || file.split("/").some((part) => part === ".." || part === "." || part === "")
      || path.isAbsolute(file) || !fs.lstatSync(path.join(packageDir, file)).isFile()
      || !fs.realpathSync(path.join(packageDir, file)).startsWith(`${fs.realpathSync(packageDir)}${path.sep}`)) {
      throw new Error(`${workspace}: unsafe package file: ${file}`);
    }
  }
  const destination = path.join(outputDir, filename);
  const temporary = `${destination}.partial`;
  const inheritedLicense = !files.includes("LICENSE") && fs.existsSync(path.join(repoRoot, "LICENSE"))
    ? ["-C", repoRoot, "LICENSE"]
    : [];
  const prefix = process.platform === "darwin"
    ? ["-s", "#^#package/#"]
    : ["--transform=s#^#package/#"];
  try {
    run("tar", ["-czf", temporary, "-C", packageDir, ...prefix, ...files, ...inheritedLicense]);
    fs.renameSync(temporary, destination);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
  return destination;
};

const { outputDir } = parseArgs();
const resolvedOutputDir = path.resolve(repoRoot, outputDir);
fs.mkdirSync(resolvedOutputDir, { recursive: true });

const packed = [];

for (const workspace of artifactWorkspaces) {
  const isContractWorkspace = workspace.startsWith("contracts/");
  const filename = isContractWorkspace
    ? packContractStreaming(workspace, resolvedOutputDir)
    : parsePackument(workspace, run("pnpm", [
      "--filter",
      `./${workspace}`,
      "pack",
      "--json",
      "--pack-destination",
      resolvedOutputDir,
    ])).filename;
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
