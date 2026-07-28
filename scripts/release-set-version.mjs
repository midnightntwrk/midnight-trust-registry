#!/usr/bin/env node

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

const parseArgs = () => {
  const options = {
    version: "",
  };
  const args = process.argv.slice(2);

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--":
        break;
      case "--version":
        options.version = args[++index] ?? "";
        break;
      case "--help":
        console.log(
          [
            "Usage: node scripts/release-set-version.mjs --version <semver>",
            "",
            "Updates the root package.json plus every workspace package.json to",
            "the same release version and rewrites internal workspace dependency",
            "specifiers to match.",
          ].join("\n"),
        );
        process.exit(0);
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!options.version) {
    throw new Error("--version is required");
  }

  return options;
};

const readJson = (relativePath) =>
  JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), "utf8"));

const writeJson = (relativePath, value) => {
  fs.writeFileSync(
    path.join(repoRoot, relativePath),
    `${JSON.stringify(value, null, 2)}\n`,
  );
};

const { version } = parseArgs();
const packageJsonPaths = [
  "package.json",
  ...workspaceCatalog.map(({ workspace }) => path.join(workspace, "package.json")),
];
const internalPackageNames = new Set(
  workspaceCatalog.map(({ workspace }) => readJson(path.join(workspace, "package.json")).name),
);

for (const relativePath of packageJsonPaths) {
  const packageJson = readJson(relativePath);
  packageJson.version = version;

  for (const section of dependencySections) {
    const dependencies = packageJson[section];
    if (!dependencies || typeof dependencies !== "object") {
      continue;
    }
    for (const [packageName, specifier] of Object.entries(dependencies)) {
      if (
        internalPackageNames.has(packageName)
        && typeof specifier === "string"
        && specifier.startsWith("workspace:")
      ) {
        dependencies[packageName] = `workspace:${version}`;
      }
    }
  }

  writeJson(relativePath, packageJson);
  console.log(`[release-set-version] Updated ${relativePath} -> ${version}`);
}
