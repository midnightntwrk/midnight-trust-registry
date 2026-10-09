#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  expectedWorkspaces,
  packageManifestCatalog,
  repositoryUrl,
  workspaceCatalog,
} from "./trust-registry-workspace-catalog.mjs";

const defaultRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

export function checkWorkspaceManifests(repoRoot = defaultRoot) {

const readJson = (relativePath) =>
  JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), "utf8"));

const rootPackage = readJson("package.json");
const errors = [];
const runtimePackageName = "@midnight-ntwrk/compact-runtime";
const runtimeVersion = readJson("contracts/trust-registry/package.json")
  .dependencies?.[runtimePackageName];
const dependencySections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];

const assertEqual = (label, actual, expected) => {
  if (actual !== expected) {
    errors.push(
      `${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
};

const assertArrayEqual = (label, actual, expected) => {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    errors.push(
      `${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
};

const assertFileExists = (label, relativePath) => {
  if (!fs.existsSync(path.join(repoRoot, relativePath))) {
    errors.push(`${label}: missing ${relativePath}`);
  }
};

assertArrayEqual("root workspaces", rootPackage.workspaces, expectedWorkspaces);
if (typeof runtimeVersion !== "string" || !/^\d+\.\d+\.\d+$/.test(runtimeVersion)) {
  errors.push("Compact runtime must use an exact semver version");
}

for (const { workspace, artifactPackage, publishPackage } of workspaceCatalog) {
  assertFileExists(`${workspace} package`, path.join(workspace, "package.json"));
  const packageJson = readJson(path.join(workspace, "package.json"));
  const label = `${workspace}/package.json`;

  for (const section of dependencySections) {
    const declaredRuntime = packageJson[section]?.[runtimePackageName];
    if (declaredRuntime !== undefined) {
      assertEqual(`${label} ${section} Compact runtime`, declaredRuntime, runtimeVersion);
    }
  }

  assertEqual(`${label} name exists`, typeof packageJson.name, "string");
  assertEqual(`${label} version`, packageJson.version, rootPackage.version);
  assertEqual(`${label} type`, packageJson.type, "module");

  if (!artifactPackage) {
    assertEqual(`${label} private`, packageJson.private, true);
    continue;
  }

  const expected = packageManifestCatalog.get(workspace);
  if (!expected) {
    errors.push(`${label}: missing artifact manifest catalog entry`);
    continue;
  }

  assertEqual(`${label} name`, packageJson.name, expected.name);
  assertEqual(`${label} license`, packageJson.license, "Apache-2.0");
  assertEqual(`${label} engines.node`, packageJson.engines?.node, ">=24");
  assertEqual(`${label} engines.pnpm`, packageJson.engines?.pnpm, ">=10");
  assertEqual(`${label} repository.type`, packageJson.repository?.type, "git");
  assertEqual(`${label} repository.url`, packageJson.repository?.url, repositoryUrl);
  assertEqual(
    `${label} repository.directory`,
    packageJson.repository?.directory,
    workspace,
  );
  assertEqual(`${label} main`, packageJson.main, "./dist/index.js");
  assertEqual(`${label} module`, packageJson.module, "./dist/index.js");
  assertEqual(`${label} types`, packageJson.types, "./dist/index.d.ts");
  assertEqual(`${label} private`, packageJson.private, !publishPackage);
  if (publishPackage) {
    assertEqual(
      `${label} publishConfig.access`,
      packageJson.publishConfig?.access,
      "public",
    );
  } else {
    assertEqual(`${label} publishConfig`, packageJson.publishConfig, undefined);
  }
  assertArrayEqual(`${label} files`, packageJson.files, expected.files);
  assertArrayEqual(
    `${label} export keys`,
    Object.keys(packageJson.exports ?? {}),
    expected.exports,
  );
  assertArrayEqual(
    `${label} bin keys`,
    Object.keys(packageJson.bin ?? {}),
    expected.bin ?? [],
  );
  assertFileExists(`${workspace} README`, path.join(workspace, "README.md"));
}

if (errors.length > 0) {
  throw new Error(`[check-workspace-manifests] Trust Registry workspace drift:\n${errors.map((error) => `- ${error}`).join("\n")}`);
}

return true;
}

if (process.argv[1] && fs.realpathSync(path.resolve(process.argv[1])) === fs.realpathSync(fileURLToPath(import.meta.url))) {
  try {
    checkWorkspaceManifests();
    console.log("[check-workspace-manifests] Trust Registry workspace manifests are aligned.");
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
