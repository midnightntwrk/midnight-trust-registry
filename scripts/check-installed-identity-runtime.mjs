#!/usr/bin/env node

import { readFileSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const runtimeName = "@midnight-ntwrk/compact-runtime";
const sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const declarations = (manifest, name) => sections.flatMap((section) =>
  manifest[section]?.[name] === undefined ? [] : [`${section}: ${manifest[section][name]}`]);

function resolvedPackageManifest(fromManifest, name) {
  const packageRequire = createRequire(fromManifest);
  let directory = dirname(packageRequire.resolve(name));
  while (true) {
    try {
      const manifest = readJson(join(directory, "package.json"));
      if (manifest.name === name) return manifest;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    const parent = dirname(directory);
    if (parent === directory) throw new Error(`could not locate resolved ${name} package manifest`);
    directory = parent;
  }
}

export function checkInstalledIdentityRuntime(directory = root) {
  const rootManifest = readJson(join(directory, "package.json"));
  const runtimePin = readJson(join(directory, "contracts/trust-registry/package.json"))
    .dependencies?.[runtimeName];
  if (!/^\d+\.\d+\.\d+$/.test(runtimePin ?? "")) {
    throw new Error("contract Compact runtime must be pinned to an exact version");
  }

  const overrides = yaml.load(readFileSync(join(directory, "pnpm-workspace.yaml"), "utf8"))?.overrides ?? {};
  const identities = Object.entries(rootManifest.dependencies ?? {})
    .filter(([name]) => name.startsWith("@midnight-ntwrk/") && !name.includes("trust-registry"));
  if (identities.length === 0) throw new Error("no root identity dependencies found");
  const identityNames = new Set(identities.map(([name]) => name));
  const runtimeDeclarers = new Set();
  const missingRuntime = [];

  if (overrides[runtimeName] !== undefined && overrides[runtimeName] !== runtimePin) {
    throw new Error(`Compact runtime override ${overrides[runtimeName]} does not match ${runtimePin}`);
  }

  for (const [name, pinnedVersion] of identities) {
    if (overrides[name] !== pinnedVersion) {
      throw new Error(`${name} override ${overrides[name] ?? "missing"} does not match ${pinnedVersion}`);
    }
    const manifestPath = realpathSync(join(directory, "node_modules", name, "package.json"));
    const manifest = readJson(manifestPath);
    if (manifest.version !== pinnedVersion) {
      throw new Error(`${name} installed ${manifest.version} does not match ${pinnedVersion}`);
    }
    const declared = declarations(manifest, runtimeName);
    if (declared.length === 0) {
      missingRuntime.push([name, manifest, manifestPath]);
      continue;
    }
    if (declared.some((value) => !value.endsWith(`: ${runtimePin}`))) {
      throw new Error(`${name} declares Compact runtime ${declared.join(", ")}, expected ${runtimePin}`);
    }
    const installedRuntime = resolvedPackageManifest(manifestPath, runtimeName).version;
    if (installedRuntime !== runtimePin) {
      throw new Error(`${name} resolves Compact runtime ${installedRuntime}, expected ${runtimePin}`);
    }
    runtimeDeclarers.add(name);
  }

  for (const [name, manifest, manifestPath] of missingRuntime) {
    const delegates = Object.keys(manifest.dependencies ?? {})
      .filter((dependency) => identityNames.has(dependency) && runtimeDeclarers.has(dependency));
    if (delegates.length === 0) {
      throw new Error(`${name} neither declares Compact runtime nor delegates to a verified identity package`);
    }
    for (const delegate of delegates) {
      const installedDelegate = resolvedPackageManifest(manifestPath, delegate);
      if (installedDelegate.version !== rootManifest.dependencies[delegate]) {
        throw new Error(`${name} resolves ${delegate}@${installedDelegate.version}, expected ${rootManifest.dependencies[delegate]}`);
      }
    }
  }
  return { runtimePin, identityCount: identities.length };
}

if (process.argv[1] && realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))) {
  try {
    const result = checkInstalledIdentityRuntime();
    console.log(`Installed identity runtime ${result.runtimePin} verified for ${result.identityCount} packages`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
