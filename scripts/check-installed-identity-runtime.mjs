#!/usr/bin/env node

import { readFileSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import semver from "semver";
import yaml from "js-yaml";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const runtimeName = "@midnight-ntwrk/compact-runtime";
const runtimeSections = ["dependencies", "peerDependencies"];
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const declarations = (manifest, name) => runtimeSections.flatMap((section) =>
  manifest[section]?.[name] === undefined ? [] : [`${section}: ${manifest[section][name]}`]);
const isIdentity = (name) => /^@midnight-ntwrk\/(?:midnight-did(?:-|$)|credential-)/.test(name);
const overrideValues = (overrides, name) => Object.entries(overrides)
  .filter(([selector]) => {
    const target = selector.split(">").at(-1);
    return target === name || target.startsWith(`${name}@`);
  })
  .map(([, value]) => value);

function resolvedPackageManifest(fromManifest, name) {
  const packageRequire = createRequire(fromManifest);
  let directory = dirname(packageRequire.resolve(name));
  while (true) {
    try {
      const manifest = readJson(join(directory, "package.json"));
      if (manifest.name === name) return { manifest, manifestPath: join(directory, "package.json") };
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
    .filter(([name]) => isIdentity(name));
  if (identities.length === 0) throw new Error("no root identity dependencies found");
  const installed = new Map();

  for (const value of overrideValues(overrides, runtimeName)) {
    if (value !== runtimePin) {
      throw new Error(`Compact runtime override ${value} does not match ${runtimePin}`);
    }
  }

  for (const [name, pinnedVersion] of identities) {
    const values = overrideValues(overrides, name);
    if (values.length === 0 || values.some((value) => value !== pinnedVersion)) {
      throw new Error(`${name} override ${values.join(", ") || "missing"} does not match ${pinnedVersion}`);
    }
    let manifestPath;
    try {
      manifestPath = realpathSync(join(directory, "node_modules", name, "package.json"));
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      throw new Error(`Missing installed identity package ${name}`, { cause: error });
    }
    const manifest = readJson(manifestPath);
    if (manifest.version !== pinnedVersion) {
      throw new Error(`${name} installed ${manifest.version} does not match ${pinnedVersion}`);
    }
    installed.set(name, { manifest, manifestPath });
  }

  const verified = new Set();
  const verifyDelegation = ({ manifest, manifestPath }, visiting = new Set()) => {
    if (verified.has(manifestPath)) return;
    if (visiting.has(manifestPath)) throw new Error(`${manifest.name} has a cyclic identity runtime delegation`);
    const declared = declarations(manifest, runtimeName);
    if (declared.some((value) => !value.endsWith(`: ${runtimePin}`))) {
      throw new Error(`${manifest.name} declares Compact runtime ${declared.join(", ")}, expected ${runtimePin}`);
    }
    const directRuntime = declared.length > 0;
    const delegates = runtimeSections.flatMap((section) => Object.entries(manifest[section] ?? {}))
      .filter(([dependency]) => isIdentity(dependency));
    if (!directRuntime && delegates.length === 0) {
      throw new Error(`${manifest.name} neither declares Compact runtime nor delegates to a verified identity package`);
    }
    visiting.add(manifestPath);
    for (const [delegate, declaredVersion] of delegates) {
      let resolved;
      try {
        resolved = resolvedPackageManifest(manifestPath, delegate);
      } catch (error) {
        if (error.code !== "MODULE_NOT_FOUND") throw error;
        throw new Error(`${manifest.name} cannot resolve identity dependency ${delegate}`, { cause: error });
      }
      if (!semver.satisfies(resolved.manifest.version, declaredVersion)) {
        throw new Error(`${manifest.name} resolves ${delegate}@${resolved.manifest.version}, incompatible with ${declaredVersion}`);
      }
      const rootPin = rootManifest.dependencies?.[delegate];
      if (rootPin && resolved.manifest.version !== rootPin) {
        throw new Error(`${manifest.name} resolves ${delegate}@${resolved.manifest.version}, expected ${rootPin}`);
      }
      verifyDelegation(resolved, visiting);
    }
    visiting.delete(manifestPath);
    try {
      const resolvedRuntime = resolvedPackageManifest(manifestPath, runtimeName).manifest.version;
      if (resolvedRuntime !== runtimePin) {
        throw new Error(`${manifest.name} resolves Compact runtime ${resolvedRuntime}, expected ${runtimePin}`);
      }
    } catch (error) {
      if (error.code !== "MODULE_NOT_FOUND") throw error;
      if (directRuntime) throw new Error(`${manifest.name} cannot resolve declared Compact runtime`, { cause: error });
    }
    verified.add(manifestPath);
  };
  for (const [name] of identities) verifyDelegation(installed.get(name));
  return {
    runtimePin,
    identityCount: identities.length,
    directRuntimeCount: [...installed.values()].filter(({ manifest }) => declarations(manifest, runtimeName).length > 0).length,
  };
}

if (process.argv[1] && realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))) {
  try {
    const result = checkInstalledIdentityRuntime();
    console.log(`Installed identity runtime ${result.runtimePin}: ${result.identityCount} identity packages checked, ${result.directRuntimeCount} direct runtime declarations`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
