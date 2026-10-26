#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, existsSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { artifactDirectory, artifactWorkspaces, packageManifestCatalog, publishWorkspaces } from "./trust-registry-workspace-catalog.mjs";
import { missingFullContractArtifacts, proofCircuitNames } from "./package-contents-policy.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const HASH = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const CONTRACT_PREFIX = "package/dist/managed/trust-registry";
const hashBytes = (value) => createHash("sha256").update(value).digest("hex");
const sha256 = (path) => {
  const hash = createHash("sha256");
  const fd = openSync(path, "r");
  try {
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    let length;
    while ((length = readSync(fd, chunk, 0, chunk.length, null)) > 0) {
      hash.update(chunk.subarray(0, length));
    }
    return hash.digest("hex");
  } finally {
    closeSync(fd);
  }
};
const json = (path) => JSON.parse(readFileSync(path, "utf8"));

const packedFilename = (name, version) =>
  `${name.replace(/^@/u, "").replace("/", "-")}-${version}.tgz`;
const assertExactTarballs = (artifactDir, filenames) => {
  const present = readdirSync(artifactDir).filter((name) => name.endsWith(".tgz"));
  if (present.length !== filenames.size || present.some((name) => !filenames.has(name))) {
    throw new Error("Release candidate artifact directory contains unlisted tarballs");
  }
};

const packedEntries = (tarball) => run("tar", ["-tzf", tarball]).split("\n");
const packedContractInfo = (tarball) => JSON.parse(readPackedTarEntry(tarball,
  `${CONTRACT_PREFIX}/compiler/contract-info.json`).toString("utf8"));
const verifierKeyEntry = (name) => `${CONTRACT_PREFIX}/keys/${name}.verifier`;

function verifierKeyHashes(tarball, contractInfo) {
  const entries = packedEntries(tarball);
  assertFullPackedContract(entries, contractInfo);
  const names = proofCircuitNames(contractInfo).sort();
  const temporary = mkdtempSync(join(tmpdir(), "tr-verifier-keys-"));
  try {
    run("tar", ["-xzf", tarball, "-C", temporary, ...names.map(verifierKeyEntry)]);
    return Object.fromEntries(names.map((name) => {
      const keyPath = join(temporary, verifierKeyEntry(name));
      if (!lstatSync(keyPath).isFile()) throw new Error(`Packed verifier key is not a regular file: ${name}`);
      return [name, sha256(keyPath)];
    }));
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

export function buildReleaseCandidateManifest(input) {
  const { repoRoot, artifactDir, revision, workspaces = artifactWorkspaces,
    publish = publishWorkspaces } = input;
  if (!HASH.test(revision)) throw new Error("Release source must be a full Git commit SHA");
  const packageRoot = json(join(repoRoot, "package.json"));
  const packages = workspaces.map((workspace) => {
    const manifest = json(join(repoRoot, workspace, "package.json"));
    if (manifest.version !== packageRoot.version || typeof manifest.name !== "string") {
      throw new Error(`${workspace}: package identity or version disagrees with the release`);
    }
    const filename = packedFilename(manifest.name, manifest.version);
    const path = join(artifactDir, filename);
    if (!existsSync(path) || statSync(path).size === 0) {
      throw new Error(`${workspace}: packed artifact is missing or empty: ${filename}`);
    }
    return {
      workspace,
      name: manifest.name,
      version: manifest.version,
      publication: publish.includes(workspace) ? "npm" : "local-only",
      filename,
      sizeBytes: statSync(path).size,
      sha256: sha256(path),
    };
  });
  if (new Set(packages.map(({ filename }) => filename)).size !== packages.length) {
    throw new Error("Release packages have duplicate filenames");
  }
  assertExactTarballs(artifactDir, new Set(packages.map(({ filename }) => filename)));
  const contract = packages.find(({ workspace }) => workspace === "contracts/trust-registry");
  if (contract === undefined) throw new Error("Release contract package is missing");
  const contractTarball = join(artifactDir, contract.filename);
  const contractInfoPath = join(repoRoot,
    "contracts/trust-registry/dist/managed/trust-registry/compiler/contract-info.json");
  const contractInfo = json(contractInfoPath);
  if (hashPackedTarEntry(contractTarball, `${CONTRACT_PREFIX}/compiler/contract-info.json`)
    !== sha256(contractInfoPath)) {
    throw new Error("Packed contract metadata does not match the candidate tree");
  }
  const verifierKeySha256 = verifierKeyHashes(contractTarball, contractInfo);
  const sourceKeys = join(repoRoot, "contracts/trust-registry/dist/managed/trust-registry/keys");
  const sourceVerifierNames = readdirSync(sourceKeys).filter((name) => name.endsWith(".verifier"))
    .map((name) => name.slice(0, -".verifier".length)).sort();
  if (sourceVerifierNames.join("\0") !== Object.keys(verifierKeySha256).join("\0")) {
    throw new Error("Generated verifier keys do not match the proof-circuit catalog");
  }
  for (const [name, hash] of Object.entries(verifierKeySha256)) {
    const source = join(sourceKeys, `${name}.verifier`);
    if (!existsSync(source) || statSync(source).size === 0 || sha256(source) !== hash) {
      throw new Error(`Packed verifier key does not match the candidate tree: ${name}`);
    }
  }
  const dependencies = packageRoot.dependencies ?? {};
  return {
    format: "tr-release-candidate-manifest-v2",
    sourceRevision: revision,
    packageVersion: packageRoot.version,
    compactCompilerVersion: readFileSync(join(repoRoot, ".compact-version"), "utf8").trim(),
    packageManager: packageRoot.packageManager,
    lockfileSha256: sha256(join(repoRoot, "pnpm-lock.yaml")),
    contractSourceSha256: sha256(join(repoRoot, "contracts/trust-registry/src/trust-registry.compact")),
    generatedContractSha256: sha256(join(repoRoot, "contracts/trust-registry/dist/managed/trust-registry/contract/index.js")),
    verifierKeySha256,
    identityDependencies: Object.fromEntries(Object.entries(dependencies)
      .filter(([name]) => name.startsWith("@midnight-ntwrk/midnight-did")
        || name.startsWith("@midnight-ntwrk/credential-"))
      .sort(([left], [right]) => left.localeCompare(right))),
    packages,
  };
}

export function assertFullPackedContract(paths, contractInfo) {
  const listed = paths.filter((path) => path.length > 0);
  if (new Set(listed).size !== listed.length) {
    throw new Error("Packed contract contains duplicate archive paths");
  }
  const files = paths.map((path) => path.replace(/^package\//u, ""));
  const required = "dist/managed/trust-registry/compiler/contract-info.json";
  if (!files.includes(required)) throw new Error(`Packed contract is missing ${required}`);
  const missing = missingFullContractArtifacts(files, "trust-registry", proofCircuitNames(contractInfo));
  if (missing.length > 0) throw new Error(`Packed contract has incomplete proof artifacts: ${missing.join(" and ")}`);
}

export function verifyReleaseCandidateArtifacts(manifest, artifactDir, workspaces = artifactWorkspaces) {
  if (manifest?.format !== "tr-release-candidate-manifest-v2"
    || !HASH.test(manifest.sourceRevision)
    || !Array.isArray(manifest.packages)
    || manifest.packages.length !== workspaces.length) {
    throw new Error("Release candidate manifest format or package count is invalid");
  }
  if (typeof manifest.packageVersion !== "string" || manifest.packageVersion.length === 0
    || typeof manifest.compactCompilerVersion !== "string" || manifest.compactCompilerVersion.length === 0
    || !SHA256.test(manifest.lockfileSha256)
    || !SHA256.test(manifest.contractSourceSha256)
    || !SHA256.test(manifest.generatedContractSha256)) {
    throw new Error("Release candidate manifest identity or source hashes are invalid");
  }
  const expected = new Set(workspaces);
  const seen = new Set();
  const filenames = new Set();
  for (const entry of manifest.packages) {
    if (!expected.has(entry.workspace) || seen.has(entry.workspace)
      || entry.name !== packageManifestCatalog.get(entry.workspace)?.name
      || entry.version !== manifest.packageVersion
      || entry.filename !== packedFilename(entry.name, entry.version)
      || filenames.has(entry.filename)
      || typeof entry.filename !== "string"
      || !/^[a-z0-9][a-z0-9.-]*\.tgz$/u.test(entry.filename)
      || !SHA256.test(entry.sha256)
      || !Number.isSafeInteger(entry.sizeBytes) || entry.sizeBytes <= 0) {
      throw new Error("Release candidate package entry is invalid or duplicated");
    }
    seen.add(entry.workspace);
    filenames.add(entry.filename);
    const path = join(artifactDir, entry.filename);
    if (!existsSync(path) || statSync(path).size !== entry.sizeBytes || sha256(path) !== entry.sha256) {
      throw new Error(`Release candidate artifact hash or size mismatch: ${entry.filename}`);
    }
  }
  assertExactTarballs(artifactDir, filenames);
  const contract = manifest.packages.find(({ workspace }) => workspace === "contracts/trust-registry");
  if (contract === undefined) throw new Error("Release contract package is missing");
  const contractTarball = join(artifactDir, contract.filename);
  const contractInfo = packedContractInfo(contractTarball);
  const expectedHashes = verifierKeyHashes(contractTarball, contractInfo);
  const actualHashes = manifest.verifierKeySha256;
  if (actualHashes === null || typeof actualHashes !== "object" || Array.isArray(actualHashes)
    || Object.keys(actualHashes).length !== Object.keys(expectedHashes).length
    || Object.keys(actualHashes).some((name, index) => name !== Object.keys(expectedHashes)[index]
      || !SHA256.test(actualHashes[name]) || actualHashes[name] !== expectedHashes[name])) {
    throw new Error("Release candidate verifier-key hashes are invalid or incomplete");
  }
  return manifest.packages.map(({ filename }) => join(artifactDir, filename));
}

const run = (command, args, trim = true) => {
  const result = spawnSync(command, args, { cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.error?.message ?? result.stderr?.trim() ?? `exit ${result.status}`}`);
  }
  return trim ? result.stdout.trim() : result.stdout;
};

const readPackedTarEntry = (tarball, entry) => {
  const result = spawnSync("tar", ["-xOzf", tarball, entry], { maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0) {
    throw new Error(`tar could not read packed entry ${entry}: ${result.error?.message ?? result.stderr.toString().trim()}`);
  }
  if (result.stdout.length === 0) throw new Error(`Packed entry is empty: ${entry}`);
  return result.stdout;
};

export const hashPackedTarEntry = (tarball, entry) => hashBytes(readPackedTarEntry(tarball, entry));

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) throw new Error("Usage: node scripts/release-candidate-manifest.mjs");
  if (run("git", ["status", "--porcelain", "--untracked-files=normal"]) !== "") {
    throw new Error("Release candidate source tree must be clean");
  }
  run("git", ["verify-commit", "HEAD"]);
  if (!/^Signed-off-by: .+ <[^>]+>$/mu.test(run("git", ["log", "-1", "--format=%B"]))) {
    throw new Error("Release source commit must carry a DCO sign-off");
  }
  run("node", ["scripts/check-full-contract-artifacts.mjs"]);
  const revision = run("git", ["rev-parse", "HEAD"]);
  const manifest = buildReleaseCandidateManifest({
    repoRoot: root,
    artifactDir: join(root, artifactDirectory),
    revision,
  });
  const contract = manifest.packages.find(({ workspace }) => workspace === "contracts/trust-registry");
  if (contract === undefined) throw new Error("Release contract package is missing");
  const packedPaths = packedEntries(join(root, artifactDirectory, contract.filename));
  const contractTarball = join(root, artifactDirectory, contract.filename);
  const contractInfo = json(join(root,
    "contracts/trust-registry/dist/managed/trust-registry/compiler/contract-info.json"));
  assertFullPackedContract(packedPaths, contractInfo);
  for (const [packed, source] of [
    ["package/src/trust-registry.compact", "contracts/trust-registry/src/trust-registry.compact"],
    ["package/dist/managed/trust-registry/contract/index.js",
      "contracts/trust-registry/dist/managed/trust-registry/contract/index.js"],
  ]) {
    if (hashPackedTarEntry(contractTarball, packed) !== sha256(join(root, source))) {
      throw new Error(`Packed contract does not match the candidate tree: ${packed}`);
    }
  }
  const output = join(root, "artifacts/release-candidate", revision, "manifest.json");
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "w", mode: 0o600 });
  process.stdout.write(`Release candidate manifest: artifacts/release-candidate/${revision}/${basename(output)}\n`);
}
