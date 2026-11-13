#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import { createHash } from "node:crypto";
import { closeSync, existsSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { artifactDirectory, artifactWorkspaces, packageManifestCatalog, publishWorkspaces } from "./trust-registry-workspace-catalog.mjs";
import { missingFullContractArtifacts, proofCircuitNames } from "./package-contents-policy.mjs";
import { exactStringSet } from "./standalone-exact-fields-policy.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const HASH = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const CONTRACT_PREFIX = "package/dist/managed/trust-registry";
const CONTRACT_SOURCE_ENTRY = "package/src/trust-registry.compact";
const GENERATED_CONTRACT_ENTRY = `${CONTRACT_PREFIX}/contract/index.js`;
const KEYLESS_ENTRY = `${CONTRACT_PREFIX}/keyless-manifest.json`;
/** @typedef {{workspace: string, name: string, version: string, filename: string, sha256: string, sizeBytes: number, publication?: string}} ReleasePackageEntry */
/** @typedef {{manifestSha256: string, keygenSha256: string, platform: string, proverKeySha256: Record<string, string>}} KeylessCandidate */
/** @typedef {{format: string, sourceRevision: string, packageVersion: string, compactCompilerVersion: string, lockfileSha256: string, contractSourceSha256: string, generatedContractSha256: string, verifierKeySha256: unknown, packages: ReleasePackageEntry[], keyless?: KeylessCandidate}} ReleaseCandidateManifest */
/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
/** @param {string | Buffer} value */
const hashBytes = (value) => createHash("sha256").update(value).digest("hex");
/** @param {string} path */
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
/** @param {string} path @returns {unknown} */
const json = (path) => JSON.parse(readFileSync(path, "utf8"));

/** @param {string} name @param {string} version */
const packedFilename = (name, version) =>
  `${name.replace(/^@/u, "").replace("/", "-")}-${version}.tgz`;
/** @param {string} artifactDir @param {Set<string>} filenames */
const assertExactTarballs = (artifactDir, filenames) => {
  const present = readdirSync(artifactDir).filter((name) => name.endsWith(".tgz"));
  if (present.length !== filenames.size || present.some((name) => !filenames.has(name))) {
    throw new Error("Release candidate artifact directory contains unlisted tarballs");
  }
};

/** @param {string} path */
const packedTarballSize = (path) => {
  if (!existsSync(path)) throw new Error(`Packed artifact is missing or empty: ${path}`);
  const file = lstatSync(path);
  if (!file.isFile() || file.nlink !== 1) {
    throw new Error(`Packed artifact must be a single-link regular file: ${path}`);
  }
  if (file.size === 0) throw new Error(`Packed artifact is missing or empty: ${path}`);
  return file.size;
};

/** @param {string} tarball */
export function packedEntries(tarball) {
  const paths = run("tar", ["-tzf", tarball]).split("\n").filter(Boolean);
  const verbose = run("tar", ["-tvzf", tarball]).split("\n").filter(Boolean);
  if (paths.length !== verbose.length) {
    throw new Error("Packed package archive listings disagree");
  }
  for (let index = 0; index < paths.length; index += 1) {
    const expectedType = paths[index].endsWith("/") ? "d" : "-";
    if (verbose[index][0] !== expectedType) {
      throw new Error(`Packed package contains a non-regular archive entry: ${paths[index]}`);
    }
  }
  return paths;
}
/** @param {string} tarball @param {string} name @param {string} version */
const assertPackedPackageIdentity = (tarball, name, version) => {
  /** @type {unknown} */
  const manifest = JSON.parse(readPackedTarEntry(tarball, "package/package.json").toString("utf8"));
  if (!isRecord(manifest) || manifest.name !== name || manifest.version !== version) {
    throw new Error(`Packed package identity differs from candidate workspace: ${name}`);
  }
};
/** @param {string} tarball @returns {unknown} */
const packedContractInfo = (tarball) => JSON.parse(readPackedTarEntry(tarball,
  `${CONTRACT_PREFIX}/compiler/contract-info.json`).toString("utf8"));
/** @param {string} name */
const verifierKeyEntry = (name) => `${CONTRACT_PREFIX}/keys/${name}.verifier`;

/** @param {string} tarball @param {unknown} contractInfo */
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

/** @param {string} tarball @param {unknown} contractInfo @param {string} trustedDigest
 * @returns {{sourceRevision: string, keygenSha256: string, platform: string, keys: Record<string, string>, assets: Record<string, string>}} */
function keylessContractManifest(tarball, contractInfo, trustedDigest) {
  if (!SHA256.test(trustedDigest)) throw new Error("Trusted keyless manifest digest is required");
  if (!isRecord(contractInfo)) throw new Error("Keyless contract metadata is invalid");
  const entries = packedEntries(tarball);
  assertCanonicalPackedPaths(entries);
  if (entries.some((entry) => /\.(?:prover|verifier)$/u.test(entry))) {
    throw new Error("Keyless contract package contains prover or verifier key bytes");
  }
  const names = proofCircuitNames(contractInfo).sort();
  const assets = ["compiler/contract-info.json", "contract/index.d.ts", "contract/index.js",
    "contract/index.js.map", ...names.flatMap((name) => [`zkir/${name}.zkir`, `zkir/${name}.bzkir`])].sort();
  const keys = names.flatMap((name) => [`${name}.prover`, `${name}.verifier`]).sort();
  const actual = entries.filter((entry) => entry.startsWith(`${CONTRACT_PREFIX}/`) && !entry.endsWith("/"))
    .map((entry) => entry.slice(`${CONTRACT_PREFIX}/`.length));
  if (!exactStringSet(actual, [...assets, "keyless-manifest.json"])) {
    throw new Error("Keyless contract has missing, extra, or renamed managed files");
  }
  const bytes = readPackedTarEntry(tarball, KEYLESS_ENTRY);
  if (hashBytes(bytes) !== trustedDigest) throw new Error("Keyless manifest digest differs from release pin");
  const manifest = JSON.parse(bytes.toString("utf8"));
  if (!isRecord(manifest) || manifest.format !== "tr-keyless-zkir-v1"
    || typeof manifest.sourceRevision !== "string" || !HASH.test(manifest.sourceRevision)
    || manifest.compilerVersion !== contractInfo["compiler-version"]
    || manifest.platform !== "linux/arm64"
    || typeof manifest.keygenSha256 !== "string" || !SHA256.test(manifest.keygenSha256)
    || !isRecord(manifest.assets) || !isRecord(manifest.keys)
    || !exactStringSet(Object.keys(manifest.assets), assets)
    || !exactStringSet(Object.keys(manifest.keys), keys)) {
    throw new Error("Keyless contract manifest identity or circuit catalog is invalid");
  }
  const assetHashes = /** @type {Record<string, string>} */ (manifest.assets);
  const keyHashes = /** @type {Record<string, string>} */ (manifest.keys);
  for (const asset of assets) {
    if (!SHA256.test(assetHashes[asset])
      || hashPackedTarEntry(tarball, `${CONTRACT_PREFIX}/${asset}`) !== assetHashes[asset]) {
      throw new Error(`Keyless contract asset hash mismatch: ${asset}`);
    }
  }
  if (keys.some((name) => !SHA256.test(keyHashes[name]))) {
    throw new Error("Keyless contract expected-key hash is invalid");
  }
  return { sourceRevision: /** @type {string} */ (manifest.sourceRevision),
    keygenSha256: /** @type {string} */ (manifest.keygenSha256),
    platform: /** @type {string} */ (manifest.platform), keys: keyHashes, assets: assetHashes };
}

/** @param {{repoRoot: string, artifactDir: string, revision: string, workspaces?: readonly string[], publish?: readonly string[], keylessManifestSha256?: string}} input */
export function buildReleaseCandidateManifest(input) {
  const { repoRoot, artifactDir, revision, workspaces = artifactWorkspaces,
    publish = publishWorkspaces, keylessManifestSha256 } = input;
  if (!HASH.test(revision)) throw new Error("Release source must be a full Git commit SHA");
  const packageRoot = json(join(repoRoot, "package.json"));
  if (!isRecord(packageRoot) || typeof packageRoot.version !== "string"
    || typeof packageRoot.packageManager !== "string") {
    throw new Error("Release root package identity is invalid");
  }
  const packages = workspaces.map((workspace) => {
    const manifest = json(join(repoRoot, workspace, "package.json"));
    if (!isRecord(manifest) || manifest.version !== packageRoot.version
      || typeof manifest.name !== "string" || typeof manifest.version !== "string") {
      throw new Error(`${workspace}: package identity or version disagrees with the release`);
    }
    const filename = packedFilename(manifest.name, manifest.version);
    const path = join(artifactDir, filename);
    const sizeBytes = packedTarballSize(path);
    const entries = packedEntries(path);
    assertCanonicalPackedPaths(entries);
    assertRequiredPackedPaths(entries, workspace);
    assertPackedPackageIdentity(path, manifest.name, manifest.version);
    return {
      workspace,
      name: manifest.name,
      version: manifest.version,
      publication: keylessManifestSha256 !== undefined ? "local-only"
        : publish.includes(workspace) ? "npm" : "local-only",
      filename,
      sizeBytes,
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
  if (!isRecord(contractInfo) || typeof contractInfo["compiler-version"] !== "string") {
    throw new Error("Generated contract metadata is invalid");
  }
  const compactCompilerVersion = readFileSync(join(repoRoot, ".compact-version"), "utf8").trim();
  if (contractInfo["compiler-version"] !== compactCompilerVersion) {
    throw new Error("Generated contract compiler version differs from the candidate toolchain pin");
  }
  if (hashPackedTarEntry(contractTarball, `${CONTRACT_PREFIX}/compiler/contract-info.json`)
    !== sha256(contractInfoPath)) {
    throw new Error("Packed contract metadata does not match the candidate tree");
  }
  for (const [packed, source] of [
    [CONTRACT_SOURCE_ENTRY, "contracts/trust-registry/src/trust-registry.compact"],
    [GENERATED_CONTRACT_ENTRY, "contracts/trust-registry/dist/managed/trust-registry/contract/index.js"],
  ]) {
    if (hashPackedTarEntry(contractTarball, packed) !== sha256(join(repoRoot, source))) {
      throw new Error(`Packed contract does not match the candidate tree: ${packed}`);
    }
  }
  const keyless = keylessManifestSha256 === undefined ? null
    : keylessContractManifest(contractTarball, contractInfo, keylessManifestSha256);
  if (keyless !== null && keyless.sourceRevision !== revision) {
    throw new Error("Keyless contract manifest differs from signed source revision");
  }
  const verifierKeySha256 = keyless === null ? verifierKeyHashes(contractTarball, contractInfo)
    : Object.fromEntries(Object.entries(keyless.keys).filter(([name]) => name.endsWith(".verifier"))
      .map(([name, hash]) => [name.slice(0, -".verifier".length), hash]));
  const sourceKeys = join(repoRoot, "contracts/trust-registry/dist/managed/trust-registry/keys");
  const sourceVerifierNames = readdirSync(sourceKeys).filter((name) => name.endsWith(".verifier"))
    .map((name) => name.slice(0, -".verifier".length)).sort();
  if (!exactStringSet(sourceVerifierNames, Object.keys(verifierKeySha256))) {
    throw new Error("Generated verifier keys do not match the proof-circuit catalog");
  }
  for (const [name, hash] of Object.entries(verifierKeySha256)) {
    const source = join(sourceKeys, `${name}.verifier`);
    if (!existsSync(source) || statSync(source).size === 0 || sha256(source) !== hash) {
      throw new Error(`Packed verifier key does not match the candidate tree: ${name}`);
    }
  }
  if (keyless !== null) {
    const sourceProverNames = readdirSync(sourceKeys).filter((name) => name.endsWith(".prover"))
      .map((name) => name.slice(0, -".prover".length)).sort();
    if (!exactStringSet(sourceProverNames, Object.keys(verifierKeySha256))) {
      throw new Error("Generated prover keys do not match the proof-circuit catalog");
    }
    for (const name of sourceProverNames) {
      if (sha256(join(sourceKeys, `${name}.prover`)) !== keyless.keys[`${name}.prover`]) {
        throw new Error(`Expected prover key does not match the candidate tree: ${name}`);
      }
    }
  }
  const dependencies = isRecord(packageRoot.dependencies) ? packageRoot.dependencies : {};
  if (Object.values(dependencies).some((value) => typeof value !== "string")) {
    throw new Error("Release identity dependencies must be version strings");
  }
  return {
    format: keyless === null ? "tr-release-candidate-manifest-v2" : "tr-release-candidate-manifest-v3",
    sourceRevision: revision,
    packageVersion: packageRoot.version,
    compactCompilerVersion,
    packageManager: packageRoot.packageManager,
    lockfileSha256: sha256(join(repoRoot, "pnpm-lock.yaml")),
    contractSourceSha256: sha256(join(repoRoot, "contracts/trust-registry/src/trust-registry.compact")),
    generatedContractSha256: sha256(join(repoRoot, "contracts/trust-registry/dist/managed/trust-registry/contract/index.js")),
    verifierKeySha256,
    ...(keyless === null ? {} : { keyless: { manifestSha256: keylessManifestSha256,
      keygenSha256: keyless.keygenSha256, platform: keyless.platform,
      proverKeySha256: Object.fromEntries(Object.entries(keyless.keys)
        .filter(([name]) => name.endsWith(".prover"))
        .map(([name, hash]) => [name.slice(0, -".prover".length), hash])) } }),
    identityDependencies: Object.fromEntries(Object.entries(dependencies)
      .filter(([name]) => name.startsWith("@midnight-ntwrk/midnight-did")
        || name.startsWith("@midnight-ntwrk/credential-"))
      .sort(([left], [right]) => left.localeCompare(right))),
    packages,
  };
}

/** @param {string[]} paths @param {unknown} contractInfo */
export function assertFullPackedContract(paths, contractInfo) {
  assertCanonicalPackedPaths(paths);
  const files = paths.map((path) => path.replace(/^package\//u, ""));
  const required = "dist/managed/trust-registry/compiler/contract-info.json";
  if (!files.includes(required)) throw new Error(`Packed contract is missing ${required}`);
  const missing = missingFullContractArtifacts(files, "trust-registry", proofCircuitNames(contractInfo));
  if (missing.length > 0) throw new Error(`Packed contract has incomplete proof artifacts: ${missing.join(" and ")}`);
}

/** @param {string[]} paths */
export function assertCanonicalPackedPaths(paths) {
  const listed = paths.filter((path) => path.length > 0);
  const normalized = listed.map((path) => path.endsWith("/") ? path.slice(0, -1) : path);
  if (new Set(normalized).size !== listed.length) {
    throw new Error("Packed package contains duplicate archive paths");
  }
  const portable = normalized.map((path) => path.normalize("NFC").toLowerCase());
  if (new Set(portable).size !== listed.length) {
    throw new Error("Packed package contains case or Unicode alias archive paths");
  }
  for (const path of listed) {
    if (!path.startsWith("package/") || /[\\\x00-\x1f\x7f]/u.test(path)) {
      throw new Error("Packed package contains non-canonical archive paths");
    }
    const relative = path.slice("package/".length);
    if (relative === "") continue;
    const segments = relative.split("/");
    if (path.endsWith("/")) segments.pop();
    if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
      throw new Error("Packed package contains non-canonical archive paths");
    }
  }
}

/** @param {string[]} paths @param {string} workspace */
export function assertRequiredPackedPaths(paths, workspace) {
  const required = packageManifestCatalog.get(workspace)?.requiredPackedPaths;
  if (!Array.isArray(required) || required.length === 0) {
    throw new Error(`Release package has no required-path catalog: ${workspace}`);
  }
  const files = new Set(paths.filter((path) => path.startsWith("package/") && !path.endsWith("/"))
    .map((path) => path.slice("package/".length)));
  const missing = required.filter((path) => !files.has(path));
  if (missing.length > 0) {
    throw new Error(`${workspace}: packed artifact is missing required files: ${missing.join(", ")}`);
  }
}

/** @param {unknown} value @returns {value is ReleasePackageEntry} */
const isReleasePackageEntry = (value) => isRecord(value)
  && typeof value.workspace === "string" && typeof value.name === "string"
  && typeof value.version === "string" && typeof value.filename === "string"
  && typeof value.sha256 === "string" && typeof value.sizeBytes === "number";

/** @param {unknown} value @returns {value is ReleaseCandidateManifest} */
const isReleaseCandidateManifest = (value) => isRecord(value)
  && typeof value.format === "string" && typeof value.sourceRevision === "string"
  && typeof value.packageVersion === "string" && typeof value.compactCompilerVersion === "string"
  && typeof value.lockfileSha256 === "string" && typeof value.contractSourceSha256 === "string"
  && typeof value.generatedContractSha256 === "string"
  && Array.isArray(value.packages)
  && value.packages.every(isReleasePackageEntry);

/** @param {unknown} manifest @param {string} artifactDir @param {readonly string[]} [workspaces] */
export function verifyReleaseCandidateArtifacts(manifest, artifactDir, workspaces = artifactWorkspaces) {
  if (!isReleaseCandidateManifest(manifest)
    || !["tr-release-candidate-manifest-v2", "tr-release-candidate-manifest-v3"].includes(manifest.format)
    || !HASH.test(manifest.sourceRevision)
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
      || (manifest.format === "tr-release-candidate-manifest-v3"
        && entry.publication !== "local-only")
      || !Number.isSafeInteger(entry.sizeBytes) || entry.sizeBytes <= 0) {
      throw new Error("Release candidate package entry is invalid or duplicated");
    }
    seen.add(entry.workspace);
    filenames.add(entry.filename);
    const path = join(artifactDir, entry.filename);
    if (packedTarballSize(path) !== entry.sizeBytes || sha256(path) !== entry.sha256) {
      throw new Error(`Release candidate artifact hash or size mismatch: ${entry.filename}`);
    }
    const entries = packedEntries(path);
    assertCanonicalPackedPaths(entries);
    assertRequiredPackedPaths(entries, entry.workspace);
    assertPackedPackageIdentity(path, entry.name, entry.version);
  }
  assertExactTarballs(artifactDir, filenames);
  const contract = manifest.packages.find(({ workspace }) => workspace === "contracts/trust-registry");
  if (contract === undefined) throw new Error("Release contract package is missing");
  const contractTarball = join(artifactDir, contract.filename);
  if (hashPackedTarEntry(contractTarball, CONTRACT_SOURCE_ENTRY) !== manifest.contractSourceSha256
    || hashPackedTarEntry(contractTarball, GENERATED_CONTRACT_ENTRY) !== manifest.generatedContractSha256) {
    throw new Error("Release candidate packed contract source or generated contract hash mismatch");
  }
  const contractInfo = packedContractInfo(contractTarball);
  if (!isRecord(contractInfo)
    || contractInfo["compiler-version"] !== manifest.compactCompilerVersion) {
    throw new Error("Release candidate compiler version differs from packed contract metadata");
  }
  const keyless = manifest.format === "tr-release-candidate-manifest-v3"
    ? keylessContractManifest(contractTarball, contractInfo, manifest.keyless?.manifestSha256 ?? "")
    : null;
  if ((keyless === null && manifest.keyless !== undefined)
    || (keyless !== null && (!isRecord(manifest.keyless)
      || !exactStringSet(Object.keys(manifest.keyless),
        ["manifestSha256", "keygenSha256", "platform", "proverKeySha256"])))) {
    throw new Error("Release candidate keyless mode is malformed");
  }
  if (keyless !== null && (keyless.sourceRevision !== manifest.sourceRevision
    || keyless.keygenSha256 !== manifest.keyless?.keygenSha256
    || keyless.platform !== manifest.keyless?.platform)) {
    throw new Error("Keyless contract toolchain or source differs from the release manifest");
  }
  const expectedHashes = keyless === null ? verifierKeyHashes(contractTarball, contractInfo)
    : Object.fromEntries(Object.entries(keyless.keys).filter(([name]) => name.endsWith(".verifier"))
      .map(([name, hash]) => [name.slice(0, -".verifier".length), hash]));
  const actualHashes = manifest.verifierKeySha256;
  if (!isRecord(actualHashes)
    || Object.keys(actualHashes).length !== Object.keys(expectedHashes).length
    || Object.keys(actualHashes).some((name, index) => name !== Object.keys(expectedHashes)[index]
      || typeof actualHashes[name] !== "string"
      || !SHA256.test(actualHashes[name]) || actualHashes[name] !== expectedHashes[name])) {
    throw new Error("Release candidate verifier-key hashes are invalid or incomplete");
  }
  if (keyless !== null) {
    const expectedProvers = Object.fromEntries(Object.entries(keyless.keys)
      .filter(([name]) => name.endsWith(".prover"))
      .map(([name, hash]) => [name.slice(0, -".prover".length), hash]));
    if (!isRecord(manifest.keyless?.proverKeySha256)
      || !isDeepStrictEqual(manifest.keyless.proverKeySha256, expectedProvers)) {
      throw new Error("Release candidate prover-key hashes are invalid or incomplete");
    }
  }
  return manifest.packages.map(({ filename }) => join(artifactDir, filename));
}

/** @param {string} command @param {string[]} args @param {boolean} [trim] */
const run = (command, args, trim = true) => {
  const result = spawnSync(command, args, { cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.error?.message ?? result.stderr?.trim() ?? `exit ${result.status}`}`);
  }
  return trim ? result.stdout.trim() : result.stdout;
};

/** @param {string} revision */
function verifySignedHead(revision) {
  if (process.env.TR_MANIFEST_GITHUB_VERIFIED_COMMIT !== "true") {
    run("git", ["verify-commit", "HEAD"]);
    return;
  }
  const repository = process.env.GITHUB_REPOSITORY;
  if (process.env.GITHUB_ACTIONS !== "true"
    || process.env.GITHUB_SHA !== revision
    || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository ?? "")
    || !process.env.GH_TOKEN) {
    throw new Error("GitHub signature verification requires the exact Actions checkout and token");
  }
  const verification = JSON.parse(run("gh", ["api", `repos/${repository}/commits/${revision}`,
    "--jq", ".commit.verification"]));
  if (verification.verified !== true || verification.reason !== "valid") {
    throw new Error("GitHub did not verify the exact release source commit signature");
  }
}

/** @param {string} tarball @param {string} entry */
const readPackedTarEntry = (tarball, entry) => {
  const result = spawnSync("tar", ["-xOzf", tarball, entry], { maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0) {
    throw new Error(`tar could not read packed entry ${entry}: ${result.error?.message ?? result.stderr.toString().trim()}`);
  }
  if (result.stdout.length === 0) throw new Error(`Packed entry is empty: ${entry}`);
  return result.stdout;
};

/** @param {string} tarball @param {string} entry */
export const hashPackedTarEntry = (tarball, entry) => hashBytes(readPackedTarEntry(tarball, entry));

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let artifactDir = join(root, artifactDirectory);
  let output;
  let verifyPath;
  let keylessManifestSha256;
  for (let index = 2; index < process.argv.length; index += 1) {
    const option = process.argv[index];
    if (!["--artifact-dir", "--output", "--verify", "--keyless-manifest-sha256"].includes(option)
      || !process.argv[index + 1]) {
      throw new Error("Usage: release-candidate-manifest.mjs [--artifact-dir dir] [--keyless-manifest-sha256 sha256] [--output file | --verify file]");
    }
    const value = process.argv[++index];
    if (option === "--artifact-dir") artifactDir = resolve(value);
    else if (option === "--output") output = resolve(value);
    else if (option === "--verify") verifyPath = resolve(value);
    else keylessManifestSha256 = value;
  }
  if (output && verifyPath) throw new Error("Choose manifest output or verification, not both");
  if (run("git", ["status", "--porcelain", "--untracked-files=normal"]) !== "") {
    throw new Error("Release candidate source tree must be clean");
  }
  const revision = run("git", ["rev-parse", "HEAD"]);
  verifySignedHead(revision);
  if (!/^Signed-off-by: .+ <[^>]+>$/mu.test(run("git", ["log", "-1", "--format=%B"]))) {
    throw new Error("Release source commit must carry a DCO sign-off");
  }
  run("node", ["scripts/check-full-contract-artifacts.mjs"]);
  const manifest = buildReleaseCandidateManifest({
    repoRoot: root,
    artifactDir,
    revision,
    keylessManifestSha256,
  });
  verifyReleaseCandidateArtifacts(manifest, artifactDir);
  if (verifyPath) {
    const approved = json(verifyPath);
    if (!isDeepStrictEqual(approved, manifest)) {
      throw new Error("Release candidate manifest differs from the exact signed source and packed bytes");
    }
    process.stdout.write(`Verified release candidate manifest: ${verifyPath}\n`);
  } else {
    const destination = output ?? join(root, "artifacts/release-candidate", revision, "manifest.json");
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "w", mode: 0o600 });
    process.stdout.write(`Release candidate manifest: ${destination}\n`);
  }
}
