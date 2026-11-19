import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { verifyKeylessContractPackage } from "./pack-keyless-contract.mjs";
import { assertCanonicalPackedPaths, assertRequiredPackedPaths, hashPackedTarEntry,
  packedEntries, verifySignedHead } from "./release-candidate-manifest.mjs";
import { selectPublishVersion } from "./select-publish-version.mjs";
import { artifactWorkspaces, packageManifestCatalog, publishWorkspaces } from "./trust-registry-workspace-catalog.mjs";

export const KEYLESS_NPM_FORMAT = "tr-keyless-npm-release-v1";
export const REGENERATION_CIRCUITS = ["activateIssuerAuthorization", "getCurrentIssuerAuthorization"];
const CONTRACT = "contracts/trust-registry";
const MANAGED = "package/dist/managed/trust-registry";
const SHA256 = /^[a-f0-9]{64}$/u;
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const json = async (file) => JSON.parse(await readFile(file, "utf8"));
const git = (args) => execFileSync("git", args, { encoding: "utf8" }).trim();

export async function buildKeylessNpmRelease(directory, revision) {
  const packageVersion = selectPublishVersion((await json("package.json")).version);
  const receipt = await json(join(directory, "cache-receipt.json"));
  const regeneration = await json(join(directory, "key-regeneration.json"));
  if (!/^[a-f0-9]{40}$/u.test(revision) || receipt.sourceRevision !== revision
    || !SHA256.test(receipt.manifestSha256) || receipt.restoredShards !== 12
    || receipt.reused !== 66 || receipt.generated !== 0) {
    throw new Error("Cache verification receipt differs from the exact source or expected catalog");
  }
  const packages = [];
  for (const workspace of artifactWorkspaces) {
    const source = await json(join(workspace, "package.json"));
    const name = packageManifestCatalog.get(workspace)?.name;
    if (source.name !== name || source.version !== packageVersion) {
      throw new Error(`Package source identity differs for ${workspace}`);
    }
    const filename = `${name.replace(/^@/u, "").replace("/", "-")}-${packageVersion}.tgz`;
    const path = join(directory, filename);
    const info = await lstat(path);
    if (!info.isFile() || info.nlink !== 1 || info.size === 0 || info.size > 64 * 1024 * 1024) {
      throw new Error(`Expected a bounded, single-link archive: ${filename}`);
    }
    const sha256 = digest(await readFile(path));
    const entries = packedEntries(path);
    assertCanonicalPackedPaths(entries);
    assertRequiredPackedPaths(entries, workspace);
    if (entries.some((entry) => /(?:\/keys\/|\.(?:prover|verifier)$)/u.test(entry))) {
      throw new Error(`Prover or verifier files are not allowed in ${filename}`);
    }
    const packed = JSON.parse(execFileSync("tar", ["-xOzf", path, "package/package.json"],
      { encoding: "utf8", maxBuffer: 1024 * 1024 }));
    if (packed.name !== name || packed.version !== packageVersion) {
      throw new Error(`Packed package identity differs for ${workspace}`);
    }
    if (workspace === CONTRACT) {
      const verified = await verifyKeylessContractPackage(path, sha256, receipt.manifestSha256);
      const embedded = JSON.parse(execFileSync("tar", ["-xOzf", path, `${MANAGED}/keyless-manifest.json`],
        { encoding: "utf8", maxBuffer: 1024 * 1024 }));
      if (verified.sourceRevision !== revision || verified.circuitCount !== receipt.reused
        || embedded.compilerVersion !== (await readFile(".compact-version", "utf8")).trim()
        || embedded.platform !== "linux/x64"
        || hashPackedTarEntry(path, "package/src/trust-registry.compact")
          !== digest(await readFile("contracts/trust-registry/src/trust-registry.compact"))) {
        throw new Error("Keyless contract differs from exact-source release inputs");
      }
      if (!isDeepStrictEqual(regeneration, {
        sourceRevision: revision, contractTarballSha256: sha256,
        manifestSha256: receipt.manifestSha256, keygenSha256: embedded.keygenSha256,
        platform: embedded.platform, circuits: REGENERATION_CIRCUITS,
      })) {
        throw new Error("Clean-consumer regeneration receipt does not bind these contract bytes");
      }
    }
    packages.push({ workspace, name, version: packageVersion, filename, sha256, sizeBytes: info.size,
      publication: publishWorkspaces.includes(workspace) ? "npm" : "local-only" });
  }
  const archives = (await readdir(directory)).filter((name) => name.endsWith(".tgz")).sort();
  if (!isDeepStrictEqual(archives, packages.map(({ filename }) => filename).sort())) {
    throw new Error("Unexpected archives in keyless release");
  }
  const sums = (await readFile(join(directory, "SHA256SUMS"), "utf8")).trimEnd().split("\n").sort();
  const expectedSums = packages.map(({ filename, sha256 }) =>
    `${sha256}  artifacts/keyless-prepare/${filename}`).sort();
  if (!isDeepStrictEqual(sums, expectedSums)) {
    throw new Error("Release archives differ from the checksums recorded before consumer testing");
  }
  return { format: KEYLESS_NPM_FORMAT, sourceRevision: revision, packageVersion,
    keylessManifestSha256: receipt.manifestSha256, regeneration, packages };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const [mode, directory, manifestPath] = process.argv.slice(2);
    if (!["create", "verify"].includes(mode) || !directory || !manifestPath || process.argv.length !== 5) {
      throw new Error("Usage: keyless-npm-release.mjs create|verify <artifact-directory> <manifest>");
    }
    const revision = git(["rev-parse", "HEAD"]);
    if (git(["status", "--porcelain", "--untracked-files=normal"])
      || !/^Signed-off-by: .+ <[^>]+>$/mu.test(git(["log", "-1", "--format=%B"]))) {
      throw new Error("Keyless release requires a clean DCO-signed source checkout");
    }
    verifySignedHead(revision);
    const manifest = await buildKeylessNpmRelease(directory, revision);
    if (mode === "create") {
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx" });
    } else if (!isDeepStrictEqual(await json(manifestPath), manifest)) {
      throw new Error("Keyless npm manifest differs from the exact tested tarballs");
    }
    console.log(`${mode === "create" ? "Prepared" : "Verified"} keyless npm manifest for ${revision}`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Keyless npm release verification failed");
    process.exitCode = 1;
  }
}
