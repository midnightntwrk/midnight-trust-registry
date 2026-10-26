#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { createReadStream, realpathSync } from "node:fs";
import { cp, lstat, mkdir, readFile, readdir, readlink, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertApprovedSourceEvidence, assertNoExportAttributes } from "./build-static-runtime-image.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const DIGEST_IMAGE = /^[a-z0-9][a-z0-9.:/_-]*@sha256:[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const FINGERPRINT = /^[0-9A-F]{40}$/u;

function run(command, args, { capture = false, cwd = root, env = process.env } = {}) {
  const result = spawnSync(command, args, {
    cwd, env, encoding: "utf8", stdio: capture ? "pipe" : "inherit",
    maxBuffer: 8 * 1024 * 1024, timeout: 30 * 60_000,
  });
  if (result.status !== 0 || result.error) {
    throw new Error(`${command} failed${capture ? `: ${result.stderr?.trim() ?? ""}` : ""}`);
  }
  return result.stdout?.trim() ?? "";
}

function cleanBuildEnvironment() {
  const allowed = ["PATH", "HOME", "TMPDIR", "TMP", "TEMP", "XDG_CACHE_HOME",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"];
  const env = Object.fromEntries(allowed.filter((key) => process.env[key] !== undefined)
    .map((key) => [key, process.env[key]]));
  return { ...env, CI: "true", TURBO_TELEMETRY_DISABLED: "1" };
}

async function fileSha256(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

export function validateApiImageInput(baseImage, platform, outputDirectory,
  expectedSourceRevision, approvedSignerFingerprint) {
  if (!DIGEST_IMAGE.test(baseImage)
    || !["linux/arm64", "linux/amd64"].includes(platform)
    || typeof outputDirectory !== "string" || !outputDirectory.startsWith("/")
    || !REVISION.test(expectedSourceRevision)
    || !FINGERPRINT.test(approvedSignerFingerprint)) {
    throw new Error("API image build requires a digest-pinned base, platform, external output, approved source SHA, and signer fingerprint");
  }
  const output = join(realpathSync(dirname(resolve(outputDirectory))), basename(outputDirectory));
  const checkout = realpathSync(root);
  if (output === checkout || output.startsWith(`${checkout}/`)) {
    throw new Error("API image output must be outside the source checkout");
  }
}

export async function assertLightApiPayload(directory) {
  const api = join(directory, "app");
  const manifest = JSON.parse(await readFile(join(api, "package.json"), "utf8"));
  if (manifest.name !== "@midnight-ntwrk/trust-registry-api") {
    throw new Error("Deployed API package identity is incorrect");
  }
  for (const path of ["bin/trust-registry-api.mjs", "dist/cli.js", "dist/local-ledger-runtime.js",
    "node_modules/@midnight-ntwrk/trust-registry-contract/dist/managed/trust-registry/contract/index.js"]) {
    if (!(await lstat(join(api, path))).isFile()) {
      throw new Error(`API runtime requires a regular file: ${path}`);
    }
  }
  const topLevel = await readdir(api);
  if (topLevel.includes("src") || topLevel.includes("test")) {
    throw new Error("API runtime must not ship source or tests");
  }
}

export async function stripPublishedDidProofArtifacts(directory) {
  const modules = join(directory, "app/node_modules");
  const candidates = [join(modules, "@midnight-ntwrk/midnight-did-contract")];
  for (const entry of await readdir(join(modules, ".pnpm"))) {
    if (entry.startsWith("@midnight-ntwrk+midnight-did-contract@")) {
      candidates.push(join(modules, ".pnpm", entry,
        "node_modules/@midnight-ntwrk/midnight-did-contract"));
    }
  }
  for (const packageRoot of candidates) {
    let manifest;
    try {
      manifest = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    if (manifest.name !== "@midnight-ntwrk/midnight-did-contract" || manifest.version !== "0.7.0") {
      throw new Error("Unexpected DID contract package; review proof-artifact exclusion before building");
    }
    const managed = join(packageRoot, "dist/managed/did");
    for (const name of ["keys", "zkir"]) {
      try {
        if (!(await lstat(join(managed, name))).isDirectory()) {
          throw new Error(`DID proof-artifact path is not a directory: ${name}`);
        }
      } catch (error) {
        if (error.code === "ENOENT") continue;
        throw error;
      }
      await rm(join(managed, name), { recursive: true });
    }
  }
}

export async function stripPnpmInstallMetadata(directory) {
  const modules = join(directory, "app/node_modules");
  for (const name of [".modules.yaml", ".pnpm-workspace-state-v1.json"]) {
    await rm(join(modules, name), { force: true });
  }
}

export async function apiPayloadInventory(directory, platform) {
  if (!["linux/arm64", "linux/amd64"].includes(platform)) {
    throw new Error("API payload inventory requires an approved Linux platform");
  }
  const app = await realpath(join(directory, "app"));
  const records = [];
  async function walk(path, prefix) {
    for (const entry of (await readdir(path, { withFileTypes: true })).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = join(path, entry.name);
      const stat = await lstat(absolute);
      if (stat.isDirectory()) {
        if (["keys", "zkir"].includes(entry.name)) {
          throw new Error(`API image contains a proving-artifact directory: ${relative}`);
        }
        await walk(absolute, relative);
      } else if (stat.isFile()) {
        if (/\.(?:prover|verifier|bzkir)$/u.test(entry.name)) {
          throw new Error(`API image contains a proving artifact: ${relative}`);
        }
        if (entry.name.endsWith(".node")) {
          throw new Error(`API image must not contain a native addon: ${relative}`);
        }
        records.push({ path: relative, mode: stat.mode & 0o777,
          size: stat.size, sha256: await fileSha256(absolute) });
      } else if (stat.isSymbolicLink()) {
        const target = await readlink(absolute);
        if (isAbsolute(target)) {
          throw new Error(`API image contains an absolute link: ${relative}`);
        }
        const resolved = await realpath(absolute);
        if (!resolved.startsWith(`${app}/`)) {
          throw new Error(`API image contains an external link: ${relative}`);
        }
        records.push({ path: relative, link: target });
      } else {
        throw new Error(`API image contains an unsupported file: ${relative}`);
      }
    }
  }
  await walk(app, "");
  return { fileCount: records.length,
    sha256: createHash("sha256").update(JSON.stringify(records)).digest("hex") };
}

export async function assertArchiveMatchesCommit(source, treeEntries) {
  const entries = treeEntries.split("\0").filter(Boolean);
  if (entries.length === 0) throw new Error("Signed source tree is empty");
  for (const entry of entries) {
    const match = /^(100644|100755|120000) blob ([0-9a-f]{40})\t(.+)$/us.exec(entry);
    if (!match) throw new Error("Signed source tree contains an unsupported entry");
    const [, mode, expected, relative] = match;
    const path = join(source, relative);
    const stat = await lstat(path);
    if (mode === "120000" ? !stat.isSymbolicLink() : !stat.isFile()) {
      throw new Error(`Source archive entry type differs from signed blob: ${relative}`);
    }
    if (mode !== "120000" && Boolean(stat.mode & 0o111) !== (mode === "100755")) {
      throw new Error(`Source archive executable mode differs from signed tree: ${relative}`);
    }
    const bytes = mode === "120000" ? Buffer.from(await readlink(path)) : await readFile(path);
    const hash = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
    if (hash !== expected) throw new Error(`Source archive bytes differ from signed blob: ${relative}`);
  }
  return entries.length;
}

export async function buildApiRuntimeImage(input) {
  validateApiImageInput(input.baseImage, input.platform, input.outputDirectory,
    input.expectedSourceRevision, input.approvedSignerFingerprint);
  const revision = run("git", ["rev-parse", "HEAD"], { capture: true });
  const status = run("git", ["status", "--porcelain", "--untracked-files=all"], { capture: true });
  const verification = spawnSync("git", ["-c", "gpg.program=gpg", "-c", "gpg.format=openpgp",
    "verify-commit", "--raw", revision], { cwd: root, encoding: "utf8" });
  const signer = assertApprovedSourceEvidence({ revision, status,
    validSignature: verification.status === 0 && !verification.error,
    verificationOutput: `${verification.stdout ?? ""}\n${verification.stderr ?? ""}`,
    message: run("git", ["show", "-s", "--format=%B", revision], { capture: true }),
  }, input.expectedSourceRevision, input.approvedSignerFingerprint);
  const tracked = run("git", ["ls-tree", "-r", "--name-only", "-z", revision],
    { capture: true }).split("\0").filter(Boolean);
  assertNoExportAttributes(run("git", ["check-attr", `--source=${revision}`, "-z",
    "export-ignore", "export-subst", "--", ...tracked], { capture: true }));
  // A stable source path makes pnpm's injected workspace names repeatable on this host.
  const temporary = join(realpathSync(tmpdir()), `tr-api-image-${revision}`);
  await mkdir(temporary, { mode: 0o700 });
  try {
    const source = join(temporary, "source");
    const context = join(temporary, "context");
    await mkdir(source);
    await mkdir(context);
    const archive = join(temporary, "source.tar");
    run("git", ["archive", "--format=tar", "--output", archive, revision]);
    run("tar", ["-xf", archive, "-C", source]);
    await assertArchiveMatchesCommit(source,
      run("git", ["ls-tree", "-r", "-z", revision], { capture: true }));
    const env = cleanBuildEnvironment();
    const cpu = input.platform === "linux/amd64" ? "x64" : "arm64";
    run("pnpm", ["install", "--frozen-lockfile", "--ignore-scripts"], { cwd: source, env });
    run("pnpm", ["exec", "turbo", "run", "build:light", "--filter",
      "@midnight-ntwrk/trust-registry-api", "--cache=local:w,remote:"], { cwd: source, env });
    run("pnpm", ["--config.inject-workspace-packages=true", "--filter",
      "@midnight-ntwrk/trust-registry-api", "deploy", "--prod", "--frozen-lockfile",
      "--os", "linux", "--cpu", cpu, "--libc", "glibc", "--no-optional",
      "--ignore-scripts",
      join(context, "app")], { cwd: source, env });
    await stripPublishedDidProofArtifacts(context);
    await stripPnpmInstallMetadata(context);
    await assertLightApiPayload(context);
    await writeFile(join(context, "app", "source-revision"), `${revision}\n`, { flag: "wx", mode: 0o444 });
    await cp(join(source, "deploy/runtime/Dockerfile.api"), join(context, "Dockerfile.api"));
    const payload = await apiPayloadInventory(context, input.platform);
    const lockfileSha256 = await fileSha256(join(source, "pnpm-lock.yaml"));
    const dockerfileSha256 = await fileSha256(join(context, "Dockerfile.api"));
    const tag = `tr-api:sha-${revision.slice(0, 12)}-${input.platform.slice(6)}`;
    const iidFile = join(temporary, "image-id");
    run("docker", ["build", "--load", "--iidfile", iidFile, "--platform", input.platform,
      "--file", join(context, "Dockerfile.api"), "--build-arg", `BASE_IMAGE=${input.baseImage}`,
      "--label", `org.opencontainers.image.revision=${revision}`, "--tag", tag, context]);
    const imageId = (await readFile(iidFile, "utf8")).trim();
    if (!/^sha256:[0-9a-f]{64}$/u.test(imageId)
      || run("docker", ["image", "inspect", "--format", "{{.Id}}", tag], { capture: true }) !== imageId) {
      throw new Error("Built API image ID does not match the loaded image");
    }
    run("docker", ["run", "--rm", "--network", "none", "--read-only", "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=16m", "--entrypoint", "/usr/bin/gpg", imageId, "--version"],
    { capture: true });
    run("docker", ["run", "--rm", "--network", "none", "--read-only", "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=16m", "--entrypoint", "/bin/sh", imageId, "-ec",
      "for tool in cp mkdir rm chmod; do command -v \"$tool\" >/dev/null; done"],
    { capture: true });
    const runtimeRevision = run("docker", ["run", "--rm", "--network", "none", "--read-only",
      "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--entrypoint", "node", imageId,
      "-e", "import('/app/dist/cli.js').then(() => process.stdout.write(require('node:fs').readFileSync('/app/source-revision', 'utf8').trim()))"],
    { capture: true });
    if (runtimeRevision !== revision) throw new Error("API runtime image source revision differs from approved source");
    await mkdir(input.outputDirectory);
    const archivePath = join(input.outputDirectory, "api.image.tar");
    run("docker", ["save", "--output", archivePath, imageId]);
    const metadata = { format: "tr-api-runtime-image-v1", sourceRevision: revision,
      approvedSignerFingerprint: signer, platform: input.platform, baseImage: input.baseImage,
      lockfileSha256, dockerfileSha256, payload,
      imageId, archiveName: basename(archivePath), archiveSha256: await fileSha256(archivePath) };
    await writeFile(join(input.outputDirectory, "manifest.json"), `${JSON.stringify(metadata, null, 2)}\n`, { flag: "wx" });
    return metadata;
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [baseImage, platform, outputDirectory, expectedSourceRevision, approvedSignerFingerprint]
    = process.argv.slice(2);
  validateApiImageInput(baseImage, platform, outputDirectory,
    expectedSourceRevision, approvedSignerFingerprint);
  const result = await buildApiRuntimeImage({ baseImage, platform, outputDirectory,
    expectedSourceRevision, approvedSignerFingerprint });
  console.log(JSON.stringify({ format: result.format, sourceRevision: result.sourceRevision,
    platform: result.platform, imageId: result.imageId, archiveSha256: result.archiveSha256 }));
}
