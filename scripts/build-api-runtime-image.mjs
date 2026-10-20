#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { createReadStream, realpathSync } from "node:fs";
import { cp, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
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
  const contract = join(api, "node_modules/@midnight-ntwrk/trust-registry-contract/dist/managed/trust-registry");
  for (const forbidden of ["keys", "zkir"]) {
    try {
      await lstat(join(contract, forbidden));
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    throw new Error(`API runtime must not contain proving artifacts: ${forbidden}`);
  }
  const topLevel = await readdir(api);
  if (topLevel.includes("src") || topLevel.includes("test")) {
    throw new Error("API runtime must not ship source or tests");
  }
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
  const temporary = await mkdtemp(join(realpathSync(tmpdir()), "tr-api-image-"));
  try {
    const source = join(temporary, "source");
    const context = join(temporary, "context");
    await mkdir(source);
    await mkdir(context);
    const archive = join(temporary, "source.tar");
    run("git", ["archive", "--format=tar", "--output", archive, revision]);
    run("tar", ["-xf", archive, "-C", source]);
    const env = cleanBuildEnvironment();
    run("pnpm", ["install", "--frozen-lockfile", "--ignore-scripts"], { cwd: source, env });
    run("pnpm", ["exec", "turbo", "run", "build:light", "--filter",
      "@midnight-ntwrk/trust-registry-api", "--cache=local:w,remote:"], { cwd: source, env });
    run("pnpm", ["--filter", "@midnight-ntwrk/trust-registry-api", "deploy", "--legacy",
      "--prod", join(context, "app")], { cwd: source, env });
    await assertLightApiPayload(context);
    await writeFile(join(context, "app", "source-revision"), `${revision}\n`, { flag: "wx", mode: 0o444 });
    await cp(join(source, "deploy/runtime/Dockerfile.api"), join(context, "Dockerfile.api"));
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
