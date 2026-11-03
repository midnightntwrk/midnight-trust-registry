#!/usr/bin/env node

import { createHash } from "node:crypto";
import { createReadStream, realpathSync } from "node:fs";
import { chmod, cp, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, extname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const DIGEST_IMAGE = /^[a-z0-9][a-z0-9.:/_-]*@sha256:[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const FINGERPRINT = /^[0-9A-F]{40}$/u;
const PUBLIC_ASSET_TYPES = new Set([".html", ".js", ".css"]);
const roles = {
  admin: "@midnight-ntwrk/trust-registry-admin-console",
  applicant: "@midnight-ntwrk/trust-registry-applicant-portal",
};

export function validateStaticImageInput(role, baseImage, platform, outputDirectory,
  expectedSourceRevision, approvedSignerFingerprint) {
  if (!Object.hasOwn(roles, role) || !DIGEST_IMAGE.test(baseImage)
    || !["linux/arm64", "linux/amd64"].includes(platform)
    || typeof outputDirectory !== "string" || !outputDirectory.startsWith("/")
    || !REVISION.test(expectedSourceRevision)
    || !FINGERPRINT.test(approvedSignerFingerprint)) {
    throw new Error("Static image build requires a role, digest-pinned base, platform, external output, approved source SHA, and signer fingerprint");
  }
  const canonicalOutput = join(realpathSync(dirname(resolve(outputDirectory))), basename(outputDirectory));
  const canonicalRoot = realpathSync(root);
  if (canonicalOutput === canonicalRoot || canonicalOutput.startsWith(`${canonicalRoot}/`)) {
    throw new Error("Static image output must be outside the source checkout");
  }
}

function run(command, args, { capture = false, cwd = root, env = process.env } = {}) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: "utf8",
    stdio: capture ? "pipe" : "inherit",
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

export function assertApprovedSourceEvidence(evidence, expectedRevision, approvedSignerFingerprint) {
  if (evidence.revision !== expectedRevision || evidence.status !== "") {
    throw new Error("Static image build requires a clean source revision");
  }
  if (!evidence.validSignature) {
    throw new Error("Source revision must have a valid OpenPGP signature");
  }
  const verifiedFingerprint = /^\[GNUPG:\] VALIDSIG ([0-9A-F]{40})\b/mu.exec(evidence.verificationOutput)?.[1];
  if (verifiedFingerprint !== approvedSignerFingerprint) {
    throw new Error("Source revision signature does not match the approved signer");
  }
  if (!/^Signed-off-by: .+ <[^<>]+>$/mu.test(evidence.message)) {
    throw new Error("Static image build requires a DCO-signed source revision");
  }
  return verifiedFingerprint;
}

export function assertNoExportAttributes(attributesOutput) {
  const fields = attributesOutput.split("\0");
  if (fields.at(-1) === "") fields.pop();
  if (fields.length % 3 !== 0) throw new Error("Malformed Git attribute output");
  for (let index = 0; index < fields.length; index += 3) {
    if (!["export-ignore", "export-subst"].includes(fields[index + 1])
      || fields[index + 2] !== "unspecified") {
      throw new Error(`Unsigned or export-modifying Git attribute for ${fields[index]}`);
    }
  }
}

async function fileSha256(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

export async function staticAssetManifest(directory) {
  const records = [];
  const walk = async (path, prefix) => {
    for (const entry of (await readdir(path, { withFileTypes: true })).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
      const absolute = join(path, entry.name);
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) await walk(absolute, relative);
      else if (entry.isFile()) {
        if (relative.endsWith(".d.ts") || relative.endsWith(".map")) continue;
        if (!PUBLIC_ASSET_TYPES.has(extname(relative))) {
          throw new Error(`Unexpected static build output: ${relative}`);
        }
        const stat = await lstat(absolute);
        if (stat.size === 0 || stat.size > 32 * 1024 * 1024) {
          throw new Error(`Static asset has invalid size: ${relative}`);
        }
        records.push({ path: relative, size: stat.size, sha256: await fileSha256(absolute) });
      } else throw new Error(`Static asset must be a regular file: ${relative}`);
    }
  };
  await walk(directory, "");
  if (!records.some((record) => record.path === "index.html")) {
    throw new Error("Static runtime requires index.html");
  }
  if (!records.some((record) => record.path.endsWith(".js"))) {
    throw new Error("Static runtime requires browser JavaScript");
  }
  return records;
}

export async function buildStaticRuntimeImage(input) {
  validateStaticImageInput(input.role, input.baseImage, input.platform, input.outputDirectory,
    input.expectedSourceRevision, input.approvedSignerFingerprint);
  const revision = run("git", ["rev-parse", "HEAD"], { capture: true });
  const status = run("git", ["status", "--porcelain", "--untracked-files=all"], { capture: true });
  const verification = spawnSync("git", ["-c", "gpg.program=gpg", "-c", "gpg.format=openpgp",
    "verify-commit", "--raw", revision], { cwd: root, encoding: "utf8" });
  const verifiedFingerprint = assertApprovedSourceEvidence({
    revision,
    status,
    validSignature: verification.status === 0 && !verification.error,
    verificationOutput: `${verification.stdout ?? ""}\n${verification.stderr ?? ""}`,
    message: run("git", ["show", "-s", "--format=%B", revision], { capture: true }),
  }, input.expectedSourceRevision, input.approvedSignerFingerprint);
  const trackedPaths = run("git", ["ls-tree", "-r", "--name-only", "-z", revision],
    { capture: true }).split("\0").filter(Boolean);
  assertNoExportAttributes(run("git", ["check-attr", `--source=${revision}`, "-z", "export-ignore", "export-subst",
    "--", ...trackedPaths], { capture: true }));
  const temporary = await mkdtemp(join(tmpdir(), `tr-static-${input.role}-`));
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
    run("pnpm", ["exec", "turbo", "run", "build:light", "--filter", roles[input.role],
      "--cache=local:w,remote:"], { cwd: source, env });
    const dist = join(source, "packages",
      `trust-registry-${input.role === "admin" ? "admin-console" : "applicant-portal"}`, "dist");
    const selectedAssets = await staticAssetManifest(dist);
    for (const asset of selectedAssets) {
      const destination = join(context, "public", asset.path);
      await mkdir(dirname(destination), { recursive: true });
      await cp(join(dist, asset.path), destination, { dereference: false });
      await chmod(destination, 0o444);
    }
    const assets = await staticAssetManifest(join(context, "public"));
    if (JSON.stringify(assets) !== JSON.stringify(selectedAssets)) {
      throw new Error("Staged static assets differ from the clean build");
    }
    await cp(join(source, "scripts", "serve-static.mjs"), join(context, "serve-static.mjs"));
    await cp(join(source, "deploy", "runtime", "static-entrypoint.mjs"), join(context, "entrypoint.mjs"));
    await chmod(join(context, "serve-static.mjs"), 0o444);
    await chmod(join(context, "entrypoint.mjs"), 0o444);
    const assetsSha256 = createHash("sha256").update(JSON.stringify(assets)).digest("hex");
    const tag = `tr-static-${input.role}:sha-${revision.slice(0, 12)}-${assetsSha256.slice(0, 12)}-${input.platform.slice(6)}`;
    const iidFile = join(temporary, "image-id");
    run("docker", ["build", "--load", "--iidfile", iidFile, "--platform", input.platform, "--file",
      join(source, "deploy", "runtime", "Dockerfile.static"),
      "--build-arg", `BASE_IMAGE=${input.baseImage}`,
      "--build-arg", `ROLE=${input.role}`,
      "--label", `org.opencontainers.image.revision=${revision}`,
      "--tag", tag, context]);
    const imageId = (await readFile(iidFile, "utf8")).trim();
    if (!/^sha256:[0-9a-f]{64}$/u.test(imageId)) throw new Error("Built image ID is invalid");
    if (run("docker", ["image", "inspect", "--format", "{{.Id}}", tag], { capture: true }) !== imageId) {
      throw new Error("Loaded image does not match the just-built image ID");
    }
    await mkdir(input.outputDirectory);
    const archivePath = join(input.outputDirectory, `${input.role}.image.tar`);
    run("docker", ["save", "--output", archivePath, imageId]);
    const archiveSha256 = await fileSha256(archivePath);
    const metadata = {
      format: "tr-static-runtime-image-v1",
      role: input.role,
      sourceRevision: revision,
      approvedSignerFingerprint: verifiedFingerprint,
      platform: input.platform,
      baseImage: input.baseImage,
      assetsSha256,
      imageId,
      archiveName: basename(archivePath),
      archiveSha256,
      assets,
    };
    await writeFile(join(input.outputDirectory, "manifest.json"), `${JSON.stringify(metadata, null, 2)}\n`, { flag: "wx" });
    return metadata;
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [role, baseImage, platform, outputDirectory, expectedSourceRevision, approvedSignerFingerprint]
    = process.argv.slice(2);
  validateStaticImageInput(role, baseImage, platform, outputDirectory,
    expectedSourceRevision, approvedSignerFingerprint);
  const result = await buildStaticRuntimeImage({ role, baseImage, platform, outputDirectory,
    expectedSourceRevision, approvedSignerFingerprint });
  console.log(JSON.stringify({ format: result.format, role: result.role,
    sourceRevision: result.sourceRevision, platform: result.platform,
    imageId: result.imageId, archiveSha256: result.archiveSha256 }));
}
