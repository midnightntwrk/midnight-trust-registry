#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";

const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;
const CONTAINER_ID = /^[0-9a-f]{64}$/u;

function docker(args) {
  return execFileSync("docker", args, { encoding: "utf8", timeout: 120_000,
    maxBuffer: 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] }).trim();
}

async function sha256(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

export async function verifyStaticAssetDirectory(directory, expectedAssets) {
  const observed = [];
  async function walk(path, prefix) {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = join(path, entry.name);
      const info = await lstat(absolute);
      if (info.isDirectory()) await walk(absolute, relative);
      else if (info.isFile()) observed.push({ path: relative, size: info.size,
        sha256: await sha256(absolute) });
      else throw new Error(`Static image contains a linked or special asset: ${relative}`);
    }
  }
  await walk(directory, "");
  observed.sort((left, right) => left.path.localeCompare(right.path, "en"));
  const expected = [...expectedAssets].sort((left, right) => left.path.localeCompare(right.path, "en"));
  if (JSON.stringify(observed) !== JSON.stringify(expected)) {
    throw new Error("Loaded static image assets disagree with the verified manifest");
  }
  return observed.length;
}

export async function checkStandaloneStaticAssets(bundleRoot, dependencies = {}) {
  const verify = dependencies.verify ?? verifyStandaloneInstallBundle;
  const runDocker = dependencies.docker ?? docker;
  const verified = await verify(bundleRoot);
  if (!verified.portalRuntimes?.admin || !verified.portalRuntimes?.applicant) {
    throw new Error("Static asset readback requires a verified v5 install bundle");
  }
  const inventoryBytes = await readFile(join(bundleRoot, "install-inventory.json"));
  if (createHash("sha256").update(inventoryBytes).digest("hex") !== verified.inventorySha256) {
    throw new Error("Install inventory changed after bundle verification");
  }
  const inventory = JSON.parse(inventoryBytes);
  const temporary = await mkdtemp(join(tmpdir(), "tr-static-readback-"));
  try {
    const results = {};
    for (const role of ["admin", "applicant"]) {
      const pin = verified.portalRuntimes[role];
      if (!IMAGE_ID.test(pin.imageId)
        || runDocker(["image", "inspect", "--format", "{{.Id}}", pin.imageId]) !== pin.imageId) {
        throw new Error(`${role} loaded image ID disagrees with the verified bundle`);
      }
      const manifestBytes = await readFile(join(bundleRoot, inventory.portalRuntimes[role].manifest));
      if (createHash("sha256").update(manifestBytes).digest("hex")
        !== inventory.portalRuntimes[role].manifestSha256) {
        throw new Error(`${role} static manifest changed after bundle verification`);
      }
      const manifest = JSON.parse(manifestBytes);
      const container = runDocker(["create", "--network", "none", "--pull", "never",
        "--read-only", "--entrypoint", "/bin/true", pin.imageId]);
      if (!CONTAINER_ID.test(container)) {
        throw new Error(`${role} image did not create a disposable readback container`);
      }
      try {
        const destination = join(temporary, role);
        runDocker(["cp", `${container}:/app/public`, destination]);
        results[role] = { imageId: pin.imageId,
          assetCount: await verifyStaticAssetDirectory(destination, manifest.assets),
          assetsSha256: manifest.assetsSha256 };
      } finally {
        runDocker(["rm", "--force", container]);
      }
    }
    return { sourceRevision: verified.sourceRevision,
      inventorySha256: verified.inventorySha256, readback: results,
      runtimeStarted: false, offlineJourneyQualified: false };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    throw new Error("Usage: node scripts/check-standalone-static-assets.mjs <verified-v5-bundle>");
  }
  console.log(JSON.stringify(await checkStandaloneStaticAssets(process.argv[2])));
}
