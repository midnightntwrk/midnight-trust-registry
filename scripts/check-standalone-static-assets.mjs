#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { portalTarLimit, verifyPortalTar } from "./verify-portal-tar.mjs";

const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;
const CONTAINER_ID = /^[0-9a-f]{64}$/u;

function docker(args) {
  return execFileSync("docker", args, { encoding: "utf8", timeout: 120_000,
    maxBuffer: 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function dockerBytes(args, maxBuffer) {
  return execFileSync("docker", args, { timeout: 120_000, maxBuffer,
    stdio: ["ignore", "pipe", "pipe"] });
}

function readLoadedImage(runDocker, runDockerBytes, pin, path, maxBuffer) {
  if (!IMAGE_ID.test(pin.imageId) || !IMAGE_ID.test(pin.configId)) {
    throw new Error("Verified image identity is invalid");
  }
  let loadedId;
  try {
    loadedId = runDocker(["image", "inspect", "--format", "{{.Id}}", pin.imageId]);
  } catch {
    loadedId = runDocker(["image", "inspect", "--format", "{{.Id}}", pin.configId]);
  }
  if (![pin.imageId, pin.configId].includes(loadedId)) {
    throw new Error("Loaded image ID disagrees with the verified bundle");
  }
  const name = `tr-portal-readback-${randomUUID()}`;
  let primaryError;
  try {
    const container = runDocker(["create", "--name", name, "--network", "none", "--pull", "never",
      "--read-only", "--entrypoint", "/bin/true", loadedId]);
    if (!CONTAINER_ID.test(container)) {
      throw new Error("Image did not create a disposable readback container");
    }
    return { loadedId, bytes: runDockerBytes(["cp", `${container}:${path}`, "-"], maxBuffer) };
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try {
      runDocker(["rm", "--force", "--volumes", name]);
    } catch (cleanupError) {
      if (primaryError) {
        throw new AggregateError([primaryError, cleanupError],
          "Portal readback and container cleanup both failed");
      }
      throw cleanupError;
    }
  }
}

export async function checkStandaloneStaticAssets(bundleRoot, dependencies = {}) {
  const verify = dependencies.verify ?? verifyStandaloneInstallBundle;
  const runDocker = dependencies.docker ?? docker;
  const runDockerBytes = dependencies.dockerBytes ?? dockerBytes;
  const verified = await verify(bundleRoot);
  if (!verified.portalRuntimes?.admin || !verified.portalRuntimes?.applicant
    || !verified.apiRuntime) {
    throw new Error("Static asset readback requires a verified v5/v6 API and portal bundle");
  }
  const inventoryBytes = await readFile(join(bundleRoot, "install-inventory.json"));
  if (createHash("sha256").update(inventoryBytes).digest("hex") !== verified.inventorySha256) {
    throw new Error("Install inventory changed after bundle verification");
  }
  const inventory = JSON.parse(inventoryBytes);
  const results = {};
  const expectedAssets = {};
  for (const role of ["admin", "applicant"]) {
    const pin = verified.portalRuntimes[role];
    const manifestBytes = await readFile(join(bundleRoot, inventory.portalRuntimes[role].manifest));
    if (createHash("sha256").update(manifestBytes).digest("hex")
      !== inventory.portalRuntimes[role].manifestSha256) {
      throw new Error(`${role} static manifest changed after bundle verification`);
    }
    const manifest = JSON.parse(manifestBytes);
    expectedAssets[role] = manifest.assets;
    const { loadedId, bytes } = readLoadedImage(runDocker, runDockerBytes, pin,
      "/app/public", portalTarLimit(manifest.assets));
    results[role] = { imageId: pin.imageId, loadedId,
      assetCount: verifyPortalTar(bytes, "public", manifest.assets),
      assetsSha256: manifest.assetsSha256 };
  }
  const apiPin = verified.apiRuntime;
  const apiManifestBytes = await readFile(join(bundleRoot, inventory.apiRuntime.manifest));
  if (createHash("sha256").update(apiManifestBytes).digest("hex")
    !== inventory.apiRuntime.manifestSha256) {
    throw new Error("API image manifest changed after bundle verification");
  }
  const apiAssets = ["admin", "applicant"].flatMap((role) =>
    expectedAssets[role].map((asset) => ({ ...asset, path: `${role}/${asset.path}` })));
  const { loadedId: loadedApiId, bytes: apiBytes } = readLoadedImage(runDocker,
    runDockerBytes, apiPin, "/app/portals", portalTarLimit(apiAssets));
  const apiAssetCount = verifyPortalTar(apiBytes, "portals", apiAssets);
  const apiPortalReadback = { imageId: apiPin.imageId, loadedId: loadedApiId,
    admin: { assetCount: expectedAssets.admin.length, assetsSha256: results.admin.assetsSha256 },
    applicant: { assetCount: expectedAssets.applicant.length, assetsSha256: results.applicant.assetsSha256 } };
  if (apiAssetCount !== apiPortalReadback.admin.assetCount + apiPortalReadback.applicant.assetCount) {
    throw new Error("API portal asset count disagrees with verified portal manifests");
  }
  return { sourceRevision: verified.sourceRevision,
    inventorySha256: verified.inventorySha256, readback: results, apiPortalReadback,
    runtimeStarted: false, offlineJourneyQualified: false };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    throw new Error("Usage: node scripts/check-standalone-static-assets.mjs <verified-v5-or-v6-bundle>");
  }
  console.log(JSON.stringify(await checkStandaloneStaticAssets(process.argv[2])));
}
