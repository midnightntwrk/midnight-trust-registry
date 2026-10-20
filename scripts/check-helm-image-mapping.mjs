#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { verifyMappingSignature } from "./verify-helm-mapping-signature.mjs";
export { approvedMappingSigner, verifyMappingSignature } from "./verify-helm-mapping-signature.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;
const REFERENCE = /^[a-z0-9][a-z0-9.:-]*(\/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}$/u;
const ROLES = ["node", "indexer", "proofServer", "api", "admin", "applicant"];

function archiveJson(archive, member) {
  return JSON.parse(execFileSync("tar", ["-xOf", archive, member], {
    encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  }));
}

function verifiedBlob(archive, digest) {
  if (!IMAGE_ID.test(digest)) throw new Error("Invalid OCI blob digest");
  const bytes = execFileSync("tar", ["-xOf", archive, `blobs/sha256/${digest.slice(7)}`], {
    timeout: 30_000, maxBuffer: 1024 * 1024,
  });
  if (createHash("sha256").update(bytes).digest("hex") !== digest.slice(7)) {
    throw new Error("OCI blob hash mismatch");
  }
  return JSON.parse(bytes);
}

export function staticImageIdentityFromArchive(archive, role, revision) {
  let legacy;
  try {
    legacy = archiveJson(archive, "manifest.json");
  } catch {
    throw new Error(`${role} image archive has no readable Docker manifest`);
  }
  const configPath = legacy?.length === 1 ? legacy[0]?.Config : undefined;
  const configDigest = /^blobs\/sha256\/([0-9a-f]{64})$/u.exec(configPath ?? "")?.[1];
  if (!configDigest || (legacy[0].RepoTags !== null && legacy[0].RepoTags?.length !== 0)) {
    throw new Error(`${role} image archive has an invalid config or implicit tag`);
  }
  let configBytes;
  try {
    configBytes = execFileSync("tar", ["-xOf", archive, configPath], {
      timeout: 30_000, maxBuffer: 1024 * 1024,
    });
  } catch {
    throw new Error(`${role} image archive lacks its config blob`);
  }
  if (createHash("sha256").update(configBytes).digest("hex") !== configDigest) {
    throw new Error(`${role} image archive config hash mismatch`);
  }
  const config = JSON.parse(configBytes);
  if (config?.os !== "linux" || config.architecture !== "arm64"
    || config.config?.Labels?.["org.opencontainers.image.revision"] !== revision
    || config.config?.User !== "1000:1000"
    || config.config?.WorkingDir !== "/app"
    || (config.config?.Entrypoint != null && config.config.Entrypoint.length !== 0)
    || !config.config?.Env?.includes(`TR_STATIC_ROLE=${role}`)
    || JSON.stringify(config.config?.Cmd)
      !== JSON.stringify(["node", "/app/entrypoint.mjs", "--host", "0.0.0.0", "--port", "4173"])) {
    throw new Error(`${role} image archive config disagrees with the approved runtime`);
  }
  const acceptedIds = [`sha256:${configDigest}`];
  const members = execFileSync("tar", ["-tf", archive], {
    encoding: "utf8", timeout: 30_000, maxBuffer: 4 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  }).split("\n");
  if (!members.includes("index.json") && !members.includes("./index.json")) {
    return { configId: `sha256:${configDigest}`, acceptedIds };
  }
  const index = archiveJson(archive, "index.json");
  if (index?.schemaVersion !== 2 || index.manifests?.length !== 1
    || !IMAGE_ID.test(index.manifests[0]?.digest)) {
    throw new Error(`${role} OCI index is malformed`);
  }
  const topDigest = index.manifests[0].digest;
  const top = verifiedBlob(archive, topDigest);
  let imageDigest = topDigest;
  let imageManifest = top;
  if (Array.isArray(top.manifests)) {
    const candidates = top.manifests.filter((entry) => entry.platform?.os === "linux"
      && entry.platform?.architecture === "arm64");
    if (candidates.length !== 1 || !IMAGE_ID.test(candidates[0].digest)) {
      throw new Error(`${role} OCI index does not select one arm64 image`);
    }
    imageDigest = candidates[0].digest;
    imageManifest = verifiedBlob(archive, imageDigest);
  }
  if (imageManifest?.schemaVersion !== 2
    || imageManifest.config?.digest !== `sha256:${configDigest}`) {
    throw new Error(`${role} OCI image manifest disagrees with the Docker config`);
  }
  return { configId: `sha256:${configDigest}`,
    acceptedIds: [...new Set([...acceptedIds, imageDigest, topDigest])] };
}

async function sha256(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function portalIdentity(manifestPath, role, revision) {
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  if (manifest?.format !== "tr-static-runtime-image-v1" || manifest.role !== role
    || manifest.sourceRevision !== revision || manifest.platform !== "linux/arm64"
    || !IMAGE_ID.test(manifest.imageId) || !SHA256.test(manifest.archiveSha256)
    || manifest.archiveName !== `${role}.image.tar`) {
    throw new Error(`Invalid ${role} static image manifest`);
  }
  const archive = join(dirname(manifestPath), manifest.archiveName);
  if (!(await lstat(archive)).isFile() || await sha256(archive) !== manifest.archiveSha256) {
    throw new Error(`${role} image archive disagrees with its manifest`);
  }
  const { configId, acceptedIds } = staticImageIdentityFromArchive(archive, role, revision);
  if (!acceptedIds.includes(manifest.imageId)) {
    throw new Error(`${role} image ID disagrees with its archive`);
  }
  return { archiveSha256: manifest.archiveSha256, acceptedIds, configId };
}

export function verifyHelmImageMapping(bundle, inventory, portals, values, receipt, valuesSha256) {
  if (inventory.format !== "tr-standalone-install-v4"
    || receipt?.format !== "tr-helm-image-mapping-v1"
    || receipt.sourceRevision !== bundle.sourceRevision
    || receipt.inventorySha256 !== bundle.inventorySha256
    || !SHA256.test(valuesSha256)
    || receipt.valuesSha256 !== valuesSha256
    || values?.imagePullPolicy !== "Never"
    || !["bootstrap", "runtime"].includes(values?.deploymentPhase)
    || !Array.isArray(receipt.images)
    || receipt.images.length !== ROLES.length
    || new Set(receipt.images.map((image) => image?.role)).size !== ROLES.length) {
    throw new Error("Helm mapping, source revision, inventory, or image roles disagree");
  }
  const expected = new Map(inventory.images.map((image) => [image.role, {
    archiveSha256: image.archiveSha256,
    acceptedIds: bundle.images.find((entry) => entry.role === image.role)?.acceptedIds,
    configId: bundle.images.find((entry) => entry.role === image.role)?.configId,
  }]));
  expected.set("proofServer", expected.get("proof-server"));
  expected.delete("proof-server");
  expected.set("api", {
    archiveSha256: inventory.apiRuntime?.archiveSha256,
    acceptedIds: [bundle.apiRuntime?.imageId, bundle.apiRuntime?.configId],
    configId: bundle.apiRuntime?.configId,
  });
  for (const role of ["admin", "applicant"]) expected.set(role, portals[role]);
  for (const role of ROLES) {
    const entry = receipt.images.find((image) => image.role === role);
    const pin = expected.get(role);
    if (!pin || !SHA256.test(pin.archiveSha256)
      || !REFERENCE.test(entry?.reference)
      || values.images?.[role] !== entry.reference
      || entry.archiveSha256 !== pin.archiveSha256
      || !IMAGE_ID.test(entry.configId)
      || entry.configId !== pin.configId
      || !IMAGE_ID.test(entry.imageId)
      || !pin.acceptedIds?.includes(entry.imageId)) {
      throw new Error(`Helm image mapping is not approved by install artifacts: ${role}`);
    }
  }
  return { sourceRevision: bundle.sourceRevision, inventorySha256: bundle.inventorySha256,
    mappedRoles: [...ROLES], deploymentPhase: values.deploymentPhase };
}

export async function checkHelmImageMapping(paths) {
  const inventoryBytes = await readFile(join(paths.bundleRoot, "install-inventory.json"));
  const bundle = await verifyStandaloneInstallBundle(paths.bundleRoot);
  if (createHash("sha256").update(inventoryBytes).digest("hex") !== bundle.inventorySha256) {
    throw new Error("Install inventory changed during mapping verification");
  }
  const inventory = JSON.parse(inventoryBytes);
  const portals = {
    admin: await portalIdentity(paths.adminManifest, "admin", bundle.sourceRevision),
    applicant: await portalIdentity(paths.applicantManifest, "applicant", bundle.sourceRevision),
  };
  const valuesBytes = await readFile(paths.valuesPath);
  const values = yaml.load(valuesBytes.toString("utf8"));
  const receiptBytes = await readFile(paths.receiptPath);
  verifyMappingSignature(receiptBytes, paths.signaturePath, paths.keyringPath,
    paths.signerFingerprint);
  const receipt = JSON.parse(receiptBytes);
  return { ...verifyHelmImageMapping(bundle, inventory, portals, values, receipt,
    createHash("sha256").update(valuesBytes).digest("hex")),
    mappingSha256: createHash("sha256").update(receiptBytes).digest("hex") };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 10) {
    throw new Error("Usage: node scripts/check-helm-image-mapping.mjs <bundle-root> <admin-manifest> <applicant-manifest> <values.yaml> <mapping.json> <mapping.sig> <reviewer-keyring> <reviewer-fingerprint>");
  }
  const [bundleRoot, adminManifest, applicantManifest, valuesPath, receiptPath,
    signaturePath, keyringPath, signerFingerprint] = process.argv.slice(2);
  console.log(JSON.stringify(await checkHelmImageMapping({ bundleRoot, adminManifest,
    applicantManifest, valuesPath, receiptPath, signaturePath, keyringPath,
    signerFingerprint })));
}
