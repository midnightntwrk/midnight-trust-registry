#!/usr/bin/env node

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { staticImageIdentityFromArchive } from "./static-runtime-archive.mjs";
import { verifyMappingSignature } from "./verify-helm-mapping-signature.mjs";
export { approvedMappingSigner, verifyMappingSignature } from "./verify-helm-mapping-signature.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;
const REFERENCE = /^(?:localhost(?::[0-9]{1,5})?|[a-z0-9][a-z0-9.-]*\.[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?|[a-z0-9][a-z0-9-]*:[0-9]{1,5})(?:\/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}$/u;
const ROLES = ["node", "indexer", "proofServer", "api", "admin", "applicant"];

export { staticImageIdentityFromArchive } from "./static-runtime-archive.mjs";

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
  if (!["tr-standalone-install-v4", "tr-standalone-install-v5",
    "tr-standalone-install-v6"].includes(inventory.format)
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
  for (const role of ["admin", "applicant"]) {
    const pin = ["tr-standalone-install-v5", "tr-standalone-install-v6"].includes(inventory.format)
      ? inventory.portalRuntimes?.[role] : portals?.[role];
    const verified = ["tr-standalone-install-v5", "tr-standalone-install-v6"].includes(inventory.format)
      ? bundle.portalRuntimes?.[role] : pin;
    expected.set(role, {
      archiveSha256: pin?.archiveSha256,
      acceptedIds: verified?.acceptedIds,
      configId: verified?.configId,
    });
  }
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
  const inventory = JSON.parse(inventoryBytes.toString("utf8"));
  if (["tr-standalone-install-v5", "tr-standalone-install-v6"].includes(inventory.format)
    ? paths.adminManifest !== undefined || paths.applicantManifest !== undefined
    : !paths.adminManifest || !paths.applicantManifest) {
    throw new Error("Helm mapping portal-manifest arguments must match the install format");
  }
  const portals = ["tr-standalone-install-v5", "tr-standalone-install-v6"].includes(inventory.format)
    ? null : {
    admin: await portalIdentity(paths.adminManifest, "admin", bundle.sourceRevision),
    applicant: await portalIdentity(paths.applicantManifest, "applicant", bundle.sourceRevision),
  };
  const valuesBytes = await readFile(paths.valuesPath);
  const values = yaml.load(valuesBytes.toString("utf8"));
  const receiptBytes = await readFile(paths.receiptPath);
  verifyMappingSignature(receiptBytes, paths.signaturePath, paths.keyringPath,
    paths.signerFingerprint);
  const receipt = JSON.parse(receiptBytes.toString("utf8"));
  return { ...verifyHelmImageMapping(bundle, inventory, portals, values, receipt,
    createHash("sha256").update(valuesBytes).digest("hex")),
    mappingSha256: createHash("sha256").update(receiptBytes).digest("hex") };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (![8, 10].includes(process.argv.length)) {
    throw new Error("Usage: node scripts/check-helm-image-mapping.mjs <bundle-root> [<admin-manifest> <applicant-manifest>] <values.yaml> <mapping.json> <mapping.sig> <reviewer-keyring> <reviewer-fingerprint>");
  }
  const args = process.argv.slice(2);
  const bundleRoot = args.shift();
  const [adminManifest, applicantManifest] = args.length === 7
    ? [args.shift(), args.shift()] : [undefined, undefined];
  const [valuesPath, receiptPath, signaturePath, keyringPath, signerFingerprint] = args;
  console.log(JSON.stringify(await checkHelmImageMapping({ bundleRoot, adminManifest,
    applicantManifest, valuesPath, receiptPath, signaturePath, keyringPath,
    signerFingerprint })));
}
