#!/usr/bin/env node

import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertImmutableProviderTree } from "./immutable-provider-tree.mjs";
import { providerRuntimeContent } from "./provider-runtime-content.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const SHA = /^[0-9a-f]{40}$/u;
const REPORT_MAX_BYTES = 64 * 1024;
const IDENTITY_FIELDS = ["dev", "ino", "size", "mtimeNs", "ctimeNs", "nlink", "mode", "uid"];

function readStageReport(root) {
  const fd = openSync(join(root, "provider-stage.json"),
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size === 0n
      || before.size > BigInt(REPORT_MAX_BYTES)) {
      throw new Error("Installed provider stage report must be a bounded single-link regular file");
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    if (bytes.length !== Number(before.size)
      || IDENTITY_FIELDS.some((field) => before[field] !== after[field])) {
      throw new Error("Installed provider stage report changed while reading");
    }
    return JSON.parse(bytes.toString("utf8"));
  } finally {
    closeSync(fd);
  }
}

/** The expected hashes must come from the reviewed handoff, not the installed tree. */
export async function verifyInstalledProviderRuntime(root, expected, options = {}) {
  if (!SHA256.test(expected?.contentSha256 ?? "") || !SHA.test(expected?.sourceRevision ?? "")
    || !SHA256.test(expected?.inventorySha256 ?? "")) {
    throw new Error("Installed provider verification requires reviewed source, inventory, and content digests");
  }
  const before = assertImmutableProviderTree(root, options);
  const stage = readStageReport(before.root);
  if (stage.format !== "tr-provider-runtime-stage-v1"
    || stage.sourceRevision !== expected.sourceRevision
    || stage.installInventorySha256 !== expected.inventorySha256
    || stage.contentSha256 !== expected.contentSha256
    || stage.ownership !== "current-user-staging-only"
    || stage.releaseQualified !== false) {
    throw new Error("Installed provider report differs from the reviewed handoff");
  }
  const content = await providerRuntimeContent(before.root);
  const after = assertImmutableProviderTree(root, options);
  if (content.sha256 !== expected.contentSha256 || content.entries !== stage.contentEntries
    || before.files !== after.files || before.directories !== after.directories
    || before.links !== after.links) {
    throw new Error("Installed provider content differs from the reviewed stage");
  }
  return { format: "tr-installed-provider-runtime-verification-v1",
    sourceRevision: expected.sourceRevision, installInventorySha256: expected.inventorySha256,
    contentSha256: content.sha256, contentEntries: content.entries,
    ownership: "trusted-tree-check-passed", releaseQualified: false };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 6) {
      throw new Error("Usage: verify-installed-provider-runtime.mjs <absolute-root-owned-install> <reviewed-content-sha256> <reviewed-source-sha> <reviewed-inventory-sha256>");
    }
    console.log(JSON.stringify(await verifyInstalledProviderRuntime(process.argv[2], {
      contentSha256: process.argv[3], sourceRevision: process.argv[4], inventorySha256: process.argv[5],
    }), null, 2));
  } catch (error) {
    console.error(`Installed provider verification failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
