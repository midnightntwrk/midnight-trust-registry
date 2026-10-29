#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertImmutableProviderTree } from "./immutable-provider-tree.mjs";
import { providerRuntimeContent } from "./provider-runtime-content.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const SHA = /^[0-9a-f]{40}$/u;

/** The expected hashes must come from the reviewed handoff, not the installed tree. */
export async function verifyInstalledProviderRuntime(root, expected, options = {}) {
  if (!SHA256.test(expected?.contentSha256 ?? "") || !SHA.test(expected?.sourceRevision ?? "")
    || !SHA256.test(expected?.inventorySha256 ?? "")) {
    throw new Error("Installed provider verification requires reviewed source, inventory, and content digests");
  }
  const before = assertImmutableProviderTree(root, options);
  const stage = JSON.parse(readFileSync(`${root}/provider-stage.json`, "utf8"));
  if (stage.format !== "tr-provider-runtime-stage-v1"
    || stage.sourceRevision !== expected.sourceRevision
    || stage.installInventorySha256 !== expected.inventorySha256
    || stage.contentSha256 !== expected.contentSha256
    || stage.ownership !== "current-user-staging-only"
    || stage.releaseQualified !== false) {
    throw new Error("Installed provider report differs from the reviewed handoff");
  }
  const content = await providerRuntimeContent(root);
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
