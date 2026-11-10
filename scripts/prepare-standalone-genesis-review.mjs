#!/usr/bin/env node

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { prepareStandaloneGenesisReviewPacketBytes } from "./standalone-genesis-review-io.mjs";
export { validateGenesisReviewEvidence } from "./standalone-genesis-review-policy.mjs";
export { renderGenesisReviewPacket } from "./standalone-genesis-review-packet.mjs";

/**
 * @param {string} directory
 * @param {{ verifyBundle?: (path: string) => Promise<unknown> }} [dependencies]
 */
export async function prepareStandaloneGenesisReviewPacket(directory,
  dependencies = {}) {
  return prepareStandaloneGenesisReviewPacketBytes(directory,
    dependencies.verifyBundle ?? verifyStandaloneInstallBundle);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    throw new Error("Usage: node scripts/prepare-standalone-genesis-review.mjs <private-setup-dir>");
  }
  console.log(JSON.stringify(await prepareStandaloneGenesisReviewPacket(process.argv[2])));
}
