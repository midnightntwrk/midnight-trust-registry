#!/usr/bin/env node

import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const environments = new Set(["standalone", "preview"]);

export function demoGenesisReference(environment) {
  if (!environments.has(environment)) {
    throw new Error("Usage: node scripts/demo-genesis-reference.mjs <standalone|preview>");
  }

  const fixture = {
    format: "tr-synthetic-chain-spec-demo-v1",
    environment,
    description: "Illustrative bytes only; not a Midnight chain specification",
  };
  const fixtureSha256 = createHash("sha256").update(JSON.stringify(fixture)).digest("hex");
  return {
    format: "tr-genesis-reference-demo-v1",
    environment,
    fixture,
    fixtureSha256,
    exampleReference: `demo:chain-spec:${environment}:sha256:${fixtureSha256}`,
    evidenceKind: "synthetic-not-network-observation",
    usableForWizardApproval: false,
    releaseQualified: false,
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    if (process.argv.length !== 3) throw new Error("Expected exactly one environment argument");
    console.log(JSON.stringify(demoGenesisReference(process.argv[2]), null, 2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
