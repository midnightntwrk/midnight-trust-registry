#!/usr/bin/env node

import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { missingFullContractArtifacts, proofCircuitNames } from "./package-contents-policy.mjs";

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const managedDirectory = "trust-registry";

const collectFiles = (directory, prefix = "") => readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
  const relative = path.posix.join(prefix, entry.name);
  const absolute = path.join(directory, entry.name);
  return entry.isDirectory() ? collectFiles(absolute, relative) : [relative];
});

export const checkFullContractArtifacts = (root = repoRoot) => {
  const dist = path.join(root, "contracts/trust-registry/dist");
  const files = collectFiles(dist).map((file) => `dist/${file}`);
  const required = [
    "dist/trust-registry.compact",
    `dist/managed/${managedDirectory}/contract/index.js`,
    `dist/managed/${managedDirectory}/compiler/contract-info.json`,
  ];
  for (const file of required) {
    if (!files.includes(file)) throw new Error(`Full contract artifact is missing ${file}`);
  }
  const source = readFileSync(path.join(root, "contracts/trust-registry/src/trust-registry.compact"));
  const packagedSource = readFileSync(path.join(dist, "trust-registry.compact"));
  if (!source.equals(packagedSource)) {
    throw new Error("Full contract artifact Compact source differs from the current source");
  }
  const info = JSON.parse(readFileSync(path.join(root, "contracts/trust-registry", required[2]), "utf8"));
  const missing = missingFullContractArtifacts(files, managedDirectory, proofCircuitNames(info));
  if (missing.length > 0) throw new Error(`Full contract artifacts are incomplete: ${missing.join(" and ")}`);
  for (const file of files.filter((name) => name.startsWith(`dist/managed/${managedDirectory}/keys/`)
    || name.startsWith(`dist/managed/${managedDirectory}/zkir/`))) {
    if (statSync(path.join(root, "contracts/trust-registry", file)).size === 0) {
      throw new Error(`Full contract artifact is empty: ${file}`);
    }
  }
  return proofCircuitNames(info).length;
};

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const count = checkFullContractArtifacts();
  console.log(`[check-full-contract-artifacts] ${count} proof circuits and full contract outputs are present.`);
}
