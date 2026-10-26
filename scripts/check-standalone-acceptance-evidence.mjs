#!/usr/bin/env node

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const CASES = ["L01", "L02", "A01", "A02", "A03", "A04", "N01", "O01", "R01", "S01"];
const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const ADDRESS = /^0x[0-9a-f]{64}$/u;
const MAX_FILE_BYTES = 32 * 1024 * 1024;

function exactKeys(value, expected) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join("|") === [...expected].sort().join("|");
}

function evidencePath(root, path) {
  if (typeof path !== "string" || path.length === 0 || isAbsolute(path)
    || path.includes("\\") || path.split("/").some((part) => part === "" || part === "." || part === "..")) {
    throw new Error(`Evidence path must be a simple relative path: ${String(path)}`);
  }
  const absolute = resolve(root, path);
  if (!relative(root, absolute) || relative(root, absolute).startsWith(`..${sep}`)) {
    throw new Error(`Evidence path escapes the private bundle: ${path}`);
  }
  return absolute;
}

async function digestEvidence(root, path) {
  const absolute = evidencePath(root, path);
  let parent = root;
  for (const part of path.split("/").slice(0, -1)) {
    parent = join(parent, part);
    if (!(await lstat(parent)).isDirectory()) {
      throw new Error(`Evidence parent must be a real directory: ${path}`);
    }
  }
  const file = await open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.size === 0n || before.size > BigInt(MAX_FILE_BYTES)) {
      throw new Error(`Evidence must be a nonempty bounded regular file: ${path}`);
    }
    const hash = createHash("sha256");
    const buffer = Buffer.alloc(64 * 1024);
    let offset = 0;
    while (offset < Number(before.size)) {
      const { bytesRead } = await file.read(buffer, 0, Math.min(buffer.length, Number(before.size) - offset), offset);
      if (bytesRead === 0) throw new Error(`Evidence changed during read: ${path}`);
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const after = await file.stat({ bigint: true });
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size
      || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs) {
      throw new Error(`Evidence changed during read: ${path}`);
    }
    return hash.digest("hex");
  } finally {
    await file.close();
  }
}

async function readAcceptanceManifest(root) {
  const file = await open(join(root, "acceptance.json"),
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.size === 0n || before.size > 1024n * 1024n
      || before.nlink !== 1n || (before.mode & 0o077n) !== 0n) {
      throw new Error("Acceptance manifest must be a private bounded regular file");
    }
    const bytes = await file.readFile();
    const after = await file.stat({ bigint: true });
    if (BigInt(bytes.length) !== before.size || after.dev !== before.dev
      || after.ino !== before.ino || after.size !== before.size
      || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs) {
      throw new Error("Acceptance manifest changed during read");
    }
    return JSON.parse(bytes.toString("utf8"));
  } finally {
    await file.close();
  }
}

/** Checks the inventory, not the truth of a receipt, finality, or a human verdict. */
export async function checkStandaloneAcceptanceEvidence(root, manifest, expectedSourceRevision = null) {
  if (expectedSourceRevision !== null && !REVISION.test(expectedSourceRevision)) {
    throw new Error("Expected candidate source revision must be a full lowercase commit SHA");
  }
  if (!exactKeys(manifest, ["format", "sourceRevision", "installInventorySha256", "signedPlanSha256",
    "genesisHash", "contractAddress", "cases"])
    || manifest.format !== "tr-standalone-acceptance-evidence-v1"
    || !REVISION.test(manifest.sourceRevision)
    || !SHA256.test(manifest.installInventorySha256)
    || !SHA256.test(manifest.signedPlanSha256)
    || !ADDRESS.test(manifest.genesisHash)
    || !ADDRESS.test(manifest.contractAddress)
    || !exactKeys(manifest.cases, CASES)) {
    throw new Error("Acceptance manifest must pin one source, install, plan, genesis, deployment, and all cases");
  }
  if (expectedSourceRevision !== null && manifest.sourceRevision !== expectedSourceRevision) {
    throw new Error("Acceptance evidence source revision differs from the selected candidate");
  }
  const cases = {};
  const seen = new Set();
  for (const id of CASES) {
    const entry = manifest.cases[id];
    if (!exactKeys(entry, ["status", "evidence"])
      || !["pass", "fail", "not-run"].includes(entry.status)
      || !Array.isArray(entry.evidence) || entry.evidence.length > 32
      || (entry.status === "pass" && entry.evidence.length === 0)) {
      throw new Error(`${id} requires status pass/fail/not-run and raw evidence for pass`);
    }
    for (const item of entry.evidence) {
      if (!exactKeys(item, ["path", "sha256"]) || !SHA256.test(item.sha256)) {
        throw new Error(`${id} evidence requires a relative path and SHA-256`);
      }
      if (seen.has(item.path)) throw new Error(`Evidence reused across cases: ${item.path}`);
      seen.add(item.path);
      if (await digestEvidence(root, item.path) !== item.sha256) {
        throw new Error(`${id} evidence SHA-256 mismatch: ${item.path}`);
      }
    }
    cases[id] = entry.status;
  }
  return {
    format: "tr-standalone-acceptance-inventory-report-v1",
    sourceRevision: manifest.sourceRevision,
    cases,
    completeInventory: Object.values(cases).every((status) => status === "pass"),
    receiptAndFinalityContent: "not-independently-verified",
    humanSecurityVerdict: "not-independently-verified",
    releaseQualified: false,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const initialize = process.argv[2] === "init";
    if ((initialize && process.argv.length !== 9) || (!initialize && process.argv.length !== 4)) {
      throw new Error("Usage: check-standalone-acceptance-evidence.mjs init <absolute-private-evidence-dir> <source-revision> <inventory-sha256> <signed-plan-sha256> <genesis-hash> <contract-address> | check-standalone-acceptance-evidence.mjs <absolute-private-evidence-dir> <candidate-source-revision>");
    }
    const directory = process.argv[initialize ? 3 : 2];
    if (!isAbsolute(directory)) throw new Error("Evidence root must be an absolute path");
    const root = resolve(directory);
    const stat = await lstat(root);
    if (!stat.isDirectory() || (stat.mode & 0o077) !== 0) {
      throw new Error("Evidence root must be a private real directory (mode 0700)");
    }
    if (initialize) {
      const [sourceRevision, installInventorySha256, signedPlanSha256, genesisHash, contractAddress] = process.argv.slice(4);
      const draft = { format: "tr-standalone-acceptance-evidence-v1", sourceRevision,
        installInventorySha256, signedPlanSha256, genesisHash, contractAddress,
        cases: Object.fromEntries(CASES.map((id) => [id, { status: "not-run", evidence: [] }])) };
      await checkStandaloneAcceptanceEvidence(root, draft);
      await writeFile(join(root, "acceptance.json"), `${JSON.stringify(draft, null, 2)}\n`,
        { flag: "wx", mode: 0o600 });
      console.log(join(root, "acceptance.json"));
      process.exit(0);
    }
    const manifest = await readAcceptanceManifest(root);
    const report = await checkStandaloneAcceptanceEvidence(root, manifest, process.argv[3]);
    console.log(JSON.stringify(report, null, 2));
    if (!report.completeInventory) process.exitCode = 2;
  } catch (error) {
    console.error(`Standalone acceptance inventory failed: ${error.message}`);
    process.exitCode = 1;
  }
}
