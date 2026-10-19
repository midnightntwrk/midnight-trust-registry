#!/usr/bin/env node

import { createHash } from "node:crypto";
import { open, lstat, mkdir, readFile, realpath, rename, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { checkLocalLedgerPreflight } from "./local-ledger-preflight.mjs";
import { runLocalDeployment, validateLocalDeploymentPlan } from "./local-ledger-deploy.mjs";

const FORMAT = "tr-standalone-setup-v1";
const RECORD = "setup-record.json";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function regularBytes(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size === 0 || stat.size > 16 * 1024 * 1024) {
    throw new Error("Setup input must be a bounded regular file");
  }
  return readFile(path);
}

async function privateDirectory(path) {
  const stat = await lstat(path);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Setup directory must be owned by this user and accessible only to them");
  }
  return realpath(path);
}

async function readRecord(directory) {
  const root = await privateDirectory(resolve(directory));
  const record = JSON.parse((await regularBytes(join(root, RECORD))).toString("utf8"));
  if (record?.format !== FORMAT || typeof record?.sourceRevision !== "string") {
    throw new Error("Invalid standalone setup record");
  }
  return { root, record };
}

async function writeRecord(root, record) {
  const temp = join(root, `.setup-record.${process.pid}.${Date.now()}.tmp`);
  const file = await open(temp, "wx", 0o600);
  try {
    await file.writeFile(`${JSON.stringify(record, null, 2)}\n`);
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(temp, join(root, RECORD));
}

async function withLock(directory, action) {
  const root = await privateDirectory(resolve(directory));
  const lockPath = join(root, ".setup.lock");
  const lock = await open(lockPath, "wx", 0o600);
  try {
    await lock.close();
    return await action(root);
  } finally {
    await unlink(lockPath);
  }
}

export async function initializeStandaloneSetup(directory, bundleDirectory, dependencies = {}) {
  const bundle = await realpath(resolve(bundleDirectory));
  const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(bundle);
  const inventory = await regularBytes(join(bundle, "install-inventory.json"));
  if (JSON.parse(inventory).sourceRevision !== verified.sourceRevision) {
    throw new Error("Verified install inventory changed during setup");
  }
  const root = resolve(directory);
  await mkdir(root, { mode: 0o700 });
  const record = {
    format: FORMAT,
    sourceRevision: verified.sourceRevision,
    createdAt: new Date().toISOString(),
    install: { bundle, inventorySha256: sha256(inventory), verified },
  };
  await writeRecord(root, record);
  return record;
}

export async function observeStandaloneLedger(directory, pinPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (record.deployment) throw new Error("Cannot replace the genesis pin after deployment was reserved");
    const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    if (sha256(inventory) !== record.install.inventorySha256) {
      throw new Error("Installed inventory changed since setup verification");
    }
    const pinBytes = await regularBytes(resolve(pinPath));
    const pin = JSON.parse(pinBytes);
    if (pin.sourceRevision !== record.sourceRevision) {
      throw new Error("Genesis pin source revision disagrees with the installed bundle");
    }
    const observation = await (dependencies.preflight ?? checkLocalLedgerPreflight)(pin);
    record.ledgerObservation = {
      pinSha256: sha256(pinBytes),
      expectedGenesisHash: pin.expectedGenesisHash,
      rpcUrl: pin.rpcUrl,
      allowedHosts: pin.allowedHosts,
      observation,
    };
    await writeRecord(root, record);
    return record.ledgerObservation;
  });
}

export async function attemptStandaloneDeployment(directory, planPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (record.deployment) {
      throw new Error("Deployment already reserved; reconcile the journal and finalized chain before any new action");
    }
    if (!record.ledgerObservation) throw new Error("Observe the independently pinned local ledger first");
    const planBytes = await regularBytes(resolve(planPath));
    const plan = validateLocalDeploymentPlan(JSON.parse(planBytes));
    if (plan.sourceRevision !== record.sourceRevision
      || plan.network.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
      || plan.network.rpcUrl !== record.ledgerObservation.rpcUrl
      || JSON.stringify(plan.network.allowedHosts) !== JSON.stringify(record.ledgerObservation.allowedHosts)) {
      throw new Error("Deployment plan disagrees with the verified install or observed local ledger");
    }
    const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(record.install.bundle);
    const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    if (verified.sourceRevision !== record.sourceRevision
      || sha256(inventory) !== record.install.inventorySha256) {
      throw new Error("Installed bundle changed since setup verification");
    }
    const packageManifest = JSON.parse(inventory).packageManifest;
    const bundleManifestBytes = await regularBytes(join(record.install.bundle, packageManifest));
    const planManifestBytes = await regularBytes(plan.releaseManifestPath);
    if (sha256(bundleManifestBytes) !== sha256(planManifestBytes)) {
      throw new Error("Deployment release manifest disagrees with the verified install bundle");
    }
    record.deployment = {
      state: "reserved",
      planSha256: sha256(planBytes),
      journalPath: plan.journalPath,
      reservedAt: new Date().toISOString(),
    };
    await writeRecord(root, record);
    try {
      const result = await (dependencies.deploy ?? runLocalDeployment)(plan);
      record.deployment = { ...record.deployment, state: "observed", result };
      await writeRecord(root, record);
      return result;
    } catch {
      record.deployment = { ...record.deployment, state: "unknown" };
      await writeRecord(root, record);
      throw new Error("Deployment outcome is unknown; inspect the journal and finalized chain, never retry blindly");
    }
  });
}

export async function standaloneSetupStatus(directory) {
  const { record } = await readRecord(directory);
  return {
    format: FORMAT,
    sourceRevision: record.sourceRevision,
    install: "verified-staged-bytes-only",
    localLedger: record.ledgerObservation ? "node-observed-not-independently-approved" : "pending",
    deployment: record.deployment?.state ?? "pending",
    maintenanceApproval: "pending",
    offlineJourneys: "pending",
    restartRestore: "pending",
    independentReview: "pending",
    releaseQualified: false,
  };
}

async function interactive(directory) {
  const io = createInterface({ input: process.stdin, output: process.stdout });
  try {
    let record;
    try {
      ({ record } = await readRecord(directory));
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      const bundle = await io.question("Verified install bundle directory: ");
      record = await initializeStandaloneSetup(directory, bundle);
    }
    if (!record.ledgerObservation) {
      const pin = await io.question("Independently approved local genesis pin JSON (blank to stop): ");
      if (pin) await observeStandaloneLedger(directory, pin);
    }
    ({ record } = await readRecord(directory));
    if (record.ledgerObservation && !record.deployment) {
      const plan = await io.question("Approved deployment plan JSON (blank to stop): ");
      if (plan && await io.question("Type DEPLOY ONCE to reserve one attempt: ") === "DEPLOY ONCE") {
        await attemptStandaloneDeployment(directory, plan);
      }
    }
    console.log(JSON.stringify(await standaloneSetupStatus(directory), null, 2));
  } finally {
    io.close();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, directory, input] = process.argv.slice(2);
  if (!directory || !["run", "init", "observe", "deploy", "status"].includes(command)) {
    throw new Error("Usage: node scripts/standalone-setup-wizard.mjs <run|init|observe|deploy|status> <private-setup-dir> [bundle-or-plan-path]");
  }
  if (command === "run") await interactive(directory);
  else if (command === "init" && input) console.log(JSON.stringify(await initializeStandaloneSetup(directory, input)));
  else if (command === "observe" && input) console.log(JSON.stringify(await observeStandaloneLedger(directory, input)));
  else if (command === "deploy" && input) console.log(JSON.stringify(await attemptStandaloneDeployment(directory, input)));
  else if (command === "status") console.log(JSON.stringify(await standaloneSetupStatus(directory), null, 2));
  else throw new Error(`Missing input path for ${command}`);
}
