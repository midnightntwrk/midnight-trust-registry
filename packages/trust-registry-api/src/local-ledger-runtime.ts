import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstat, readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";

import type { SequenceToTimestamp } from "@midnight-ntwrk/trust-registry-client";
import {
  createLocalNetworkDeploymentActionReader,
  type LocalNetworkDeploymentActionReaderConfig,
} from "@midnight-ntwrk/trust-registry-integration";

import { createLocalLedgerBoundSource } from "./local-ledger-source.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const FINGERPRINT = /^[0-9A-F]{40}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;

export type LocalLedgerRuntimePlan = LocalNetworkDeploymentActionReaderConfig & {
  format: "tr-local-api-runtime-v1";
  sourceRevision: string;
  installInventoryPath: string;
  installInventorySha256: string;
  releaseManifestPath: string;
  releaseManifestSha256: string;
  contractAddress: string;
  snapshotPath: string;
  snapshotSha256: string;
  sequenceTimestamps: Readonly<Record<string, string>>;
};

const exactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean =>
  Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");

export function validateLocalLedgerRuntimePlan(value: unknown): LocalLedgerRuntimePlan {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Local API runtime plan must be an object");
  }
  const plan = value as Record<string, unknown>;
  if (!exactKeys(plan, ["allowedHosts", "contractAddress", "expectedGenesisHash", "format",
    "indexerHttpUrl", "indexerWsUrl", "installInventoryPath", "installInventorySha256",
    "networkId", "releaseManifestPath", "releaseManifestSha256", "rpcUrl", "sequenceTimestamps",
    "snapshotPath", "snapshotSha256", "sourceRevision"])
    || plan.format !== "tr-local-api-runtime-v1" || plan.networkId !== "undeployed"
    || typeof plan.sourceRevision !== "string" || !REVISION.test(plan.sourceRevision)
    || typeof plan.expectedGenesisHash !== "string" || !HASH.test(plan.expectedGenesisHash)
    || /^0x0{64}$/u.test(plan.expectedGenesisHash)
    || typeof plan.contractAddress !== "string" || !HASH.test(plan.contractAddress)
    || /^0x0{64}$/u.test(plan.contractAddress)
    || typeof plan.installInventorySha256 !== "string" || !SHA256.test(plan.installInventorySha256)
    || typeof plan.releaseManifestSha256 !== "string" || !SHA256.test(plan.releaseManifestSha256)
    || typeof plan.snapshotSha256 !== "string" || !SHA256.test(plan.snapshotSha256)
    || ["installInventoryPath", "releaseManifestPath", "snapshotPath"].some((key) =>
      typeof plan[key] !== "string" || !isAbsolute(plan[key]))
    || ["rpcUrl", "indexerHttpUrl", "indexerWsUrl"].some((key) =>
      typeof plan[key] !== "string")
    || !Array.isArray(plan.allowedHosts) || plan.allowedHosts.length === 0
    || plan.allowedHosts.some((host) => typeof host !== "string" || host.length === 0)
    || plan.sequenceTimestamps === null || typeof plan.sequenceTimestamps !== "object"
    || Array.isArray(plan.sequenceTimestamps)) {
    throw new Error("Local API runtime plan lacks exact approved local pins");
  }
  let previousSequence = -1n;
  let previousTime = -1;
  for (const [sequence, timestamp] of Object.entries(plan.sequenceTimestamps)) {
    const parsed = typeof timestamp === "string" ? Date.parse(timestamp) : Number.NaN;
    if (!DECIMAL.test(sequence) || BigInt(sequence) <= previousSequence
      || !Number.isFinite(parsed) || new Date(parsed).toISOString() !== timestamp
      || parsed < previousTime) {
      throw new Error("Local API runtime sequence timestamps must be ordered UTC ledger history");
    }
    previousSequence = BigInt(sequence);
    previousTime = parsed;
  }
  if (previousSequence < 0n) throw new Error("Local API runtime requires approved sequence timestamps");
  return plan as LocalLedgerRuntimePlan;
}

async function boundedFile(path: string, maxBytes: number): Promise<Buffer> {
  if (!isAbsolute(path)) throw new Error("Local API approval path must be absolute");
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size === 0 || stat.size > maxBytes) {
    throw new Error("Local API approval file must be a bounded regular file");
  }
  return readFile(path);
}

export function sequenceTimestampMap(plan: LocalLedgerRuntimePlan): SequenceToTimestamp {
  return (sequence) => {
    const timestamp = plan.sequenceTimestamps[sequence.toString()];
    if (timestamp === undefined) throw new Error("Governance sequence has no approved ledger timestamp");
    return timestamp;
  };
}

export async function loadApprovedLocalLedgerRuntimePlan(input: {
  planPath: string;
  signaturePath: string;
  keyringDirectory: string;
  reviewerFingerprint: string;
}): Promise<LocalLedgerRuntimePlan> {
  if (!FINGERPRINT.test(input.reviewerFingerprint)) {
    throw new Error("Local API reviewer signing-key fingerprint must be canonical");
  }
  const planBytes = await boundedFile(input.planPath, 1024 * 1024);
  await boundedFile(input.signaturePath, 64 * 1024);
  const keyring = await lstat(input.keyringDirectory);
  if (!keyring.isDirectory() || (keyring.mode & 0o077) !== 0) {
    throw new Error("Local API reviewer keyring must be a private directory");
  }
  const verification = spawnSync("gpg", ["--batch", "--no-auto-key-retrieve", "--homedir",
    input.keyringDirectory, "--status-fd=1", "--verify", input.signaturePath, input.planPath],
  { encoding: "utf8", timeout: 10_000, maxBuffer: 1024 * 1024 });
  const fingerprint = /^\[GNUPG:\] VALIDSIG ([0-9A-F]{40})\b/mu.exec(verification.stdout ?? "")?.[1];
  if (verification.status !== 0 || verification.error || fingerprint !== input.reviewerFingerprint) {
    throw new Error("Local API runtime plan lacks the approved detached reviewer signature");
  }
  const plan = validateLocalLedgerRuntimePlan(JSON.parse(planBytes.toString("utf8")));
  const inventoryBytes = await boundedFile(plan.installInventoryPath, 1024 * 1024);
  const manifestBytes = await boundedFile(plan.releaseManifestPath, 1024 * 1024);
  const digest = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");
  if (digest(inventoryBytes) !== plan.installInventorySha256
    || digest(manifestBytes) !== plan.releaseManifestSha256) {
    throw new Error("Local API install or release manifest differs from approved bytes");
  }
  const inventory = JSON.parse(inventoryBytes.toString("utf8"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  if (inventory?.format !== "tr-standalone-install-v3"
    || manifest?.format !== "tr-release-candidate-manifest-v2"
    || inventory.sourceRevision !== plan.sourceRevision
    || manifest.sourceRevision !== plan.sourceRevision) {
    throw new Error("Local API runtime source revision disagrees with approved install artifacts");
  }
  return plan;
}

export async function createApprovedLocalLedgerRuntimeSource(plan: LocalLedgerRuntimePlan) {
  const reader = await createLocalNetworkDeploymentActionReader(plan);
  return createLocalLedgerBoundSource({
    snapshotPath: plan.snapshotPath,
    expectedSnapshotSha256: plan.snapshotSha256,
    contractAddress: plan.contractAddress,
    reader,
    sequenceToTimestamp: sequenceTimestampMap(plan),
  });
}
