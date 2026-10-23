import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { constants, existsSync } from "node:fs";
import { lstat, mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";

import type { SequenceToTimestamp } from "@midnight-ntwrk/trust-registry-client";
import {
  createLocalNetworkDeploymentActionReader,
  type LocalNetworkDeploymentActionReaderConfig,
} from "@midnight-ntwrk/trust-registry-integration";

import { createLocalLedgerBoundSource, LocalLedgerSourceUnavailableError } from "./local-ledger-source.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const FINGERPRINT = /^[0-9A-F]{40}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;

export function assertApprovedReviewerSignatureStatus(
  output: string,
  exitStatus: number | null,
  expectedPrimaryFingerprint: string,
  now = Date.now(),
): void {
  const statuses = output.split("\n").filter((line) => line.startsWith("[GNUPG:] "));
  const valid = statuses.filter((line) => line.startsWith("[GNUPG:] VALIDSIG "));
  const good = statuses.filter((line) => line.startsWith("[GNUPG:] GOODSIG "));
  const fields = valid[0]?.split(/\s+/u);
  const signerFingerprint = fields?.[2];
  const goodSignerKeyId = good[0]?.split(/\s+/u)[2];
  const primaryFingerprint = fields?.[11];
  const signedAt = Number(fields?.[4]);
  const expiresAt = Number(fields?.[5]);
  const hashAlgorithm = fields?.[9];
  const signatureClass = fields?.[10];
  const nowSeconds = Math.floor(now / 1000);
  if (exitStatus !== 0 || !FINGERPRINT.test(expectedPrimaryFingerprint)
    || valid.length !== 1 || good.length !== 1
    || fields?.length !== 12
    || !FINGERPRINT.test(signerFingerprint ?? "")
    || ![signerFingerprint?.slice(-16), signerFingerprint].includes(goodSignerKeyId)
    || primaryFingerprint !== expectedPrimaryFingerprint
    || !Number.isSafeInteger(signedAt) || signedAt <= 0 || signedAt > nowSeconds + 300
    || !Number.isSafeInteger(expiresAt) || expiresAt < 0
    || (expiresAt !== 0 && expiresAt <= nowSeconds)
    || !["8", "9", "10"].includes(hashAlgorithm ?? "")
    || signatureClass !== "00"
    || statuses.some((line) => /^\[GNUPG:\] (?:BADSIG|ERRSIG|EXPKEYSIG|EXPSIG|REVKEYSIG|KEYREVOKED|SIGEXPIRED|PLAINTEXT|PLAINTEXT_LENGTH)\b/u.test(line))) {
    throw new Error("Local API runtime plan lacks the approved detached reviewer signature");
  }
}

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
  notBefore: string;
  notAfter: string;
};

const exactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean =>
  Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));

const canonicalTimestamp = (value: unknown): number => {
  const parsed = typeof value === "string" ? Date.parse(value) : Number.NaN;
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : Number.NaN;
};

function parseCanonicalApprovedPlan(bytes: Buffer): unknown {
  const raw = bytes.toString("utf8");
  const value: unknown = JSON.parse(raw);
  const compact = JSON.stringify(value);
  if (!Buffer.from(raw, "utf8").equals(bytes)
    || ![compact, `${compact}\n`, `${JSON.stringify(value, null, 2)}\n`].includes(raw)) {
    throw new Error("Local API runtime plan must use canonical signed JSON without duplicate keys");
  }
  return value;
}

export function validateLocalLedgerRuntimePlan(value: unknown): LocalLedgerRuntimePlan {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Local API runtime plan must be an object");
  }
  const plan = value as Record<string, unknown>;
  if (!exactKeys(plan, ["allowedHosts", "contractAddress", "expectedGenesisHash", "format",
    "indexerHttpUrl", "indexerWsUrl", "installInventoryPath", "installInventorySha256",
    "networkId", "notAfter", "notBefore", "releaseManifestPath", "releaseManifestSha256", "rpcUrl", "sequenceTimestamps",
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
    || Array.isArray(plan.sequenceTimestamps)
    || !Number.isFinite(canonicalTimestamp(plan.notBefore))
    || !Number.isFinite(canonicalTimestamp(plan.notAfter))
    || canonicalTimestamp(plan.notAfter) <= canonicalTimestamp(plan.notBefore)
    || canonicalTimestamp(plan.notAfter) - canonicalTimestamp(plan.notBefore) > 90 * 24 * 60 * 60 * 1000) {
    throw new Error("Local API runtime plan lacks exact approved local pins");
  }
  const now = Date.now();
  if (now < canonicalTimestamp(plan.notBefore) || now > canonicalTimestamp(plan.notAfter)) {
    throw new Error("Local API runtime plan is not currently valid");
  }
  let previousSequence = -1n;
  let previousTime = -1;
  for (const [sequence, timestamp] of Object.entries(plan.sequenceTimestamps)) {
    const parsed = canonicalTimestamp(timestamp);
    if (!DECIMAL.test(sequence) || BigInt(sequence) !== previousSequence + 1n
      || !Number.isFinite(parsed) || parsed < previousTime
      || parsed > now + 5 * 60_000) {
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
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size === 0 || stat.size > maxBytes) {
      throw new Error("Local API approval file must be a bounded regular file");
    }
    if (typeof process.getuid === "function" && stat.uid !== process.getuid() && stat.uid !== 0) {
      throw new Error("Local API approval file must be owned by root or the runtime user");
    }
    const buffer = Buffer.alloc(maxBytes + 1);
    let count = 0;
    while (count < buffer.length) {
      const result = await file.read(buffer, count, buffer.length - count, count);
      if (result.bytesRead === 0) break;
      count += result.bytesRead;
    }
    if (count === 0 || count > maxBytes || count !== stat.size) {
      throw new Error("Local API approval file changed or exceeded its size limit");
    }
    return buffer.subarray(0, count);
  } finally {
    await file.close();
  }
}

export function sequenceTimestampMap(plan: LocalLedgerRuntimePlan): SequenceToTimestamp {
  return (sequence) => {
    const timestamp = plan.sequenceTimestamps[sequence.toString()];
    if (timestamp === undefined) throw new Error("Governance sequence has no approved ledger timestamp");
    return timestamp;
  };
}

export function assertApprovedPlanCoversGovernanceCount(
  plan: Pick<LocalLedgerRuntimePlan, "sequenceTimestamps">,
  count: unknown,
): void {
  if (typeof count !== "bigint"
    || count !== BigInt(Object.keys(plan.sequenceTimestamps).length - 1)) {
    throw new Error("Approved sequence timestamps do not cover the finalized governance count");
  }
}

export async function assertLocalApiImageSourceRevision(
  expectedRevision: string,
  path = "/app/source-revision",
): Promise<void> {
  if (!REVISION.test(expectedRevision)) {
    throw new Error("Local API image source revision is malformed");
  }
  const bytes = await boundedFile(path, 41);
  if (bytes.toString("utf8") !== `${expectedRevision}\n`) {
    throw new Error("Container source-revision file differs from the approved local plan");
  }
}

export async function loadApprovedLocalLedgerRuntimePlan(input: {
  planPath: string;
  signaturePath: string;
  keyringDirectory: string;
  reviewerFingerprint: string;
  requireApiRuntimePin?: boolean;
}): Promise<LocalLedgerRuntimePlan> {
  if (!FINGERPRINT.test(input.reviewerFingerprint)) {
    throw new Error("Local API reviewer primary signing-key fingerprint must be canonical");
  }
  const planBytes = await boundedFile(input.planPath, 1024 * 1024);
  const signatureBytes = await boundedFile(input.signaturePath, 64 * 1024);
  const keyring = await lstat(input.keyringDirectory);
  if (!keyring.isDirectory() || (keyring.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && keyring.uid !== process.getuid() && keyring.uid !== 0)) {
    throw new Error("Local API reviewer keyring must be a private directory");
  }
  const keyringBytes = await boundedFile(join(input.keyringDirectory, "pubring.kbx"), 8 * 1024 * 1024);
  const gpg = ["/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg"].find(existsSync);
  if (gpg === undefined) throw new Error("Local API runtime requires an installed GPG verifier");
  const temporary = await mkdtemp(join(tmpdir(), "tr-local-api-approval-"));
  try {
    const planCopy = join(temporary, "plan.json");
    const signatureCopy = join(temporary, "plan.sig");
    await writeFile(planCopy, planBytes, { flag: "wx", mode: 0o600 });
    await writeFile(signatureCopy, signatureBytes, { flag: "wx", mode: 0o600 });
    await writeFile(join(temporary, "pubring.kbx"), keyringBytes, { flag: "wx", mode: 0o600 });
    const verification = spawnSync(gpg, ["--batch", "--no-options", "--no-auto-key-retrieve",
      "--trust-model", "always", "--no-default-keyring", "--homedir", temporary,
      "--keyring", join(temporary, "pubring.kbx"), "--status-fd=1",
      "--verify", signatureCopy, planCopy],
    { encoding: "utf8", timeout: 10_000, maxBuffer: 1024 * 1024,
      env: { PATH: "/usr/bin:/bin", HOME: temporary, LC_ALL: "C" } });
    if (verification.error) {
      throw new Error("Local API runtime plan lacks the approved detached reviewer signature");
    }
    assertApprovedReviewerSignatureStatus(verification.stdout ?? "", verification.status,
      input.reviewerFingerprint);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
  const plan = validateLocalLedgerRuntimePlan(parseCanonicalApprovedPlan(planBytes));
  const inventoryBytes = await boundedFile(plan.installInventoryPath, 1024 * 1024);
  const manifestBytes = await boundedFile(plan.releaseManifestPath, 1024 * 1024);
  const digest = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");
  if (digest(inventoryBytes) !== plan.installInventorySha256
    || digest(manifestBytes) !== plan.releaseManifestSha256) {
    throw new Error("Local API install or release manifest differs from approved bytes");
  }
  const inventory = JSON.parse(inventoryBytes.toString("utf8"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const installFormat = inventory?.format;
  const supportedFormat = ["tr-standalone-install-v3", "tr-standalone-install-v4",
    "tr-standalone-install-v5", "tr-standalone-install-v6"].includes(installFormat);
  const requiresApiPin = installFormat !== "tr-standalone-install-v3";
  const requiresPortalPins = installFormat === "tr-standalone-install-v5"
    || installFormat === "tr-standalone-install-v6";
  const artifactPin = (value: unknown, manifestPath: string, archivePath: string): boolean => {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
    const pin = value as Record<string, unknown>;
    return pin.manifest === manifestPath && pin.archive === archivePath
      && typeof pin.manifestSha256 === "string" && SHA256.test(pin.manifestSha256)
      && typeof pin.archiveSha256 === "string" && SHA256.test(pin.archiveSha256);
  };
  if (!supportedFormat
    || manifest?.format !== "tr-release-candidate-manifest-v2"
    || inventory.sourceRevision !== plan.sourceRevision
    || manifest.sourceRevision !== plan.sourceRevision
    || (requiresApiPin && !artifactPin(inventory.apiRuntime,
      "images/api.manifest.json", "images/api.image.tar"))
    || (requiresPortalPins && (!["admin", "applicant"].every((role) =>
      artifactPin(inventory.portalRuntimes?.[role],
        `images/${role}.manifest.json`, `images/${role}.image.tar`))
      || Object.keys(inventory.portalRuntimes ?? {}).sort().join(",") !== "admin,applicant"))
    || (installFormat === "tr-standalone-install-v6"
      && (inventory.installRelay?.path !== "install-relay.py"
        || inventory.installRelay.imageRole !== "node"
        || typeof inventory.installRelay.sha256 !== "string"
        || !SHA256.test(inventory.installRelay.sha256)))) {
    throw new Error("Local API runtime inventory or release manifest disagrees with approved install artifacts");
  }
  if (input.requireApiRuntimePin === true && !requiresApiPin) {
    throw new Error("Cluster API binding requires a signed install with an API image pin");
  }
  return plan;
}

export async function createApprovedLocalLedgerRuntimeSource(plan: LocalLedgerRuntimePlan) {
  const reader = await createLocalNetworkDeploymentActionReader(plan);
  const source = createLocalLedgerBoundSource({
    snapshotPath: plan.snapshotPath,
    expectedSnapshotSha256: plan.snapshotSha256,
    contractAddress: plan.contractAddress,
    reader: {
      async readCurrentFinalizedLedger(address) {
        const view = await reader.readCurrentFinalizedLedger(address);
        if (view !== null) {
          assertApprovedPlanCoversGovernanceCount(plan, view.ledger.governanceActionCount);
        }
        return view;
      },
    },
    sequenceToTimestamp: sequenceTimestampMap(plan),
  });
  const assertPlanCurrent = () => {
    const now = Date.now();
    if (now < Date.parse(plan.notBefore) || now > Date.parse(plan.notAfter)) {
      throw new LocalLedgerSourceUnavailableError(new Error("Local API runtime plan is not currently valid"));
    }
  };
  return {
    ...source,
    async loadSnapshot() {
      assertPlanCurrent();
      return source.loadSnapshot();
    },
    async readFinalizedProposalLedger() {
      assertPlanCurrent();
      return source.readFinalizedProposalLedger();
    },
  };
}
