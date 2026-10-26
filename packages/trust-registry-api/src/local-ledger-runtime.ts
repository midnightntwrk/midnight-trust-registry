import { createHash } from "node:crypto";
import { dirname, isAbsolute, join } from "node:path";

import type { SequenceToTimestamp } from "@midnight-ntwrk/trust-registry-client";
import {
  createLocalNetworkDeploymentActionReader,
  type FinalizedRegistryLedgerView,
  type LocalNetworkDeploymentActionReaderConfig,
} from "@midnight-ntwrk/trust-registry-integration";

import { createLocalLedgerBoundSource, LocalLedgerSourceUnavailableError } from "./local-ledger-source.js";
import { verifyLocalApiApprovalChain } from "./local-approval-chain.js";
import { readBoundedLocalApprovalFile, verifyDetachedLocalReviewerSignature } from "./local-reviewer-signature.js";
export { assertApprovedReviewerSignatureStatus } from "./local-reviewer-signature.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;

export type LocalLedgerRuntimePlan = LocalNetworkDeploymentActionReaderConfig & {
  format: "tr-local-api-runtime-v2" | "tr-local-api-runtime-v3";
  approvalChainPath?: string;
  approvalChainSha256?: string;
  sourceRevision: string;
  installInventoryPath: string;
  installInventorySha256: string;
  releaseManifestPath: string;
  releaseManifestSha256: string;
  contractAddress: string;
  snapshotPath: string;
  snapshotSha256: string;
  verifierKeySha256: Readonly<Record<string, string>>;
  maintenanceAuthority: {
    committee: readonly string[];
    threshold: number;
    counter: string;
  };
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

function validMaintenanceAuthority(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const authority = value as Record<string, unknown>;
  if (!exactKeys(authority, ["committee", "threshold", "counter"])
    || !Array.isArray(authority.committee) || authority.committee.length < 3
    || authority.committee.some((key: unknown) =>
      typeof key !== "string" || !HASH.test(key) || /^0x0{64}$/u.test(key))
    || new Set(authority.committee).size !== authority.committee.length
    || !Number.isSafeInteger(authority.threshold)
    || (authority.threshold as number) < 2
    || (authority.threshold as number) > authority.committee.length
    || typeof authority.counter !== "string" || !DECIMAL.test(authority.counter)
    || BigInt(authority.counter) < 1n) return false;
  return true;
}

export function validateLocalLedgerRuntimePlan(value: unknown): LocalLedgerRuntimePlan {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Local API runtime plan must be an object");
  }
  const plan = value as Record<string, unknown>;
  const approvalChainKeys = plan.format === "tr-local-api-runtime-v3"
    ? ["approvalChainPath", "approvalChainSha256"] : [];
  if (!exactKeys(plan, ["allowedHosts", "contractAddress", "expectedGenesisHash", "format",
    "indexerHttpUrl", "indexerWsUrl", "installInventoryPath", "installInventorySha256",
    "maintenanceAuthority", "networkId", "notAfter", "notBefore", "releaseManifestPath",
    "releaseManifestSha256", "rpcUrl", "sequenceTimestamps", "snapshotPath", "snapshotSha256",
    "sourceRevision", "verifierKeySha256", ...approvalChainKeys])
    || !["tr-local-api-runtime-v2", "tr-local-api-runtime-v3"].includes(plan.format as string)
    || (plan.format === "tr-local-api-runtime-v3"
      && (typeof plan.approvalChainPath !== "string" || !isAbsolute(plan.approvalChainPath)
        || typeof plan.approvalChainSha256 !== "string" || !SHA256.test(plan.approvalChainSha256)))
    || plan.networkId !== "undeployed"
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
    || plan.verifierKeySha256 === null || typeof plan.verifierKeySha256 !== "object"
    || Array.isArray(plan.verifierKeySha256)
    || Object.keys(plan.verifierKeySha256).length === 0
    || Object.entries(plan.verifierKeySha256).some(([name, digest]) =>
      name.length === 0 || typeof digest !== "string" || !SHA256.test(digest))
    || !validMaintenanceAuthority(plan.maintenanceAuthority)
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

export function assertApprovedDeploymentImage(
  plan: Pick<LocalLedgerRuntimePlan, "networkId" | "contractAddress" | "verifierKeySha256" | "maintenanceAuthority">,
  view: Pick<FinalizedRegistryLedgerView, "networkId" | "contractAddress" | "verifierKeySha256" | "maintenanceAuthority">,
): void {
  if (view.networkId !== plan.networkId || view.contractAddress !== plan.contractAddress) {
    throw new Error("Finalized registry identity differs from the approved local plan");
  }
  const expected = plan.verifierKeySha256;
  const observed = view.verifierKeySha256;
  if (observed === null || typeof observed !== "object" || Array.isArray(observed)
    || Object.keys(observed).length !== Object.keys(expected).length
    || Object.entries(expected).some(([name, digest]) =>
      !Object.hasOwn(observed, name) || observed[name] !== digest)) {
    throw new Error("Finalized verifier-key catalog differs from the approved local plan");
  }
  const authority = view.maintenanceAuthority;
  const approved = plan.maintenanceAuthority;
  if (!authority || !Array.isArray(authority.committee)
    || authority.committee.length !== approved.committee.length
    || authority.committee.some((key, index) => key !== approved.committee[index])
    || authority.threshold !== approved.threshold
    || authority.counter !== BigInt(approved.counter)) {
    throw new Error("Finalized maintenance authority differs from the approved local plan");
  }
}

export async function assertLocalApiImageSourceRevision(
  expectedRevision: string,
  path = "/app/source-revision",
): Promise<void> {
  if (!REVISION.test(expectedRevision)) {
    throw new Error("Local API image source revision is malformed");
  }
  const bytes = await readBoundedLocalApprovalFile(path, 41);
  if (bytes.toString("utf8") !== `${expectedRevision}\n`) {
    throw new Error("Container source-revision file differs from the approved local plan");
  }
}

type ApprovedLocalLedgerRuntimePlanInput = {
  planPath: string;
  signaturePath: string;
  keyringDirectory: string;
  reviewerFingerprint: string;
  requireApiRuntimePin?: boolean;
};

export async function loadApprovedLocalLedgerRuntimePlanWithDigest(
  input: ApprovedLocalLedgerRuntimePlanInput,
): Promise<{ plan: LocalLedgerRuntimePlan; planSha256: string }> {
  const planBytes = await readBoundedLocalApprovalFile(input.planPath, 1024 * 1024);
  await verifyDetachedLocalReviewerSignature({
    documentBytes: planBytes,
    signaturePath: input.signaturePath,
    keyringDirectory: input.keyringDirectory,
    reviewerFingerprint: input.reviewerFingerprint,
  });
  const plan = validateLocalLedgerRuntimePlan(parseCanonicalApprovedPlan(planBytes));
  const inventoryBytes = await readBoundedLocalApprovalFile(plan.installInventoryPath, 1024 * 1024);
  const manifestBytes = await readBoundedLocalApprovalFile(plan.releaseManifestPath, 1024 * 1024);
  const digest = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");
  if (digest(inventoryBytes) !== plan.installInventorySha256
    || digest(manifestBytes) !== plan.releaseManifestSha256) {
    throw new Error("Local API install or release manifest differs from approved bytes");
  }
  const inventory = JSON.parse(inventoryBytes.toString("utf8"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const installFormat = inventory?.format;
  const supportedFormat = ["tr-standalone-install-v4",
    "tr-standalone-install-v5", "tr-standalone-install-v6"].includes(installFormat);
  if (installFormat === "tr-standalone-install-v3" && input.requireApiRuntimePin === true) {
    throw new Error("Cluster API binding requires a signed install with an API image pin");
  }
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
    || inventory.packageManifest !== "release-manifest.json"
    || inventory.packageManifestSha256 !== plan.releaseManifestSha256
    || plan.releaseManifestPath !== join(dirname(plan.installInventoryPath), inventory.packageManifest)
    || !artifactPin(inventory.apiRuntime,
      "images/api.manifest.json", "images/api.image.tar")
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
  const approvedKeys = Object.entries(plan.verifierKeySha256);
  if (manifest.verifierKeySha256 === null || typeof manifest.verifierKeySha256 !== "object"
    || Array.isArray(manifest.verifierKeySha256)
    || Object.keys(manifest.verifierKeySha256 ?? {}).length !== approvedKeys.length
    || approvedKeys.some(([name, hash]) =>
      !Object.hasOwn(manifest.verifierKeySha256, name)
      || manifest.verifierKeySha256[name] !== hash)) {
    throw new Error("Local API approved verifier-key catalog differs from the release manifest");
  }
  if (plan.format === "tr-local-api-runtime-v3") {
    const chainBytes = await readBoundedLocalApprovalFile(plan.approvalChainPath!, 512 * 1024, true);
    if (digest(chainBytes) !== plan.approvalChainSha256) {
      throw new Error("Local API approval-chain bytes differ from the signed runtime plan");
    }
    await verifyLocalApiApprovalChain({ chainBytes, plan,
      keyringDirectory: input.keyringDirectory,
      governanceReviewerFingerprint: input.reviewerFingerprint });
  }
  return { plan, planSha256: digest(planBytes) };
}

export async function loadApprovedLocalLedgerRuntimePlan(
  input: ApprovedLocalLedgerRuntimePlanInput,
): Promise<LocalLedgerRuntimePlan> {
  return (await loadApprovedLocalLedgerRuntimePlanWithDigest(input)).plan;
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
          assertApprovedDeploymentImage(plan, view);
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
    localDeploymentBinding: {
      contractAddress: plan.contractAddress,
      expectedGenesisHash: plan.expectedGenesisHash,
    },
    async loadSnapshot() {
      assertPlanCurrent();
      const snapshot = await source.loadSnapshot();
      assertPlanCurrent();
      return snapshot;
    },
    async loadCurrentLedgerSelection() {
      assertPlanCurrent();
      const selection = await source.loadCurrentLedgerSelection();
      assertPlanCurrent();
      return selection;
    },
    async readFinalizedProposalLedger() {
      assertPlanCurrent();
      const ledger = await source.readFinalizedProposalLedger();
      assertPlanCurrent();
      return ledger;
    },
  };
}
