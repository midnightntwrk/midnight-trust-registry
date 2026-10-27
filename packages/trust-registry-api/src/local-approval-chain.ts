import { createHash } from "node:crypto";

import { committeeMaintenanceUpdateSha256 } from "@midnight-ntwrk/trust-registry-integration";

import { verifyDetachedLocalReviewerSignature } from "./local-reviewer-signature.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const FINGERPRINT = /^[A-F0-9]{40}$/u;

const digest = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");
const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (value: unknown, keys: readonly string[]): value is Record<string, unknown> =>
  object(value) && Object.keys(value).length === keys.length
  && keys.every((key) => Object.hasOwn(value, key));

function canonicalJson(bytes: Buffer, label: string): Record<string, unknown> {
  const raw = bytes.toString("utf8");
  const parsed: unknown = JSON.parse(raw);
  if (!object(parsed) || !Buffer.from(raw, "utf8").equals(bytes)
    || ![JSON.stringify(parsed), `${JSON.stringify(parsed)}\n`,
      `${JSON.stringify(parsed, null, 2)}\n`].includes(raw)) {
    throw new Error(`${label} must be canonical JSON without duplicate keys`);
  }
  return parsed;
}

function decode(value: unknown, hash: unknown, label: string): Buffer {
  if (typeof value !== "string" || value.length === 0 || value.length > 90_000
    || typeof hash !== "string" || !SHA256.test(hash)) {
    throw new Error(`${label} has no bounded encoded evidence`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.length === 0 || bytes.toString("base64") !== value || digest(bytes) !== hash) {
    throw new Error(`${label} differs from its pinned SHA-256`);
  }
  return bytes;
}

export type ApprovalChainPlanPins = {
  sourceRevision: string;
  installInventorySha256: string;
  releaseManifestSha256: string;
  networkId: string;
  rpcUrl: string;
  expectedGenesisHash: string;
  contractAddress: string;
  verifierKeySha256: Readonly<Record<string, string>>;
  maintenanceAuthority: { committee: readonly string[]; threshold: number; counter: string };
};

export async function verifyLocalApiApprovalChain(input: {
  chainBytes: Buffer;
  plan: ApprovalChainPlanPins;
  keyringDirectory: string;
  governanceReviewerFingerprint: string;
}): Promise<void> {
  const chain = canonicalJson(input.chainBytes, "Local API approval chain");
  if (!exact(chain, ["format", "sourceRevision", "installInventorySha256",
    "releaseManifestSha256", "networkId", "expectedGenesisHash", "contractAddress",
    "genesisApproval", "committeeApproval", "committeeDeploymentApproval", "maintenanceReadback"])
    || chain.format !== "tr-local-api-approval-chain-v1") {
    throw new Error("Local API approval chain has an unsupported shape");
  }
  const plan = input.plan;
  for (const key of ["sourceRevision", "installInventorySha256", "releaseManifestSha256",
    "networkId", "expectedGenesisHash", "contractAddress"] as const) {
    if (chain[key] !== plan[key]) {
      throw new Error(`Local API approval chain ${key} differs from the signed runtime plan`);
    }
  }
  const readApproval = async (entry: unknown, label: string,
    expectedFingerprint?: string): Promise<{ document: Record<string, unknown>; hash: string }> => {
    if (!exact(entry, ["documentBase64", "documentSha256", "signatureBase64",
      "signatureSha256", "reviewerFingerprint"])
      || typeof entry.reviewerFingerprint !== "string"
      || !FINGERPRINT.test(entry.reviewerFingerprint)
      || (expectedFingerprint !== undefined && entry.reviewerFingerprint !== expectedFingerprint)) {
      throw new Error(`${label} has no approved reviewer identity`);
    }
    const documentBytes = decode(entry.documentBase64, entry.documentSha256, `${label} document`);
    const signatureBytes = decode(entry.signatureBase64, entry.signatureSha256, `${label} signature`);
    const document = canonicalJson(documentBytes, label);
    if (document.reviewerFingerprint !== entry.reviewerFingerprint) {
      throw new Error(`${label} reviewer differs from signed bytes`);
    }
    await verifyDetachedLocalReviewerSignature({
      documentBytes, signatureBytes, keyringDirectory: input.keyringDirectory,
      reviewerFingerprint: entry.reviewerFingerprint, description: label,
    });
    return { document, hash: entry.documentSha256 as string };
  };
  const genesis = await readApproval(chain.genesisApproval, "Genesis approval");
  const committee = await readApproval(chain.committeeApproval, "Committee approval",
    input.governanceReviewerFingerprint);
  const deployment = await readApproval(chain.committeeDeploymentApproval,
    "Committee deployment approval", input.governanceReviewerFingerprint);
  if (!exact(genesis.document, ["approvedAt", "expectedGenesisHash", "format",
    "installInventorySha256", "networkId", "pinSha256", "reviewedReference",
    "reviewerFingerprint", "rpcUrl", "setupId", "sourceRevision", "stackProject"])
    || genesis.document.format !== "tr-local-genesis-approval-v1"
    || !exact(committee.document, ["approvedAt", "custodians", "deploymentPlanSha256",
      "expectedGenesisHash", "format", "genesisApprovalSha256", "installInventorySha256",
      "maintenancePolicy", "networkId", "providerModuleSha256", "reviewedReference",
      "reviewerFingerprint", "sourceRevision"])
    || committee.document.format !== "tr-local-committee-approval-v2"
    || !exact(deployment.document, ["approvedAt", "committeeApprovalSha256",
      "deploymentPlanSha256", "deploymentReceipt", "expectedGenesisHash", "format",
      "releaseManifestSha256", "reviewedReference", "reviewerFingerprint", "sourceRevision"])
    || deployment.document.format !== "tr-local-committee-deployment-approval-v1") {
    throw new Error("Local API approval chain contains an unsupported signed document");
  }
  const policy = committee.document.maintenancePolicy;
  const custodians = committee.document.custodians;
  const receipt = deployment.document.deploymentReceipt;
  const maintenance = chain.maintenanceReadback;
  const metadata = [genesis.document, committee.document, deployment.document];
  if (!exact(policy, ["mode", "threshold", "verifyingKeys"])
    || policy.mode !== "committee"
    || !Array.isArray(policy.verifyingKeys)
    || !Array.isArray(custodians) || custodians.length !== policy.verifyingKeys.length
    || custodians.some((entry, index) => !exact(entry,
      ["custodyReference", "holderRole", "verifyingKey"])
      || entry.verifyingKey !== (policy.verifyingKeys as unknown[])[index]
      || typeof entry.holderRole !== "string" || entry.holderRole.length < 3
      || typeof entry.custodyReference !== "string" || entry.custodyReference.length < 8)
    || new Set(custodians.map((entry) => (entry as Record<string, unknown>).holderRole)).size
      !== custodians.length
    || !exact(receipt, ["blockHash", "blockHeight", "contractAddress", "networkId", "txId"])
    || !exact(maintenance, ["committeeDeploymentApprovalSha256", "updateSha256",
      "txId", "finalizedBlockHash", "status"])
    || genesis.document.sourceRevision !== plan.sourceRevision
    || committee.document.sourceRevision !== plan.sourceRevision
    || deployment.document.sourceRevision !== plan.sourceRevision
    || genesis.document.installInventorySha256 !== plan.installInventorySha256
    || genesis.document.rpcUrl !== plan.rpcUrl
    || typeof genesis.document.pinSha256 !== "string"
    || !SHA256.test(genesis.document.pinSha256)
    || metadata.some((document) => typeof document.reviewedReference !== "string"
      || document.reviewedReference.length < 8 || document.reviewedReference.length > 512
      || document.reviewedReference.startsWith("demo:")
      || typeof document.approvedAt !== "string"
      || !Number.isFinite(Date.parse(document.approvedAt))
      || new Date(Date.parse(document.approvedAt)).toISOString() !== document.approvedAt)
    || Date.parse(genesis.document.approvedAt as string) > Date.parse(committee.document.approvedAt as string)
    || Date.parse(committee.document.approvedAt as string) > Date.parse(deployment.document.approvedAt as string)
    || committee.document.installInventorySha256 !== plan.installInventorySha256
    || committee.document.genesisApprovalSha256 !== genesis.hash
    || deployment.document.committeeApprovalSha256 !== committee.hash
    || committee.document.deploymentPlanSha256 !== deployment.document.deploymentPlanSha256
    || genesis.document.networkId !== plan.networkId
    || committee.document.networkId !== plan.networkId
    || genesis.document.expectedGenesisHash !== plan.expectedGenesisHash
    || committee.document.expectedGenesisHash !== plan.expectedGenesisHash
    || deployment.document.expectedGenesisHash !== plan.expectedGenesisHash
    || deployment.document.releaseManifestSha256 !== plan.releaseManifestSha256
    || receipt.networkId !== plan.networkId || receipt.contractAddress !== plan.contractAddress
    || !HASH.test(receipt.blockHash as string) || /^0x0{64}$/u.test(receipt.blockHash as string)
    || !Number.isSafeInteger(receipt.blockHeight) || (receipt.blockHeight as number) < 0
    || typeof receipt.txId !== "string" || receipt.txId.length === 0
    || policy.threshold !== plan.maintenanceAuthority.threshold
    || JSON.stringify(policy.verifyingKeys) !== JSON.stringify(plan.maintenanceAuthority.committee)
    || plan.maintenanceAuthority.counter !== String(Object.keys(plan.verifierKeySha256).length)
    || maintenance.status !== "observed"
    || maintenance.committeeDeploymentApprovalSha256 !== deployment.hash
    || typeof maintenance.updateSha256 !== "string" || !SHA256.test(maintenance.updateSha256)
    || typeof maintenance.txId !== "string" || maintenance.txId.length === 0
    || maintenance.txId === receipt.txId
    || !HASH.test(maintenance.finalizedBlockHash as string)
    || /^0x0{64}$/u.test(maintenance.finalizedBlockHash as string)) {
    throw new Error("Local API approval chain disagrees with the approved deployment or maintenance state");
  }
  if (!/^[1-9][0-9]*$/u.test(plan.maintenanceAuthority.counter)
    || committeeMaintenanceUpdateSha256({
      contractAddress: plan.contractAddress,
      committee: plan.maintenanceAuthority.committee,
      threshold: plan.maintenanceAuthority.threshold,
      currentCounter: BigInt(plan.maintenanceAuthority.counter) - 1n,
    }) !== maintenance.updateSha256) {
    throw new Error("Local API maintenance update differs from the approved committee action");
  }
}
