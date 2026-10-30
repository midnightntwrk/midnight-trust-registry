import { createHash } from "node:crypto";

import { getLocalNetworkProfile } from "@midnight-ntwrk/trust-registry-integration";

const FINGERPRINT = /^[A-F0-9]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const SOURCE_REVISION = /^[0-9a-f]{40}$/u;

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/** @param {unknown} value @param {string} label */
const requireRecord = (value, label) => {
  if (!isRecord(value)) throw new Error(`${label} is missing`);
  return value;
};

/** @param {Buffer} bytes @param {string} label */
const parseCanonicalSignedJson = (bytes, label) => {
  const raw = bytes.toString("utf8");
  const parsed = requireRecord(JSON.parse(raw), label);
  if (!Buffer.from(raw, "utf8").equals(bytes)
    || (raw !== JSON.stringify(parsed) && raw !== `${JSON.stringify(parsed, null, 2)}\n`)) {
    throw new Error(`${label} must use canonical signed JSON without duplicate keys`);
  }
  return parsed;
};

/** @param {Buffer} bytes */
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** @param {unknown} value @param {string} label */
const approval = (value, label) => {
  const entry = requireRecord(value, `${label} reviewer approval`);
  if (typeof entry.reviewerFingerprint !== "string" || !FINGERPRINT.test(entry.reviewerFingerprint)) {
    throw new Error(`${label} reviewer approval is missing`);
  }
  /** @param {unknown} encoded @param {unknown} expected @param {string} kind */
  const decode = (encoded, expected, kind) => {
    if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > 90_000) {
      throw new Error(`${label} ${kind} is missing or oversized`);
    }
    const bytes = Buffer.from(encoded, "base64");
    if (bytes.toString("base64") !== encoded || sha256(bytes) !== expected) {
      throw new Error(`${label} ${kind} differs from the recorded digest`);
    }
    return bytes;
  };
  const document = decode(entry.documentBase64, entry.documentSha256, "document");
  decode(entry.signatureBase64, entry.signatureSha256, "signature");
  const parsed = parseCanonicalSignedJson(document, label);
  if (parsed.reviewerFingerprint !== entry.reviewerFingerprint) {
    throw new Error(`${label} reviewer fingerprint differs from signed bytes`);
  }
  return {
    documentBase64: entry.documentBase64,
    documentSha256: entry.documentSha256,
    signatureBase64: entry.signatureBase64,
    signatureSha256: entry.signatureSha256,
    reviewerFingerprint: entry.reviewerFingerprint,
    parsed,
  };
};

/** @param {Record<string, unknown>} receipt */
const validLocalDeploymentReceipt = (receipt) => receipt.networkId === getLocalNetworkProfile().networkId
  && typeof receipt.contractAddress === "string" && HASH.test(receipt.contractAddress)
  && !/^0x0{64}$/u.test(receipt.contractAddress)
  && typeof receipt.blockHash === "string" && HASH.test(receipt.blockHash)
  && !/^0x0{64}$/u.test(receipt.blockHash)
  && typeof receipt.txId === "string" && receipt.txId.length > 0
  && typeof receipt.blockHeight === "number" && Number.isSafeInteger(receipt.blockHeight)
  && receipt.blockHeight >= 0;

/**
 * Validate recorded, already verified approval evidence before exporting its restricted API handoff.
 * This does not verify detached signatures, authenticate finality, or approve a deployment.
 * @param {unknown} value
 * @param {unknown} releaseManifestSha256
 */
export function buildStandaloneApiApprovalChain(value, releaseManifestSha256) {
  const record = requireRecord(value, "Standalone setup record");
  const genesis = approval(record.genesisApproval, "Genesis");
  const committee = approval(record.committeeApproval, "Committee");
  const deployment = approval(record.committeeDeploymentApproval, "Deployment");
  const install = requireRecord(record.install, "Installed inventory");
  const deployed = requireRecord(record.deployment, "Finalized deployment");
  const result = requireRecord(deployed.result, "Finalized deployment result");
  const receipt = requireRecord(result.receipt, "Finalized deployment receipt");
  const attempt = requireRecord(record.maintenanceAttempt, "Maintenance attempt");
  const observed = requireRecord(attempt.reconciliation, "Maintenance readback");
  if (deployed.state !== "observed" || !validLocalDeploymentReceipt(receipt)
    || attempt.state !== "observed" || attempt.alert || observed.status !== "observed"
    || typeof attempt.txId !== "string" || !attempt.txId
    || attempt.txId === receipt.txId
    || observed.txId !== attempt.txId || typeof observed.finalizedBlockHash !== "string"
    || !HASH.test(observed.finalizedBlockHash) || /^0x0{64}$/u.test(observed.finalizedBlockHash)
    || typeof attempt.updateSha256 !== "string" || !SHA256.test(attempt.updateSha256)
    || attempt.committeeDeploymentApprovalSha256 !== deployment.documentSha256
    || typeof releaseManifestSha256 !== "string" || !SHA256.test(releaseManifestSha256)) {
    throw new Error("Finalized deployment and unambiguous maintenance readback are required");
  }
  const deploymentReceipt = requireRecord(deployment.parsed.deploymentReceipt, "Signed deployment receipt");
  if (genesis.parsed.format !== "tr-local-genesis-approval-v1"
    || committee.parsed.format !== "tr-local-committee-approval-v2"
    || deployment.parsed.format !== "tr-local-committee-deployment-approval-v1"
    || typeof record.sourceRevision !== "string" || !SOURCE_REVISION.test(record.sourceRevision)
    || typeof install.inventorySha256 !== "string" || !SHA256.test(install.inventorySha256)
    || genesis.parsed.sourceRevision !== record.sourceRevision
    || committee.parsed.sourceRevision !== record.sourceRevision
    || deployment.parsed.sourceRevision !== record.sourceRevision
    || genesis.parsed.installInventorySha256 !== install.inventorySha256
    || committee.parsed.installInventorySha256 !== install.inventorySha256
    || committee.parsed.genesisApprovalSha256 !== genesis.documentSha256
    || committee.parsed.networkId !== genesis.parsed.networkId
    || committee.parsed.expectedGenesisHash !== genesis.parsed.expectedGenesisHash
    || committee.parsed.reviewerFingerprint !== deployment.reviewerFingerprint
    || deployment.parsed.committeeApprovalSha256 !== committee.documentSha256
    || deployment.parsed.deploymentPlanSha256 !== committee.parsed.deploymentPlanSha256
    || deployment.parsed.expectedGenesisHash !== genesis.parsed.expectedGenesisHash
    || deployment.parsed.releaseManifestSha256 !== releaseManifestSha256
    || receipt.networkId !== genesis.parsed.networkId
    || !["networkId", "contractAddress", "blockHash", "blockHeight", "txId"]
      .every((key) => deploymentReceipt[key] === receipt[key])) {
    throw new Error("Signed approval chain disagrees with the observed install or deployment");
  }
  /** @param {ReturnType<typeof approval>} entry */
  const publicApproval = ({ parsed: _parsed, ...evidence }) => evidence;
  return {
    format: "tr-local-api-approval-chain-v1",
    sourceRevision: record.sourceRevision,
    installInventorySha256: install.inventorySha256,
    releaseManifestSha256,
    networkId: genesis.parsed.networkId,
    expectedGenesisHash: genesis.parsed.expectedGenesisHash,
    contractAddress: receipt.contractAddress,
    genesisApproval: publicApproval(genesis),
    committeeApproval: publicApproval(committee),
    committeeDeploymentApproval: publicApproval(deployment),
    maintenanceReadback: {
      committeeDeploymentApprovalSha256: deployment.documentSha256,
      updateSha256: attempt.updateSha256,
      txId: attempt.txId,
      finalizedBlockHash: observed.finalizedBlockHash,
      status: "observed",
    },
  };
}

/**
 * A first-run pin candidate for operator review and protected installation.
 * The API must verify an independently installed copy; this private export is
 * not itself a trusted runtime anchor.
 * @param {ReturnType<typeof buildStandaloneApiApprovalChain>} chain
 * @param {Buffer} chainBytes
 */
export function buildStandaloneApiTrustAnchor(chain, chainBytes) {
  const parsed = parseCanonicalSignedJson(chainBytes, "API approval chain");
  if (JSON.stringify(parsed) !== JSON.stringify(chain)
    || chain.format !== "tr-local-api-approval-chain-v1"
    || !SOURCE_REVISION.test(chain.sourceRevision)
    || !SHA256.test(chain.installInventorySha256)
    || !SHA256.test(chain.releaseManifestSha256)
    || typeof chain.expectedGenesisHash !== "string" || !HASH.test(chain.expectedGenesisHash)
    || typeof chain.contractAddress !== "string" || !HASH.test(chain.contractAddress)) {
    throw new Error("API trust anchor requires exact exported approval-chain bytes");
  }
  const genesis = approval(chain.genesisApproval, "Genesis");
  const committee = approval(chain.committeeApproval, "Committee");
  const deployment = approval(chain.committeeDeploymentApproval, "Deployment");
  if (committee.parsed.genesisApprovalSha256 !== genesis.documentSha256
    || deployment.parsed.committeeApprovalSha256 !== committee.documentSha256
    || committee.reviewerFingerprint !== deployment.reviewerFingerprint) {
    throw new Error("API trust anchor reviewer chain is inconsistent");
  }
  return {
    format: "tr-local-api-trust-anchor-v1",
    sourceRevision: chain.sourceRevision,
    installInventorySha256: chain.installInventorySha256,
    releaseManifestSha256: chain.releaseManifestSha256,
    networkId: chain.networkId,
    expectedGenesisHash: chain.expectedGenesisHash,
    contractAddress: chain.contractAddress,
    approvalChainSha256: sha256(chainBytes),
    genesisApprovalSha256: genesis.documentSha256,
    genesisReviewerFingerprint: genesis.reviewerFingerprint,
    governanceReviewerFingerprint: committee.reviewerFingerprint,
  };
}
