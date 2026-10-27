import { getLocalNetworkProfile } from "@midnight-ntwrk/trust-registry-integration";

import { STANDALONE_IMAGE_REFERENCE } from "./standalone-image-reference.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const PROJECT = /^tr-standalone-local-[a-z0-9][a-z0-9-]*[a-z0-9]$/u;

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/** @param {unknown} value @param {readonly string[]} fields @returns {value is Record<string, unknown>} */
const exactFields = (value, fields) => isRecord(value)
  && Object.keys(value).sort().join("\0") === [...fields].sort().join("\0");

/** @param {unknown} value */
const validLoopbackRpcUrl = (value) => {
  const match = typeof value === "string"
    ? /^http:\/\/127\.0\.0\.1:([1-9][0-9]*)$/u.exec(value) : null;
  return match !== null && Number(match[1]) >= 1024 && Number(match[1]) <= 65535;
};

/**
 * Compare only node-reported data against the selected installation; independent
 * chain-spec review and the human's detached approval remain separate gates.
 * @param {unknown} recordValue
 * @param {unknown} candidateValue
 * @param {unknown} pinValue
 * @param {unknown} verifiedValue
 */
export function validateGenesisReviewEvidence(recordValue, candidateValue, pinValue, verifiedValue) {
  const profile = getLocalNetworkProfile();
  const record = isRecord(recordValue) ? recordValue : null;
  const install = record !== null && isRecord(record.install) ? record.install : null;
  const stack = record !== null && isRecord(record.stack) ? record.stack : null;
  const verified = isRecord(verifiedValue) ? verifiedValue : null;
  if (record === null || !exactFields(record.networkProfile,
    ["id", "networkId", "kind", "genesisPinPolicy"])
    || JSON.stringify(record.networkProfile) !== JSON.stringify(profile)
    || typeof record.sourceRevision !== "string" || !REVISION.test(record.sourceRevision)
    || install === null || typeof install.inventorySha256 !== "string"
    || !SHA256.test(install.inventorySha256)
    || stack === null || typeof stack.project !== "string" || !PROJECT.test(stack.project)
    || stack.state !== "observed-ledger-bridge-only" || !isRecord(stack.observation)
    || verified === null || verified.sourceRevision !== record.sourceRevision
    || verified.inventorySha256 !== install.inventorySha256
    || !Array.isArray(verified.images)) {
    throw new Error("Review packet requires a verified profiled standalone installation");
  }
  const nodeImage = verified.images.find((image) => isRecord(image) && image.role === "node");
  if (!isRecord(nodeImage) || typeof nodeImage.reference !== "string"
    || !STANDALONE_IMAGE_REFERENCE.test(nodeImage.reference)) {
    throw new Error("Review packet requires the pinned node image identity");
  }
  const candidate = candidateValue;
  if (!exactFields(candidate, ["format", "sourceRevision", "installInventorySha256",
    "project", "networkId", "nodeReportedGenesisHash", "nodeReportedFinalizedBlockHash",
    "nodeReportedFinalizedHeight", "observerSha256", "observedAt", "status"])
    || candidate.format !== "tr-local-genesis-candidate-v1"
    || candidate.status !== "untrusted-node-observation-independent-review-required"
    || candidate.sourceRevision !== record.sourceRevision
    || candidate.installInventorySha256 !== verified.inventorySha256
    || candidate.project !== stack.project
    || candidate.networkId !== profile.networkId
    || typeof candidate.nodeReportedGenesisHash !== "string"
    || !HASH.test(candidate.nodeReportedGenesisHash)
    || /^0x0{64}$/u.test(candidate.nodeReportedGenesisHash)
    || typeof candidate.nodeReportedFinalizedBlockHash !== "string"
    || !HASH.test(candidate.nodeReportedFinalizedBlockHash)
    || typeof candidate.nodeReportedFinalizedHeight !== "number"
    || !Number.isSafeInteger(candidate.nodeReportedFinalizedHeight)
    || candidate.nodeReportedFinalizedHeight < 1
    || typeof candidate.observerSha256 !== "string" || !SHA256.test(candidate.observerSha256)
    || typeof candidate.observedAt !== "string"
    || !Number.isFinite(Date.parse(candidate.observedAt))
    || new Date(Date.parse(candidate.observedAt)).toISOString() !== candidate.observedAt) {
    throw new Error("Untrusted genesis candidate differs from the observed installation");
  }
  const pin = pinValue;
  if (!exactFields(pin, ["format", "networkId", "sourceRevision", "rpcUrl",
    "expectedGenesisHash", "allowedHosts"])
    || pin.format !== "tr-local-ledger-pin-v1"
    || pin.networkId !== profile.networkId
    || pin.sourceRevision !== record.sourceRevision
    || pin.expectedGenesisHash !== candidate.nodeReportedGenesisHash
    || !validLoopbackRpcUrl(pin.rpcUrl)
    || JSON.stringify(pin.allowedHosts) !== '["127.0.0.1"]') {
    throw new Error("Proposed genesis pin differs from the untrusted candidate");
  }
  return { sourceRevision: record.sourceRevision, project: stack.project,
    networkId: profile.networkId, inventorySha256: verified.inventorySha256,
    nodeImage: nodeImage.reference, nodeReportedGenesisHash: candidate.nodeReportedGenesisHash,
    observedAt: candidate.observedAt, rpcUrl: pin.rpcUrl };
}
