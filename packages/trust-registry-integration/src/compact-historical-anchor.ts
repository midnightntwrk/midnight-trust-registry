import { Buffer } from "node:buffer";

import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import {
  MaintainerStatus,
  type Ledger,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import {
  bytes32Commitment,
  bytes32Hex,
  type EpochAnchorVerificationContext,
  type SequenceToTimestamp,
} from "@midnight-ntwrk/trust-registry-client";

const POLICY_VERSION = /^v([1-9]\d*)$/u;
const same = (left: Uint8Array, right: Uint8Array): boolean => Buffer.from(left).equals(Buffer.from(right));

/** The caller must first authenticate this ledger as a finalized view of the selected deployment. */
export function resolveCompactHistoricalEpochAnchor(input: {
  ledger: Ledger;
  registryId: string;
  epochId: string;
  policyVersion: string;
  /** Resolve from the authenticated deployment selection, never from the evidence bundle. */
  contractAddress: Uint8Array;
  sequenceToTimestamp: SequenceToTimestamp;
}): EpochAnchorVerificationContext {
  const { ledger } = input;
  if (ledger.contractVersion !== 1n) throw new Error("Unsupported trust registry format");
  for (const [name, value] of [
    ["Deployment network ID commitment", ledger.deploymentNetworkIdCommitment],
    ["Contract address", input.contractAddress],
  ] as const) {
    if (!(value instanceof Uint8Array) || value.length !== 32 || value.every((byte) => byte === 0)) {
      throw new Error(`${name} is missing or malformed`);
    }
  }
  const registryIdCommitment = bytes32Commitment(input.registryId);
  if (!same(ledger.registryId, registryIdCommitment)) {
    throw new Error("Historical registry ID does not match finalized Compact ledger");
  }
  const epochIdCommitment = bytes32Commitment(input.epochId);
  if (!ledger.epochCommitmentRecords.member(epochIdCommitment)) {
    throw new Error("Historical epoch is absent from finalized Compact ledger");
  }
  const epochRecord = ledger.epochCommitmentRecords.lookup(epochIdCommitment);
  if (!same(epochRecord.epochId, epochIdCommitment)
    || epochRecord.publishedAtSequence > ledger.governanceActionCount) {
    throw new Error("Historical epoch record is inconsistent with finalized Compact ledger");
  }

  const match = POLICY_VERSION.exec(input.policyVersion);
  if (match === null) throw new Error("Historical policy version is invalid");
  const policyVersion = BigInt(match[1]!);
  if (policyVersion > ledger.governancePolicyVersion
    || !ledger.governancePolicyCommitmentsByVersion.member(policyVersion)
    || bytes32Hex(ledger.governancePolicyCommitmentsByVersion.lookup(policyVersion)) !== bytes32Hex(epochRecord.policyRoot)) {
    throw new Error("Historical policy root is not committed at the selected version");
  }

  const signerKeyId = epochRecord.maintainerKeyId;
  if (!ledger.maintainerRecords.member(signerKeyId)) {
    throw new Error("Historical publication signer is absent from finalized Compact ledger");
  }
  const signer = ledger.maintainerRecords.lookup(signerKeyId);
  if (!same(signer.keyId, signerKeyId)
    || signer.joinedAtSequence > epochRecord.publishedAtSequence
    || (signer.status !== MaintainerStatus.active
      && signer.lastStatusSequence <= epochRecord.publishedAtSequence)) {
    throw new Error("Historical publication signer is inconsistent with the epoch");
  }
  const nextVersion = policyVersion + 1n;
  const policySupersededAt = nextVersion <= ledger.governancePolicyVersion
    ? input.sequenceToTimestamp(ledger.governancePolicyEffectiveFromByVersion.lookup(nextVersion))
    : undefined;
  return {
    epochRecord,
    maintainerPublicKey: signer.publicKey as JubjubPoint,
    registryIdCommitment,
    networkIdCommitment: Uint8Array.from(ledger.deploymentNetworkIdCommitment),
    contractAddress: Uint8Array.from(input.contractAddress),
    sequenceToTimestamp: input.sequenceToTimestamp,
    ...(policySupersededAt === undefined ? {} : { policySupersededAt }),
  };
}
