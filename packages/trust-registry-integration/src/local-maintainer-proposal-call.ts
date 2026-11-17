import { Buffer } from "node:buffer";

import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import {
  AuthorizationStatus,
  computeCreateMaintainerMembershipPayloadHash,
  computeMaintainerEvidenceBoundProposalPayloadHash,
  encodeCompactActionKind,
  EvidenceVerifierKeyStatus,
  isPrimeOrderJubjubPoint,
  TrustRegistryContract,
} from "@midnight-ntwrk/trust-registry-contract";

type Ledger = TrustRegistryContract.Ledger;
type PublicKey = Parameters<typeof computeCreateMaintainerMembershipPayloadHash>[3];

export type UnsignedLocalMaintainerProposalCall = {
  networkId: "undeployed";
  registryId: string;
  contractAddress: string;
  maintainerLabel: string;
  maintainerId: Uint8Array;
  maintainerDidCommitment: Uint8Array;
  candidateKeyId: Uint8Array;
  candidatePublicKey: PublicKey;
  policyId: Uint8Array;
  trustLevel: Uint8Array;
  evidenceHash: Uint8Array;
  evidenceVerifierAuthorizationId: Uint8Array;
  evidenceVerifierKeyIdCommitment: Uint8Array;
};

export type LocalMaintainerProposalSigningContext = {
  registryId: Uint8Array;
  networkIdCommitment: Uint8Array;
  contractAddress: Uint8Array;
  maintainerId: Uint8Array;
  policyCommitment: Uint8Array;
  policyVersion: bigint;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  evidenceHash: Uint8Array;
  evidenceVerifierAuthorizationId: Uint8Array;
  evidenceVerifierKeyIdCommitment: Uint8Array;
  requiredThreshold: bigint;
};

const same = (left: Uint8Array, right: Uint8Array): boolean => Buffer.from(left).equals(right);
const bytes32 = (value: Uint8Array, name: string): Uint8Array => {
  if (!(value instanceof Uint8Array) || value.length !== 32 || value.every((byte) => byte === 0)) {
    throw new Error(`${name} must be a nonzero bytes32 commitment`);
  }
  return value;
};

/** Prepares exact signing inputs from an independently authenticated finalized ledger. */
export function prepareUnsignedLocalMaintainerProposalCall(
  input: UnsignedLocalMaintainerProposalCall,
  ledger: Ledger,
): LocalMaintainerProposalSigningContext {
  if (input.networkId !== "undeployed"
    || !/^0x[0-9a-f]{64}$/u.test(input.contractAddress)
    || /^0x0{64}$/u.test(input.contractAddress)
    || input.registryId.length === 0 || input.registryId.includes("\0")
    || input.maintainerLabel.length === 0 || input.maintainerLabel.length > 256
    || input.maintainerLabel.trim() !== input.maintainerLabel
    || input.maintainerLabel.includes("\0")
    || !same(input.maintainerId, bytes32Commitment(input.maintainerLabel))) {
    throw new Error("Local maintainer call has an invalid deployment or identity binding");
  }
  const registryId = bytes32Commitment(input.registryId);
  const networkIdCommitment = bytes32Commitment(input.networkId);
  const contractAddress = Buffer.from(input.contractAddress.slice(2), "hex");
  if (!ledger.initialized || ledger.contractVersion !== 1n
    || !same(ledger.registryId, registryId)
    || !same(ledger.deploymentNetworkIdCommitment, networkIdCommitment)) {
    throw new Error("Finalized maintainer context has an unsupported version, registry, or network");
  }
  for (const [name, value] of Object.entries({
    maintainerId: input.maintainerId,
    maintainerDidCommitment: input.maintainerDidCommitment,
    candidateKeyId: input.candidateKeyId,
    policyId: input.policyId,
    trustLevel: input.trustLevel,
    evidenceHash: input.evidenceHash,
    evidenceVerifierAuthorizationId: input.evidenceVerifierAuthorizationId,
    evidenceVerifierKeyIdCommitment: input.evidenceVerifierKeyIdCommitment,
  })) bytes32(value, name);
  if (!isPrimeOrderJubjubPoint(input.candidatePublicKey)) {
    throw new Error("Candidate maintainer key is not a prime-order Jubjub point");
  }
  if (!same(input.policyId, ledger.governancePolicyCommitment)
    || ledger.maintainerMembershipIds.member(input.maintainerId)
    || ledger.maintainerProposalEvidenceRecords.member(input.maintainerId)
    || ledger.maintainerKeyIds.member(input.candidateKeyId)) {
    throw new Error("Maintainer policy is stale or the candidate identity is already registered");
  }
  const didScope = TrustRegistryContract.pureCircuits.maintainerMembershipScopeKey(input.maintainerDidCommitment);
  const keyScope = TrustRegistryContract.pureCircuits.maintainerMembershipKeyScopeKey(input.candidateKeyId);
  for (const [index, scope] of [
    [ledger.currentMaintainerMembershipIdsByDidCommitment, didScope],
    [ledger.currentMaintainerMembershipIdsByKeyId, keyScope],
  ] as const) {
    if (!index.member(scope)) continue;
    const current = ledger.maintainerMembershipRecords.lookup(index.lookup(scope));
    if (current.status !== AuthorizationStatus.revoked && current.status !== AuthorizationStatus.archived) {
      throw new Error("Maintainer DID or key already has a live membership");
    }
  }
  if (!ledger.evidenceVerifierKeyRecords.member(input.evidenceVerifierAuthorizationId)) {
    throw new Error("Evidence-verifier authorization is absent");
  }
  const evidenceKey = ledger.evidenceVerifierKeyRecords.lookup(input.evidenceVerifierAuthorizationId);
  const verifierScope = TrustRegistryContract.pureCircuits.evidenceVerifierKeyScopeKey(
    evidenceKey.verifierDidCommitment, evidenceKey.policyCommitment,
  );
  const suite = new Uint8Array(32);
  suite.set(new TextEncoder().encode("jubjub-schnorr"));
  if (evidenceKey.status !== EvidenceVerifierKeyStatus.active
    || !same(evidenceKey.authorizationId, input.evidenceVerifierAuthorizationId)
    || !same(evidenceKey.keyIdCommitment, input.evidenceVerifierKeyIdCommitment)
    || !same(evidenceKey.suite, suite)
    || !same(evidenceKey.policyCommitment, ledger.governancePolicyCommitment)
    || evidenceKey.policyVersion !== ledger.governancePolicyVersion
    || !ledger.currentEvidenceVerifierKeyIdsByScopeKey.member(verifierScope)
    || !same(ledger.currentEvidenceVerifierKeyIdsByScopeKey.lookup(verifierScope),
      input.evidenceVerifierAuthorizationId)) {
    throw new Error("Evidence-verifier key is not current for this policy and scope");
  }
  const baseHash = computeCreateMaintainerMembershipPayloadHash(
    input.maintainerId, input.maintainerDidCommitment, input.candidateKeyId,
    input.candidatePublicKey, input.policyId, input.trustLevel, input.evidenceHash,
  );
  const actionKind = encodeCompactActionKind("tr:maintainer:propose");
  return {
    registryId,
    networkIdCommitment,
    contractAddress,
    maintainerId: input.maintainerId,
    policyCommitment: ledger.governancePolicyCommitment,
    policyVersion: ledger.governancePolicyVersion,
    actionKind,
    actionPayloadHash: computeMaintainerEvidenceBoundProposalPayloadHash(
      baseHash, input.evidenceVerifierAuthorizationId, input.evidenceVerifierKeyIdCommitment,
      evidenceKey.policyCommitment, evidenceKey.policyVersion,
    ),
    actionSequence: ledger.governanceActionCount,
    evidenceHash: input.evidenceHash,
    evidenceVerifierAuthorizationId: input.evidenceVerifierAuthorizationId,
    evidenceVerifierKeyIdCommitment: input.evidenceVerifierKeyIdCommitment,
    requiredThreshold: TrustRegistryContract.pureCircuits.actionScopedMaintainerThreshold(
      actionKind, ledger.maintainerThreshold, ledger.emergencyMaintainerThreshold,
      ledger.archivalMaintainerThreshold,
    ),
  };
}
