import { Buffer } from "node:buffer";

import { submitCallTx, type ContractProviders } from "@midnight-ntwrk/midnight-js-contracts";
import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import {
  AuthorizationStatus,
  buildCanonicalMaintainerAuthorizationBundle,
  computeCreateMaintainerMembershipPayloadHash,
  computeMaintainerEvidenceBoundProposalPayloadHash,
  encodeCompactActionKind,
  EvidenceVerifierKeyStatus,
  isPrimeOrderJubjubPoint,
  MaintainerStatus,
  TrustRegistryContract,
  verifyDeploymentBoundMaintainerAction,
  verifyMaintainerProposalEvidenceSignature,
  type TrustRegistryJubjubSignature,
  type TrustRegistryPrivateState,
} from "@midnight-ntwrk/trust-registry-contract";

import { compiledStagedVerifierKeyContract } from "./public-network-deployment.js";

type Ledger = TrustRegistryContract.Ledger;
type PublicKey = Parameters<typeof computeCreateMaintainerMembershipPayloadHash>[3];
type Signer = TrustRegistryContract.MaintainerAuthorizationSigner;
type RegistryContract = TrustRegistryContract.Contract<TrustRegistryPrivateState>;

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

export type LocalMaintainerProposalCall = UnsignedLocalMaintainerProposalCall & {
  evidenceVerifierSignature: TrustRegistryJubjubSignature;
  signers: readonly Signer[];
};

export type LocalMaintainerProposalCallContext = {
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  expectedEventHash: Uint8Array;
  authorizationBundle: TrustRegistryContract.MaintainerAuthorizationBundle;
};

function assertSameReservedAction(
  reserved: LocalMaintainerProposalCallContext,
  current: LocalMaintainerProposalCallContext,
): void {
  if (reserved.actionSequence !== current.actionSequence
    || !same(reserved.actionKind, current.actionKind)
    || !same(reserved.actionPayloadHash, current.actionPayloadHash)
    || !same(reserved.expectedEventHash, current.expectedEventHash)) {
    throw new Error("Finalized maintainer action changed after reservation");
  }
}

export type LocalMaintainerProposalSubmissionInput = {
  call: LocalMaintainerProposalCall;
  expectedGenesisHash: string;
  readFinalizedLedger: (contractAddress: string) => Promise<{
    contractAddress: string; genesisHash: string; ledger: Ledger;
  }>;
  providers: ContractProviders<RegistryContract>;
  readSubmissionProviderIdentity: (providers: ContractProviders<RegistryContract>) => Promise<{
    contractAddress: string; genesisHash: string;
  }>;
};

export type LocalMaintainerProposalJournal = {
  assertDeploymentBinding(registryId: string, contractAddress: string, expectedGenesisHash: string): Promise<void>;
  executeOnce(
    role: "maintainer", authorizationId: string, evidenceCommitment: string,
    execute: () => Promise<{ eventHash: string }>,
    reservationContext: { actionSequence: string; actionKind: string; actionPayloadHash: string },
  ): Promise<{ eventHash: string }>;
};

const same = (left: Uint8Array, right: Uint8Array): boolean => Buffer.from(left).equals(right);
const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;
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
  for (const keyId of ledger.maintainerKeyIds) {
    const existing = ledger.maintainerRecords.lookup(keyId);
    if (existing.publicKey.x === input.candidatePublicKey.x
      && existing.publicKey.y === input.candidatePublicKey.y) {
      throw new Error("Candidate maintainer public key is already registered");
    }
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

/** Verifies the candidate evidence and the distinct, current maintainer quorum before proving. */
export function prepareLocalMaintainerProposalCall(
  input: LocalMaintainerProposalCall,
  ledger: Ledger,
): LocalMaintainerProposalCallContext {
  const prepared = prepareUnsignedLocalMaintainerProposalCall(input, ledger);
  const evidenceKey = ledger.evidenceVerifierKeyRecords.lookup(input.evidenceVerifierAuthorizationId);
  if (!verifyMaintainerProposalEvidenceSignature(
    evidenceKey.publicKey, prepared.registryId, prepared.networkIdCommitment, prepared.contractAddress,
    input.evidenceVerifierKeyIdCommitment, prepared.actionPayloadHash, input.evidenceVerifierSignature,
  )) throw new Error("Maintainer evidence signature does not bind the current proposal");
  if (BigInt(input.signers.length) < prepared.requiredThreshold || input.signers.length > 5) {
    throw new Error("Maintainer signer count does not satisfy the action threshold");
  }
  for (const signer of input.signers) {
    bytes32(signer.keyId, "Maintainer signer key id");
    if (!ledger.maintainerKeyIds.member(signer.keyId)) {
      throw new Error("Maintainer signer key is not registered");
    }
    const current = ledger.maintainerRecords.lookup(signer.keyId);
    if (current.status !== MaintainerStatus.active || !same(current.keyId, signer.keyId)
      || current.publicKey.x !== signer.publicKey.x || current.publicKey.y !== signer.publicKey.y) {
      throw new Error("Maintainer signer is not current and active");
    }
    if (!verifyDeploymentBoundMaintainerAction(
      signer.publicKey, prepared.registryId, prepared.networkIdCommitment, prepared.contractAddress,
      prepared.policyCommitment, prepared.actionKind, prepared.actionPayloadHash,
      prepared.actionSequence, signer.signature,
    )) throw new Error("Maintainer signature does not bind the current proposal");
  }
  for (let index = 0; index < input.signers.length; index += 1) {
    for (let previous = 0; previous < index; previous += 1) {
      const left = input.signers[previous]!.publicKey;
      const right = input.signers[index]!.publicKey;
      if (left.x === right.x && left.y === right.y) {
        throw new Error("Maintainer signer public keys must be distinct");
      }
    }
  }
  const authorizationBundle = buildCanonicalMaintainerAuthorizationBundle(input.signers);
  const signerSetHash = TrustRegistryContract.pureCircuits.maintainerSignerSetHash(
    authorizationBundle.signerCount, authorizationBundle.signer1.keyId,
    authorizationBundle.signer2.keyId, authorizationBundle.signer3.keyId,
    authorizationBundle.signer4.keyId, authorizationBundle.signer5.keyId,
  );
  return {
    actionKind: prepared.actionKind,
    actionPayloadHash: prepared.actionPayloadHash,
    actionSequence: prepared.actionSequence,
    expectedEventHash: TrustRegistryContract.pureCircuits.governanceEventHash(
      prepared.registryId, prepared.networkIdCommitment, prepared.contractAddress,
      prepared.policyCommitment, signerSetHash, prepared.actionKind,
      prepared.actionPayloadHash, prepared.actionSequence,
    ),
    authorizationBundle,
  };
}

/** The finalized reader and submitting providers must independently agree on the pinned deployment. */
export async function preflightLocalMaintainerProposalSubmission(
  input: LocalMaintainerProposalSubmissionInput,
): Promise<{
  prepared: LocalMaintainerProposalCallContext;
  compiledContract: ReturnType<typeof compiledStagedVerifierKeyContract>;
}> {
  if (!/^0x[0-9a-f]{64}$/u.test(input.expectedGenesisHash)
    || /^0x0{64}$/u.test(input.expectedGenesisHash)) {
    throw new Error("Local maintainer call requires a pinned nonzero genesis hash");
  }
  const finalized = await input.readFinalizedLedger(input.call.contractAddress);
  if (finalized.contractAddress !== input.call.contractAddress
    || finalized.genesisHash !== input.expectedGenesisHash) {
    throw new Error("Finalized maintainer ledger read differs from the pinned deployment");
  }
  const providerIdentity = await input.readSubmissionProviderIdentity(input.providers);
  if (providerIdentity.contractAddress !== input.call.contractAddress
    || providerIdentity.genesisHash !== input.expectedGenesisHash) {
    throw new Error("Maintainer submission providers differ from the pinned deployment");
  }
  return {
    prepared: prepareLocalMaintainerProposalCall(input.call, finalized.ledger),
    compiledContract: compiledStagedVerifierKeyContract("proposeMaintainerMembership"),
  };
}

/** A caller must reserve durably before invoking this function; an ambiguous result is never retried. */
export async function executeLocalMaintainerProposalAfterReservation(
  input: LocalMaintainerProposalSubmissionInput,
  reserved: LocalMaintainerProposalCallContext,
  assertReadyBeforeBroadcast: () => Promise<void>,
): Promise<{ eventHash: string }> {
  const { prepared, compiledContract } = await preflightLocalMaintainerProposalSubmission(input);
  assertSameReservedAction(reserved, prepared);
  const guardedProvider = input.providers.midnightProvider as (typeof input.providers.midnightProvider & {
    submitTxWithBroadcastGuard?: (
      tx: Parameters<typeof input.providers.midnightProvider.submitTx>[0], guard: () => Promise<void>,
    ) => ReturnType<typeof input.providers.midnightProvider.submitTx>;
  }) | undefined;
  if (!guardedProvider || typeof guardedProvider.submitTxWithBroadcastGuard !== "function") {
    throw new Error("Maintainer submission requires a pinned provider with a transport broadcast guard");
  }
  const providers = {
    ...input.providers,
    midnightProvider: {
      supportedEras: guardedProvider.supportedEras,
      submitTx: async (tx: Parameters<typeof input.providers.midnightProvider.submitTx>[0]) =>
        guardedProvider.submitTxWithBroadcastGuard!(tx, assertReadyBeforeBroadcast),
    },
  };
  const result = await submitCallTx(providers, {
    compiledContract,
    contractAddress: input.call.contractAddress.slice(2),
    privateStateId: "trustRegistryPrivateState",
    circuitId: "proposeMaintainerMembership",
    args: [
      prepared.authorizationBundle,
      input.call.maintainerId,
      input.call.maintainerDidCommitment,
      input.call.candidateKeyId,
      input.call.candidatePublicKey,
      input.call.policyId,
      input.call.trustLevel,
      input.call.evidenceHash,
      input.call.evidenceVerifierAuthorizationId,
      input.call.evidenceVerifierKeyIdCommitment,
      input.call.evidenceVerifierSignature,
    ],
  });
  const eventHash = result.private.result;
  if (!result.public.txId || !(eventHash instanceof Uint8Array) || eventHash.length !== 32
    || !same(eventHash, prepared.expectedEventHash)) {
    throw new Error("Submitted maintainer proposal differs from the prepared action");
  }
  return { eventHash: hex(eventHash) };
}

/** The journal reserves before SDK submission; SDK finalization is not independent readback. */
export async function submitLocalMaintainerProposalCall(
  input: LocalMaintainerProposalSubmissionInput & { journal: LocalMaintainerProposalJournal },
): Promise<{ eventHash: string }> {
  if (!/^0x[0-9a-f]{64}$/u.test(input.expectedGenesisHash)
    || /^0x0{64}$/u.test(input.expectedGenesisHash)) {
    throw new Error("Local maintainer call requires a pinned nonzero genesis hash");
  }
  if (typeof (input.providers.midnightProvider as { submitTxWithBroadcastGuard?: unknown } | undefined)
    ?.submitTxWithBroadcastGuard !== "function") {
    throw new Error("Maintainer submission requires a pinned provider with a transport broadcast guard");
  }
  await input.journal.assertDeploymentBinding(
    input.call.registryId, input.call.contractAddress, input.expectedGenesisHash,
  );
  const { prepared } = await preflightLocalMaintainerProposalSubmission(input);
  return input.journal.executeOnce("maintainer", input.call.maintainerLabel,
    hex(input.call.evidenceHash),
    () => executeLocalMaintainerProposalAfterReservation(input, prepared, async () => {
      await input.journal.assertDeploymentBinding(
        input.call.registryId, input.call.contractAddress, input.expectedGenesisHash,
      );
      const current = await preflightLocalMaintainerProposalSubmission(input);
      assertSameReservedAction(prepared, current.prepared);
    }), {
      actionSequence: prepared.actionSequence.toString(),
      actionKind: hex(prepared.actionKind),
      actionPayloadHash: hex(prepared.actionPayloadHash),
    });
}
