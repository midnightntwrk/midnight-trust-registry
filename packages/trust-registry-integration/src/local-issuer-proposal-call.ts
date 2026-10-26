import { Buffer } from "node:buffer";

import { submitCallTx, type ContractProviders } from "@midnight-ntwrk/midnight-js-contracts";
import { getNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import {
  buildCanonicalMaintainerAuthorizationBundle,
  computeCreateIssuerAuthorizationPayloadHash,
  computeIssuerEvidenceBoundProposalPayloadHash,
  encodeCompactActionKind,
  verifyDeploymentBoundMaintainerAction,
  verifyIssuerProposalEvidenceSignature,
  AuthorizationStatus,
  EvidenceVerifierKeyStatus,
  MaintainerStatus,
  TrustRegistryContract,
  type TrustRegistryJubjubSignature,
  type TrustRegistryPrivateState,
} from "@midnight-ntwrk/trust-registry-contract";

import { compiledStagedVerifierKeyContract } from "./public-network-deployment.js";

type RegistryContract = TrustRegistryContract.Contract<TrustRegistryPrivateState>;
type Ledger = TrustRegistryContract.Ledger;
type IssuerResourceType = TrustRegistryContract.IssuerResourceType;
type Signer = TrustRegistryContract.MaintainerAuthorizationSigner;

export type LocalIssuerProposalCall = {
  networkId: "undeployed";
  registryId: string;
  contractAddress: string;
  authorizationLabel: string;
  authorizationId: Uint8Array;
  subjectDidCommitment: Uint8Array;
  resourceType: IssuerResourceType;
  resourceId: Uint8Array;
  policyId: Uint8Array;
  statusPolicyBindingCommitment: Uint8Array;
  trustLevel: Uint8Array;
  evidenceHash: Uint8Array;
  evidenceVerifierAuthorizationId: Uint8Array;
  evidenceVerifierKeyIdCommitment: Uint8Array;
  evidenceVerifierSignature: TrustRegistryJubjubSignature;
  signers: readonly Signer[];
};

export type UnsignedLocalIssuerProposalCall = Omit<LocalIssuerProposalCall,
  "evidenceVerifierSignature" | "signers">;

export type LocalIssuerProposalSigningContext = {
  registryId: Uint8Array;
  networkIdCommitment: Uint8Array;
  contractAddress: Uint8Array;
  authorizationId: Uint8Array;
  policyCommitment: Uint8Array;
  policyVersion: bigint;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  evidenceHash: Uint8Array;
  statusPolicyBindingCommitment: Uint8Array;
  evidenceVerifierAuthorizationId: Uint8Array;
  evidenceVerifierKeyIdCommitment: Uint8Array;
  requiredThreshold: bigint;
};

export type LocalIssuerProposalCallContext = {
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  expectedEventHash: Uint8Array;
  authorizationBundle: TrustRegistryContract.MaintainerAuthorizationBundle;
};

export type LocalIssuerProposalJournal = {
  assertDeploymentBinding(
    registryId: string, contractAddress: string, expectedGenesisHash: string,
  ): Promise<void>;
  executeOnce(
    role: "issuer", authorizationId: string, evidenceCommitment: string,
    execute: () => Promise<{ eventHash: string }>,
    reservationContext: { actionSequence: string; actionKind: string; actionPayloadHash: string },
  ): Promise<{ eventHash: string }>;
};

export type LocalIssuerProposalSubmissionInput = {
  call: LocalIssuerProposalCall;
  expectedGenesisHash: string;
  readFinalizedLedger: (contractAddress: string) => Promise<{
    contractAddress: string; genesisHash: string; ledger: Ledger;
  }>;
  providers: ContractProviders<RegistryContract>;
  /** Must authenticate the node/indexer and submitter transports used by these exact providers. */
  readSubmissionProviderIdentity: (providers: ContractProviders<RegistryContract>) => Promise<{
    contractAddress: string; genesisHash: string;
  }>;
};

const bytes32 = (value: Uint8Array, label: string): Uint8Array => {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error(`${label} must be 32 bytes`);
  }
  return value;
};

const same = (left: Uint8Array, right: Uint8Array): boolean => Buffer.from(left).equals(right);
const isZero = (value: Uint8Array): boolean => value.every((byte) => byte === 0);

const assertPinnedGenesisHash = (value: string): void => {
  if (!/^0x[0-9a-f]{64}$/u.test(value) || /^0x0{64}$/u.test(value)) {
    throw new Error("Local issuer call requires a pinned nonzero genesis hash");
  }
};

/** The caller must authenticate this finalized ledger independently of the submitting SDK provider. */
export function prepareUnsignedLocalIssuerProposalCall(
  input: UnsignedLocalIssuerProposalCall, ledger: Ledger,
): LocalIssuerProposalSigningContext {
  if (input.networkId !== "undeployed" || getNetworkId() !== input.networkId
    || !/^0x[0-9a-f]{64}$/u.test(input.contractAddress)
    || /^0x0{64}$/u.test(input.contractAddress)
    || input.registryId.length === 0 || input.registryId.includes("\0")
    || input.authorizationLabel.length === 0 || input.authorizationLabel.length > 256
    || input.authorizationLabel.trim() !== input.authorizationLabel || input.authorizationLabel.includes("\0")
    || !same(input.authorizationId, bytes32Commitment(input.authorizationLabel))) {
    throw new Error("Local issuer call has an invalid deployment or authorization binding");
  }
  const registryId = bytes32Commitment(input.registryId);
  const networkId = bytes32Commitment(input.networkId);
  const contractAddress = Buffer.from(input.contractAddress.slice(2), "hex");
  if (!ledger.initialized || ledger.contractVersion !== 1n || !same(ledger.registryId, registryId)
    || !same(ledger.deploymentNetworkIdCommitment, networkId)) {
    throw new Error("Finalized issuer call context has an unsupported version, registry, or network");
  }
  for (const [label, value] of Object.entries({
    authorizationId: input.authorizationId,
    subjectDidCommitment: input.subjectDidCommitment,
    resourceId: input.resourceId,
    policyId: input.policyId,
    statusPolicyBindingCommitment: input.statusPolicyBindingCommitment,
    trustLevel: input.trustLevel,
    evidenceHash: input.evidenceHash,
    evidenceVerifierAuthorizationId: input.evidenceVerifierAuthorizationId,
    evidenceVerifierKeyIdCommitment: input.evidenceVerifierKeyIdCommitment,
  })) bytes32(value, label);
  if ([input.authorizationId, input.subjectDidCommitment, input.resourceId, input.policyId,
    input.trustLevel, input.evidenceHash].some(isZero)) {
    throw new Error("Issuer proposal has an unset required field");
  }
  if (!same(input.policyId, ledger.governancePolicyCommitment)
    || !ledger.evidenceVerifierKeyRecords.member(input.evidenceVerifierAuthorizationId)) {
    throw new Error("Issuer policy or evidence-verifier authorization is not current");
  }
  const evidenceKey = ledger.evidenceVerifierKeyRecords.lookup(input.evidenceVerifierAuthorizationId);
  const keyScope = TrustRegistryContract.pureCircuits.evidenceVerifierKeyScopeKey(
    evidenceKey.verifierDidCommitment, evidenceKey.policyCommitment,
  );
  const expectedSuite = new Uint8Array(32);
  expectedSuite.set(new TextEncoder().encode("jubjub-schnorr"));
  if (evidenceKey.status !== EvidenceVerifierKeyStatus.active
    || !same(evidenceKey.authorizationId, input.evidenceVerifierAuthorizationId)
    || !same(evidenceKey.keyIdCommitment, input.evidenceVerifierKeyIdCommitment)
    || !same(evidenceKey.suite, expectedSuite)
    || !same(evidenceKey.policyCommitment, ledger.governancePolicyCommitment)
    || evidenceKey.policyVersion !== ledger.governancePolicyVersion
    || !ledger.currentEvidenceVerifierKeyIdsByScopeKey.member(keyScope)
    || !same(ledger.currentEvidenceVerifierKeyIdsByScopeKey.lookup(keyScope), input.evidenceVerifierAuthorizationId)) {
    throw new Error("Evidence-verifier key is not current for this policy and scope");
  }
  const baseHash = computeCreateIssuerAuthorizationPayloadHash(
    input.authorizationId, input.subjectDidCommitment, input.resourceType, input.resourceId,
    input.policyId, input.statusPolicyBindingCommitment, input.trustLevel, input.evidenceHash,
  );
  const actionPayloadHash = computeIssuerEvidenceBoundProposalPayloadHash(
    baseHash, input.evidenceVerifierAuthorizationId, input.evidenceVerifierKeyIdCommitment,
    evidenceKey.policyCommitment, evidenceKey.policyVersion,
  );
  const actionKind = encodeCompactActionKind("tr:issuer:propose");
  const requiredThreshold = TrustRegistryContract.pureCircuits.actionScopedMaintainerThreshold(
    actionKind, ledger.maintainerThreshold, ledger.emergencyMaintainerThreshold,
    ledger.archivalMaintainerThreshold,
  );
  if (ledger.issuerAuthorizationIds.member(input.authorizationId)
    || ledger.issuerProposalEvidenceRecords.member(input.authorizationId)) {
    throw new Error("Issuer proposal authorization already exists");
  }
  const scopeKey = TrustRegistryContract.pureCircuits.issuerAuthorizationScopeKey(
    input.subjectDidCommitment, input.resourceType, input.resourceId,
  );
  if (ledger.currentIssuerAuthorizationIdsByScopeKey.member(scopeKey)) {
    const currentId = ledger.currentIssuerAuthorizationIdsByScopeKey.lookup(scopeKey);
    const current = ledger.issuerAuthorizationRecords.lookup(currentId);
    if (current.status !== AuthorizationStatus.revoked && current.status !== AuthorizationStatus.archived) {
      throw new Error("Issuer authorization scope already has a live authorization");
    }
  }
  const actionSequence = ledger.governanceActionCount;
  return {
    registryId,
    networkIdCommitment: networkId,
    contractAddress,
    authorizationId: input.authorizationId,
    policyCommitment: ledger.governancePolicyCommitment,
    policyVersion: ledger.governancePolicyVersion,
    actionKind,
    actionPayloadHash,
    actionSequence,
    evidenceHash: input.evidenceHash,
    statusPolicyBindingCommitment: input.statusPolicyBindingCommitment,
    evidenceVerifierAuthorizationId: input.evidenceVerifierAuthorizationId,
    evidenceVerifierKeyIdCommitment: input.evidenceVerifierKeyIdCommitment,
    requiredThreshold,
  };
}

/** The reader must authenticate finality independently of the submitting SDK provider. */
export function prepareLocalIssuerProposalCall(input: LocalIssuerProposalCall, ledger: Ledger): LocalIssuerProposalCallContext {
  const prepared = prepareUnsignedLocalIssuerProposalCall(input, ledger);
  const evidenceKey = ledger.evidenceVerifierKeyRecords.lookup(input.evidenceVerifierAuthorizationId);
  if (!verifyIssuerProposalEvidenceSignature(
    evidenceKey.publicKey, prepared.registryId, prepared.networkIdCommitment, prepared.contractAddress,
    input.evidenceVerifierKeyIdCommitment,
    prepared.actionPayloadHash, input.evidenceVerifierSignature,
  )) throw new Error("Issuer evidence signature does not bind the current proposal");
  if (BigInt(input.signers.length) < prepared.requiredThreshold || input.signers.length > 5) {
    throw new Error("Maintainer signer count does not satisfy the issuer action threshold");
  }
  for (const signer of input.signers) {
    if (isZero(bytes32(signer.keyId, "Maintainer key id")) || !ledger.maintainerKeyIds.member(signer.keyId)) {
      throw new Error("Maintainer signer key is not registered");
    }
    const maintainer = ledger.maintainerRecords.lookup(signer.keyId);
    if (maintainer.status !== MaintainerStatus.active
      || !same(maintainer.keyId, signer.keyId)
      || maintainer.publicKey.x !== signer.publicKey.x
      || maintainer.publicKey.y !== signer.publicKey.y) {
      throw new Error("Maintainer signer is not current and active");
    }
  }
  if (input.signers.some((signer) => !verifyDeploymentBoundMaintainerAction(
    signer.publicKey, prepared.registryId, prepared.networkIdCommitment, prepared.contractAddress,
    prepared.policyCommitment, prepared.actionKind, prepared.actionPayloadHash,
    prepared.actionSequence, signer.signature,
  ))) throw new Error("Maintainer signature does not bind the current issuer proposal");
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
      prepared.policyCommitment, signerSetHash, prepared.actionKind, prepared.actionPayloadHash,
      prepared.actionSequence,
    ),
    authorizationBundle,
  };
}

/** No transaction or journal mutation occurs during this preflight. */
export async function preflightLocalIssuerProposalSubmission(input: LocalIssuerProposalSubmissionInput): Promise<{
  prepared: LocalIssuerProposalCallContext;
  compiledContract: ReturnType<typeof compiledStagedVerifierKeyContract>;
}> {
  assertPinnedGenesisHash(input.expectedGenesisHash);
  const finalized = await input.readFinalizedLedger(input.call.contractAddress);
  if (finalized.contractAddress !== input.call.contractAddress) {
    throw new Error("Finalized issuer ledger read belongs to a different contract address");
  }
  if (finalized.genesisHash !== input.expectedGenesisHash) {
    throw new Error("Finalized issuer ledger read belongs to a different genesis");
  }
  const providerIdentity = await input.readSubmissionProviderIdentity(input.providers);
  if (providerIdentity.contractAddress !== input.call.contractAddress
    || providerIdentity.genesisHash !== input.expectedGenesisHash) {
    throw new Error("Issuer submission providers do not match the pinned deployment");
  }
  const prepared = prepareLocalIssuerProposalCall(input.call, finalized.ledger);
  const compiledContract = compiledStagedVerifierKeyContract("proposeIssuerAuthorization");
  return { prepared, compiledContract };
}

const submitPreparedLocalIssuerProposal = async (
  input: LocalIssuerProposalSubmissionInput,
  prepared: LocalIssuerProposalCallContext,
  compiledContract: ReturnType<typeof compiledStagedVerifierKeyContract>,
): Promise<{ eventHash: string }> => {
  const result = await submitCallTx(input.providers, {
    compiledContract,
    contractAddress: input.call.contractAddress.slice(2),
    privateStateId: "trustRegistryPrivateState",
    circuitId: "proposeIssuerAuthorization",
    args: [
      prepared.authorizationBundle,
      input.call.authorizationId,
      input.call.subjectDidCommitment,
      input.call.resourceType,
      input.call.resourceId,
      input.call.policyId,
      input.call.statusPolicyBindingCommitment,
      input.call.trustLevel,
      input.call.evidenceHash,
      input.call.evidenceVerifierAuthorizationId,
      input.call.evidenceVerifierKeyIdCommitment,
      input.call.evidenceVerifierSignature,
    ],
  });
  const eventHash = bytes32(result.private.result, "Finalized issuer proposal event hash");
  if (!result.public.txId) throw new Error("Finalized issuer proposal lacks a transaction ID");
  if (!same(eventHash, prepared.expectedEventHash)) {
    throw new Error("Submitted issuer proposal event hash differs from the prepared action");
  }
  return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
};

/** The caller must already own a durable reservation; this function never retries an ambiguous submit. */
export async function executeLocalIssuerProposalAfterReservation(
  input: LocalIssuerProposalSubmissionInput,
): Promise<{ eventHash: string }> {
  const { prepared, compiledContract } = await preflightLocalIssuerProposalSubmission(input);
  return submitPreparedLocalIssuerProposal(input, prepared, compiledContract);
}

/** The journal reserves before SDK submission; SDK finalization is not independent readback. */
export async function submitLocalIssuerProposalCall(
  input: LocalIssuerProposalSubmissionInput & { journal: LocalIssuerProposalJournal },
): Promise<{ eventHash: string }> {
  assertPinnedGenesisHash(input.expectedGenesisHash);
  await input.journal.assertDeploymentBinding(
    input.call.registryId, input.call.contractAddress, input.expectedGenesisHash,
  );
  const { prepared, compiledContract } = await preflightLocalIssuerProposalSubmission(input);
  return input.journal.executeOnce("issuer", input.call.authorizationLabel,
    `0x${Buffer.from(input.call.evidenceHash).toString("hex")}`,
    () => submitPreparedLocalIssuerProposal(input, prepared, compiledContract), {
      actionSequence: prepared.actionSequence.toString(),
      actionKind: `0x${Buffer.from(prepared.actionKind).toString("hex")}`,
      actionPayloadHash: `0x${Buffer.from(prepared.actionPayloadHash).toString("hex")}`,
    });
}
