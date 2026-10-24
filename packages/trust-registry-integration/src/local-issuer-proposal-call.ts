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
  EvidenceVerifierKeyStatus,
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

export type LocalIssuerProposalCallContext = {
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  authorizationBundle: TrustRegistryContract.MaintainerAuthorizationBundle;
};

export type LocalIssuerProposalJournal = {
  executeOnce(
    role: "issuer", authorizationId: string, evidenceCommitment: string,
    execute: () => Promise<{ eventHash: string }>,
  ): Promise<{ eventHash: string }>;
};

const bytes32 = (value: Uint8Array, label: string): Uint8Array => {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error(`${label} must be 32 bytes`);
  }
  return value;
};

const same = (left: Uint8Array, right: Uint8Array): boolean => Buffer.from(left).equals(right);

/** The reader must authenticate finality independently of the submitting SDK provider. */
export function prepareLocalIssuerProposalCall(input: LocalIssuerProposalCall, ledger: Ledger): LocalIssuerProposalCallContext {
  if (input.networkId !== "undeployed" || getNetworkId() !== input.networkId
    || !/^0x[0-9a-f]{64}$/u.test(input.contractAddress)
    || /^0x0{64}$/u.test(input.contractAddress)
    || input.registryId.length === 0 || input.registryId.includes("\0")
    || input.authorizationLabel.length === 0 || input.authorizationLabel.includes("\0")
    || !same(input.authorizationId, bytes32Commitment(input.authorizationLabel))) {
    throw new Error("Local issuer call has an invalid deployment or authorization binding");
  }
  const registryId = bytes32Commitment(input.registryId);
  const networkId = bytes32Commitment(input.networkId);
  const contractAddress = Buffer.from(input.contractAddress.slice(2), "hex");
  if (!ledger.initialized || !same(ledger.registryId, registryId)
    || !same(ledger.deploymentNetworkIdCommitment, networkId)) {
    throw new Error("Finalized issuer call context belongs to a different registry or network");
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
  if (!verifyIssuerProposalEvidenceSignature(
    evidenceKey.publicKey, registryId, input.evidenceVerifierKeyIdCommitment,
    actionPayloadHash, input.evidenceVerifierSignature,
  )) throw new Error("Issuer evidence signature does not bind the current proposal");

  const actionKind = encodeCompactActionKind("tr:issuer:propose");
  const actionSequence = ledger.governanceActionCount;
  if (input.signers.some((signer) => !verifyDeploymentBoundMaintainerAction(
    signer.publicKey, registryId, networkId, contractAddress, ledger.governancePolicyCommitment,
    actionKind, actionPayloadHash, actionSequence, signer.signature,
  ))) throw new Error("Maintainer signature does not bind the current issuer proposal");
  return {
    actionPayloadHash,
    actionSequence,
    authorizationBundle: buildCanonicalMaintainerAuthorizationBundle(input.signers),
  };
}

/** The journal reserves before SDK submission; SDK finalization is not independent readback. */
export async function submitLocalIssuerProposalCall(input: {
  call: LocalIssuerProposalCall;
  readFinalizedLedger: () => Promise<Ledger>;
  providers: ContractProviders<RegistryContract>;
  journal: LocalIssuerProposalJournal;
}): Promise<{ eventHash: string }> {
  const ledger = await input.readFinalizedLedger();
  const prepared = prepareLocalIssuerProposalCall(input.call, ledger);
  return input.journal.executeOnce("issuer", input.call.authorizationLabel,
    `0x${Buffer.from(input.call.evidenceHash).toString("hex")}`, async () => {
      const result = await submitCallTx(input.providers, {
        compiledContract: compiledStagedVerifierKeyContract("proposeIssuerAuthorization"),
        contractAddress: input.call.contractAddress,
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
      return { eventHash: `0x${Buffer.from(eventHash).toString("hex")}` };
    });
}
