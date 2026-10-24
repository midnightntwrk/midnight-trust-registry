import { Buffer } from "node:buffer";

import { beforeEach, describe, expect, it, vi } from "vitest";

import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import {
  computeCreateIssuerAuthorizationPayloadHash,
  computeIssuerEvidenceBoundProposalPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
  EvidenceVerifierKeyStatus,
  signDeploymentBoundMaintainerActionFromSeed,
  signIssuerProposalEvidenceFromSeed,
  AuthorizationStatus,
  MaintainerStatus,
  TrustRegistryContract,
} from "@midnight-ntwrk/trust-registry-contract";

import {
  prepareLocalIssuerProposalCall,
  submitLocalIssuerProposalCall,
  type LocalIssuerProposalCall,
} from "../local-issuer-proposal-call.js";

const mocks = vi.hoisted(() => ({ submitCallTx: vi.fn(), compiledContract: { circuit: "issuer" } }));
vi.mock("@midnight-ntwrk/midnight-js-contracts", async (importOriginal) => ({
  ...await importOriginal<typeof import("@midnight-ntwrk/midnight-js-contracts")>(),
  submitCallTx: mocks.submitCallTx,
}));
vi.mock("../public-network-deployment.js", async (importOriginal) => ({
  ...await importOriginal<typeof import("../public-network-deployment.js")>(),
  compiledStagedVerifierKeyContract: vi.fn(() => mocks.compiledContract),
}));

const registryLabel = "registry:local-issuer-call";
const authorizationLabel = "issuer:local-issuer-call";
const contractAddress = `0x${"a".repeat(64)}`;
const genesisHash = `0x${"d".repeat(64)}`;
const maintainerSeed = new Uint8Array(32).fill(13);
const verifierSeed = new Uint8Array(32).fill(19);
const keyId = bytes32Commitment("maintainer:key-1");
const verifierAuthorizationId = bytes32Commitment("evidence-verifier:local-issuer-call");
const verifierKeyId = bytes32Commitment("evidence-verifier:key-1");
const policy = bytes32Commitment("policy:local-issuer-call");
const signerPublicKey = deriveJubjubPublicKeyFromSeed(maintainerSeed);
const verifierPublicKey = deriveJubjubPublicKeyFromSeed(verifierSeed);

const fixture = (): { call: LocalIssuerProposalCall; ledger: TrustRegistryContract.Ledger } => {
  const authorizationId = bytes32Commitment(authorizationLabel);
  const subjectDidCommitment = bytes32Commitment("did:midnight:undeployed:issuer");
  const resourceId = bytes32Commitment("credential-family:local-call");
  const statusPolicyBindingCommitment = bytes32Commitment("status:local-call");
  const trustLevel = bytes32Commitment("trust-level:local-call");
  const evidenceHash = bytes32Commitment("accepted-vp:local-call");
  const resourceType = TrustRegistryContract.IssuerResourceType.credentialFamily;
  const baseHash = computeCreateIssuerAuthorizationPayloadHash(
    authorizationId, subjectDidCommitment, resourceType, resourceId, policy,
    statusPolicyBindingCommitment, trustLevel, evidenceHash,
  );
  const actionPayloadHash = computeIssuerEvidenceBoundProposalPayloadHash(
    baseHash, verifierAuthorizationId, verifierKeyId, policy, 1n,
  );
  const registryId = bytes32Commitment(registryLabel);
  const networkIdCommitment = bytes32Commitment("undeployed");
  const addressBytes = Buffer.from(contractAddress.slice(2), "hex");
  const suite = new Uint8Array(32);
  suite.set(new TextEncoder().encode("jubjub-schnorr"));
  const keyRecord = {
    authorizationId: verifierAuthorizationId, keyIdCommitment: verifierKeyId,
    verifierDidCommitment: bytes32Commitment("did:midnight:undeployed:evidence-verifier"),
    publicKey: verifierPublicKey, status: EvidenceVerifierKeyStatus.active,
    suite,
    policyCommitment: policy, policyVersion: 1n,
  };
  const keyScope = TrustRegistryContract.pureCircuits.evidenceVerifierKeyScopeKey(
    keyRecord.verifierDidCommitment, keyRecord.policyCommitment,
  );
  const ledger = {
    initialized: true, contractVersion: 1n, registryId, deploymentNetworkIdCommitment: networkIdCommitment,
    governancePolicyCommitment: policy, governancePolicyVersion: 1n, governanceActionCount: 3n,
    maintainerThreshold: 1n, emergencyMaintainerThreshold: 1n, archivalMaintainerThreshold: 1n,
    maintainerKeyIds: { member: (id: Uint8Array) => Buffer.from(id).equals(Buffer.from(keyId)) },
    maintainerRecords: { lookup: () => ({ keyId, publicKey: signerPublicKey, status: MaintainerStatus.active }) },
    issuerAuthorizationIds: { member: () => false },
    issuerProposalEvidenceRecords: { member: () => false },
    currentIssuerAuthorizationIdsByScopeKey: { member: () => false },
    evidenceVerifierKeyRecords: {
      member: (id: Uint8Array) => Buffer.from(id).equals(Buffer.from(verifierAuthorizationId)),
      lookup: () => keyRecord,
    },
    currentEvidenceVerifierKeyIdsByScopeKey: {
      member: (scope: Uint8Array) => Buffer.from(scope).equals(Buffer.from(keyScope)),
      lookup: () => verifierAuthorizationId,
    },
  } as unknown as TrustRegistryContract.Ledger;
  const call: LocalIssuerProposalCall = {
    networkId: "undeployed", registryId: registryLabel, contractAddress,
    authorizationLabel, authorizationId, subjectDidCommitment, resourceType, resourceId,
    policyId: policy, statusPolicyBindingCommitment, trustLevel, evidenceHash,
    evidenceVerifierAuthorizationId: verifierAuthorizationId,
    evidenceVerifierKeyIdCommitment: verifierKeyId,
    evidenceVerifierSignature: signIssuerProposalEvidenceFromSeed(
      verifierSeed, registryId, verifierKeyId, actionPayloadHash,
    ),
    signers: [{
      keyId, publicKey: signerPublicKey,
      signature: signDeploymentBoundMaintainerActionFromSeed(
        maintainerSeed, registryId, networkIdCommitment, addressBytes, policy,
        encodeCompactActionKind("tr:issuer:propose"), actionPayloadHash, 3n,
      ),
    }],
  };
  return { call, ledger };
};

beforeEach(() => {
  setNetworkId("undeployed");
  vi.clearAllMocks();
});

describe("local issuer proposal circuit call", () => {
  it("preflights the finalized context and submits through a reservation", async () => {
    const { call, ledger } = fixture();
    const prepared = prepareLocalIssuerProposalCall(call, ledger);
    expect(prepared.actionSequence).toBe(3n);
    expect(prepared.authorizationBundle.signerCount).toBe(1n);
    mocks.submitCallTx.mockResolvedValueOnce({
      private: { result: prepared.expectedEventHash },
      public: { txId: "tx-local-issuer" },
    });
    const journal = { assertDeploymentBinding: vi.fn(async () => {}), executeOnce: vi.fn(async (
      role: "issuer", id: string, commitment: string, execute: () => Promise<{ eventHash: string }>,
    ) => {
      expect([role, id, commitment]).toEqual([
        "issuer", authorizationLabel, `0x${Buffer.from(call.evidenceHash).toString("hex")}`,
      ]);
      expect(mocks.submitCallTx).not.toHaveBeenCalled();
      return execute();
    }) };
    await expect(submitLocalIssuerProposalCall({
      call, expectedGenesisHash: genesisHash,
      readFinalizedLedger: async (address) => ({ contractAddress: address, genesisHash, ledger }),
      providers: {} as Parameters<typeof submitLocalIssuerProposalCall>[0]["providers"], journal,
    })).resolves.toEqual({ eventHash: `0x${Buffer.from(prepared.expectedEventHash).toString("hex")}` });
    expect(journal.executeOnce).toHaveBeenCalledOnce();
    expect(journal.assertDeploymentBinding).toHaveBeenCalledWith(registryLabel, contractAddress, genesisHash);
    expect(mocks.submitCallTx).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      contractAddress: contractAddress.slice(2), privateStateId: "trustRegistryPrivateState", circuitId: "proposeIssuerAuthorization",
      args: [prepared.authorizationBundle, call.authorizationId, call.subjectDidCommitment,
        call.resourceType, call.resourceId, call.policyId, call.statusPolicyBindingCommitment,
        call.trustLevel, call.evidenceHash, call.evidenceVerifierAuthorizationId,
        call.evidenceVerifierKeyIdCommitment, call.evidenceVerifierSignature],
    }));
  });

  it("rejects stale governance, substituted evidence, and mismatched IDs before reservation", () => {
    const { call, ledger } = fixture();
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, governanceActionCount: 4n,
    })).toThrow(/Maintainer signature/u);
    expect(() => prepareLocalIssuerProposalCall({
      ...call, evidenceHash: bytes32Commitment("substituted-vp"),
    }, ledger)).toThrow(/Issuer evidence signature/u);
    expect(() => prepareLocalIssuerProposalCall({
      ...call, authorizationLabel: "different-authorization",
    }, ledger)).toThrow(/authorization binding/u);
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, registryId: bytes32Commitment("another-registry"),
    })).toThrow(/registry/u);
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, contractVersion: 2n,
    })).toThrow(/unsupported version/u);
    expect(mocks.submitCallTx).not.toHaveBeenCalled();
  });

  it("rejects inactive verifier keys and duplicate maintainer keys", () => {
    const { call, ledger } = fixture();
    const key = ledger.evidenceVerifierKeyRecords.lookup(call.evidenceVerifierAuthorizationId);
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, evidenceVerifierKeyRecords: {
        ...ledger.evidenceVerifierKeyRecords,
        lookup: () => ({ ...key, status: EvidenceVerifierKeyStatus.suspended }),
      },
    })).toThrow(/not current/u);
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, currentEvidenceVerifierKeyIdsByScopeKey: {
        ...ledger.currentEvidenceVerifierKeyIdsByScopeKey,
        lookup: () => bytes32Commitment("another-key"),
      },
    })).toThrow(/not current/u);
    expect(() => prepareLocalIssuerProposalCall({
      ...call, signers: [call.signers[0]!, call.signers[0]!],
    }, ledger)).toThrow(/duplicate key ID/u);
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, governancePolicyVersion: 2n,
    })).toThrow(/not current/u);
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, evidenceVerifierKeyRecords: {
        ...ledger.evidenceVerifierKeyRecords,
        lookup: () => ({ ...key, suite: new Uint8Array(32) }),
      },
    })).toThrow(/not current/u);
  });

  it("rejects journal-ambiguous labels and predictable Compact failures before reservation", () => {
    const { call, ledger } = fixture();
    for (const authorizationLabel of [` ${call.authorizationLabel}`, `${call.authorizationLabel} `,
      "a".repeat(257)]) {
      expect(() => prepareLocalIssuerProposalCall({ ...call, authorizationLabel }, ledger))
        .toThrow(/authorization binding/u);
    }
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, maintainerThreshold: 2n,
    })).toThrow(/threshold/u);
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, maintainerKeyIds: { member: () => false } as unknown as typeof ledger.maintainerKeyIds,
    })).toThrow(/not registered/u);
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, maintainerRecords: {
        lookup: () => ({ keyId, publicKey: signerPublicKey, status: MaintainerStatus.suspended }),
      } as unknown as typeof ledger.maintainerRecords,
    })).toThrow(/not current and active/u);
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, issuerAuthorizationIds: { member: () => true } as unknown as typeof ledger.issuerAuthorizationIds,
    })).toThrow(/already exists/u);
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, issuerProposalEvidenceRecords: { member: () => true } as unknown as typeof ledger.issuerProposalEvidenceRecords,
    })).toThrow(/already exists/u);
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, currentIssuerAuthorizationIdsByScopeKey: {
        member: () => true, lookup: () => bytes32Commitment("existing-issuer"),
      } as unknown as typeof ledger.currentIssuerAuthorizationIdsByScopeKey,
      issuerAuthorizationRecords: {
        lookup: () => ({ status: AuthorizationStatus.active }),
      } as unknown as typeof ledger.issuerAuthorizationRecords,
    })).toThrow(/live authorization/u);
    expect(() => prepareLocalIssuerProposalCall(call, {
      ...ledger, currentIssuerAuthorizationIdsByScopeKey: {
        member: () => true, lookup: () => bytes32Commitment("existing-issuer"),
      } as unknown as typeof ledger.currentIssuerAuthorizationIdsByScopeKey,
      issuerAuthorizationRecords: {
        lookup: () => ({ status: AuthorizationStatus.revoked }),
      } as unknown as typeof ledger.issuerAuthorizationRecords,
    })).not.toThrow();
    expect(mocks.submitCallTx).not.toHaveBeenCalled();
  });

  it("requires the finalized reader to bind its ledger to the requested contract", async () => {
    const { call, ledger } = fixture();
    const journal = { assertDeploymentBinding: vi.fn(async () => {}), executeOnce: vi.fn() };
    const readFinalizedLedger = vi.fn(async () => ({
      contractAddress: `0x${"b".repeat(64)}`, genesisHash, ledger,
    }));
    await expect(submitLocalIssuerProposalCall({
      call, expectedGenesisHash: genesisHash, readFinalizedLedger,
      providers: {} as Parameters<typeof submitLocalIssuerProposalCall>[0]["providers"], journal,
    })).rejects.toThrow(/different contract address/u);
    expect(readFinalizedLedger).toHaveBeenCalledWith(contractAddress);
    expect(journal.executeOnce).not.toHaveBeenCalled();
  });

  it("rejects an unbound journal or wrong genesis before reserving or submitting", async () => {
    const { call, ledger } = fixture();
    let rejectBinding = true;
    const journal = {
      assertDeploymentBinding: vi.fn(async () => {
        if (rejectBinding) throw new Error("journal bound to another deployment");
      }),
      executeOnce: vi.fn(),
    };
    const readFinalizedLedger = vi.fn(async (address: string) => ({ contractAddress: address, genesisHash, ledger }));
    await expect(submitLocalIssuerProposalCall({
      call, expectedGenesisHash: genesisHash, readFinalizedLedger,
      providers: {} as Parameters<typeof submitLocalIssuerProposalCall>[0]["providers"], journal,
    })).rejects.toThrow(/another deployment/u);
    expect(readFinalizedLedger).not.toHaveBeenCalled();
    expect(journal.executeOnce).not.toHaveBeenCalled();
    rejectBinding = false;
    readFinalizedLedger.mockResolvedValueOnce({
      contractAddress, genesisHash: `0x${"e".repeat(64)}`, ledger,
    });
    await expect(submitLocalIssuerProposalCall({
      call, expectedGenesisHash: genesisHash, readFinalizedLedger,
      providers: {} as Parameters<typeof submitLocalIssuerProposalCall>[0]["providers"], journal,
    })).rejects.toThrow(/different genesis/u);
    expect(journal.executeOnce).not.toHaveBeenCalled();
    expect(mocks.submitCallTx).not.toHaveBeenCalled();
  });

  it("requires a nonzero pinned genesis hash before journal or provider access", async () => {
    const { call, ledger } = fixture();
    const journal = { assertDeploymentBinding: vi.fn(), executeOnce: vi.fn() };
    const readFinalizedLedger = vi.fn(async (address: string) => ({ contractAddress: address, genesisHash, ledger }));
    await expect(submitLocalIssuerProposalCall({
      call, expectedGenesisHash: `0x${"0".repeat(64)}`, readFinalizedLedger,
      providers: {} as Parameters<typeof submitLocalIssuerProposalCall>[0]["providers"], journal,
    })).rejects.toThrow(/pinned nonzero genesis/u);
    expect(journal.assertDeploymentBinding).not.toHaveBeenCalled();
    expect(readFinalizedLedger).not.toHaveBeenCalled();
  });

  it("does not reserve when finalized governance cannot satisfy the signer threshold", async () => {
    const { call, ledger } = fixture();
    const journal = { assertDeploymentBinding: vi.fn(async () => {}), executeOnce: vi.fn() };
    await expect(submitLocalIssuerProposalCall({
      call, expectedGenesisHash: genesisHash, readFinalizedLedger: async (address) => ({
        contractAddress: address, genesisHash, ledger: { ...ledger, maintainerThreshold: 2n },
      }),
      providers: {} as Parameters<typeof submitLocalIssuerProposalCall>[0]["providers"], journal,
    })).rejects.toThrow(/threshold/u);
    expect(journal.executeOnce).not.toHaveBeenCalled();
    expect(mocks.submitCallTx).not.toHaveBeenCalled();
  });

  it("treats a provider-returned event hash mismatch as an uncertain journaled outcome", async () => {
    const { call, ledger } = fixture();
    mocks.submitCallTx.mockResolvedValueOnce({
      private: { result: bytes32Commitment("different-governance-event") },
      public: { txId: "tx-local-issuer" },
    });
    const journal = { assertDeploymentBinding: vi.fn(async () => {}), executeOnce: vi.fn(async (
      _role: "issuer", _id: string, _commitment: string,
      execute: () => Promise<{ eventHash: string }>,
    ) => {
      try {
        return await execute();
      } catch {
        throw new Error("Proposal may have reached Compact; reconcile before any further action");
      }
    }) };
    await expect(submitLocalIssuerProposalCall({
      call, expectedGenesisHash: genesisHash,
      readFinalizedLedger: async (address) => ({ contractAddress: address, genesisHash, ledger }),
      providers: {} as Parameters<typeof submitLocalIssuerProposalCall>[0]["providers"], journal,
    })).rejects.toThrow(/reconcile/u);
    expect(journal.executeOnce).toHaveBeenCalledOnce();
  });

  it("never reserves or submits after a stale or substituted finalized read", async () => {
    const { call, ledger } = fixture();
    const journal = { assertDeploymentBinding: vi.fn(async () => {}), executeOnce: vi.fn() };
    await expect(submitLocalIssuerProposalCall({
      call: { ...call, contractAddress: `0x${"b".repeat(64)}` },
      expectedGenesisHash: genesisHash,
      readFinalizedLedger: async (address) => ({ contractAddress: address, genesisHash, ledger }),
      providers: {} as Parameters<typeof submitLocalIssuerProposalCall>[0]["providers"], journal,
    })).rejects.toThrow(/Maintainer signature/u);
    expect(journal.executeOnce).not.toHaveBeenCalled();
    expect(mocks.submitCallTx).not.toHaveBeenCalled();
  });
});
