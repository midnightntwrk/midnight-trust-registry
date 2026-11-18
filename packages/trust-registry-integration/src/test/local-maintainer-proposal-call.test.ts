import { Buffer } from "node:buffer";

import { beforeEach, describe, expect, it, vi } from "vitest";

import { bytes32Commitment } from "@midnightntwrk/trust-registry-client";
import {
  AuthorizationStatus,
  computeCreateMaintainerMembershipPayloadHash,
  computeMaintainerEvidenceBoundProposalPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
  EvidenceVerifierKeyStatus,
  MaintainerStatus,
  signDeploymentBoundMaintainerActionFromSeed,
  signMaintainerProposalEvidenceFromSeed,
  TrustRegistryContract,
} from "@midnightntwrk/trust-registry-contract";

import {
  executeLocalMaintainerProposalAfterReservation,
  preflightLocalMaintainerProposalSubmission,
  prepareLocalMaintainerProposalCall,
  prepareUnsignedLocalMaintainerProposalCall,
  submitLocalMaintainerProposalCall,
  type LocalMaintainerProposalCall,
  type UnsignedLocalMaintainerProposalCall,
} from "../local-maintainer-proposal-call.js";
import { createMaintainerAuthorizationScopeFixture, createMaintainerScenarioFixture } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

const mocks = vi.hoisted(() => ({ submitCallTx: vi.fn(), compiledContract: { circuit: "maintainer" } }));
vi.mock("@midnight-ntwrk/midnight-js-contracts", async (importOriginal) => ({
  ...await importOriginal<typeof import("@midnight-ntwrk/midnight-js-contracts")>(),
  submitCallTx: mocks.submitCallTx,
}));
vi.mock("../public-network-deployment.js", async (importOriginal) => ({
  ...await importOriginal<typeof import("../public-network-deployment.js")>(),
  compiledStagedVerifierKeyContract: vi.fn(() => mocks.compiledContract),
}));

const registryLabel = "registry:local-maintainer-call";
const maintainerLabel = "participant:maintainer:local-call:v1";
const policy = bytes32Commitment("policy:local-maintainer-call");
const verifierAuthorizationId = bytes32Commitment("evidence-verifier:local-maintainer-call");
const verifierKeyId = bytes32Commitment("evidence-verifier:local-maintainer-key");
const genesisHash = `0x${"d".repeat(64)}`;

beforeEach(() => vi.clearAllMocks());

function fixture(): { input: UnsignedLocalMaintainerProposalCall; ledger: TrustRegistryContract.Ledger } {
  const input: UnsignedLocalMaintainerProposalCall = {
    networkId: "undeployed",
    registryId: registryLabel,
    contractAddress: `0x${"a".repeat(64)}`,
    maintainerLabel,
    maintainerId: bytes32Commitment(maintainerLabel),
    maintainerDidCommitment: bytes32Commitment("did:midnight:undeployed:maintainer:local-call"),
    candidateKeyId: bytes32Commitment("maintainer:local-call:key-1"),
    candidatePublicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(13)),
    policyId: policy,
    trustLevel: bytes32Commitment("governance-approved"),
    evidenceHash: bytes32Commitment("accepted-vp:local-maintainer-call"),
    evidenceVerifierAuthorizationId: verifierAuthorizationId,
    evidenceVerifierKeyIdCommitment: verifierKeyId,
  };
  const suite = new Uint8Array(32);
  suite.set(new TextEncoder().encode("jubjub-schnorr"));
  const evidenceKey = {
    authorizationId: verifierAuthorizationId,
    keyIdCommitment: verifierKeyId,
    verifierDidCommitment: bytes32Commitment("did:midnight:undeployed:verifier:local-call"),
    publicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(19)),
    status: EvidenceVerifierKeyStatus.active,
    suite,
    policyCommitment: policy,
    policyVersion: 1n,
  };
  const scope = TrustRegistryContract.pureCircuits.evidenceVerifierKeyScopeKey(
    evidenceKey.verifierDidCommitment, evidenceKey.policyCommitment,
  );
  const ledger = {
    initialized: true,
    contractVersion: 1n,
    registryId: bytes32Commitment(registryLabel),
    deploymentNetworkIdCommitment: bytes32Commitment("undeployed"),
    governancePolicyCommitment: policy,
    governancePolicyVersion: 1n,
    governanceActionCount: 18n,
    maintainerThreshold: 1n,
    emergencyMaintainerThreshold: 1n,
    archivalMaintainerThreshold: 1n,
    maintainerMembershipIds: { member: () => false },
    maintainerMembershipRecords: {
      lookup: () => ({ status: AuthorizationStatus.active }),
    },
    maintainerProposalEvidenceRecords: { member: () => false },
    maintainerKeyIds: { member: () => false, *[Symbol.iterator]() {} },
    maintainerRecords: { lookup: () => ({ publicKey: input.candidatePublicKey }) },
    currentMaintainerMembershipIdsByDidCommitment: {
      member: () => false, lookup: () => bytes32Commitment("old-maintainer"),
    },
    currentMaintainerMembershipIdsByKeyId: {
      member: () => false, lookup: () => bytes32Commitment("old-maintainer"),
    },
    evidenceVerifierKeyRecords: {
      member: (id: Uint8Array) => Buffer.from(id).equals(verifierAuthorizationId),
      lookup: () => evidenceKey,
    },
    currentEvidenceVerifierKeyIdsByScopeKey: {
      member: (key: Uint8Array) => Buffer.from(key).equals(scope),
      lookup: () => verifierAuthorizationId,
    },
  } as unknown as TrustRegistryContract.Ledger;
  return { input, ledger };
}

function signedFixture(): { call: LocalMaintainerProposalCall; ledger: TrustRegistryContract.Ledger } {
  const { input, ledger } = fixture();
  const signerSeed = new Uint8Array(32).fill(17);
  const signerKeyId = bytes32Commitment("maintainer:existing:key-1");
  const signerPublicKey = deriveJubjubPublicKeyFromSeed(signerSeed);
  const finalized = {
    ...ledger,
    maintainerKeyIds: {
      ...ledger.maintainerKeyIds,
      member: (key: Uint8Array) => Buffer.from(key).equals(signerKeyId),
      *[Symbol.iterator]() { yield signerKeyId; },
    },
    maintainerRecords: {
      ...ledger.maintainerRecords,
      lookup: () => ({ keyId: signerKeyId, publicKey: signerPublicKey, status: MaintainerStatus.active }),
    },
  } as unknown as TrustRegistryContract.Ledger;
  const prepared = prepareUnsignedLocalMaintainerProposalCall(input, finalized);
  const call: LocalMaintainerProposalCall = {
    ...input,
    evidenceVerifierSignature: signMaintainerProposalEvidenceFromSeed(
      new Uint8Array(32).fill(19), prepared.registryId, prepared.networkIdCommitment,
      prepared.contractAddress, verifierKeyId, prepared.actionPayloadHash,
    ),
    signers: [{
      keyId: signerKeyId,
      publicKey: signerPublicKey,
      signature: signDeploymentBoundMaintainerActionFromSeed(
        signerSeed, prepared.registryId, prepared.networkIdCommitment,
        prepared.contractAddress, prepared.policyCommitment, prepared.actionKind,
        prepared.actionPayloadHash, prepared.actionSequence,
      ),
    }],
  };
  return { call, ledger: finalized };
}

describe("local maintainer proposal signing preflight", () => {
  it("matches the evidence-backed simulator signing context", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("local-maintainer-proposal-parity");
    const candidate = createMaintainerScenarioFixture("local-maintainer-proposal-parity");
    await harness.ready;
    const evidence = await harness.createApplicationEvidence({
      applicationId: candidate.maintainerId,
      subjectDid: candidate.subjectDid,
      role: "maintainer",
      scope: createMaintainerAuthorizationScopeFixture(harness.registryId),
    });
    const prepared = await harness.prepareMaintainerProposalAction(candidate, evidence);
    const ledger = await harness.simulator.getLedger();
    const actual = prepareUnsignedLocalMaintainerProposalCall({
      networkId: "undeployed",
      registryId: harness.registryId,
      contractAddress: `0x${harness.simulator.contractAddress}`,
      maintainerLabel: candidate.maintainerId,
      maintainerId: candidate.maintainerIdCommitment,
      maintainerDidCommitment: candidate.subjectDidCommitment,
      candidateKeyId: candidate.keyId,
      candidatePublicKey: deriveJubjubPublicKeyFromSeed(candidate.seed),
      policyId: ledger.governancePolicyCommitment,
      trustLevel: bytes32Commitment(candidate.trustLevel),
      evidenceHash: prepared.evidenceHash,
      evidenceVerifierAuthorizationId: prepared.evidenceVerifierAuthorizationId,
      evidenceVerifierKeyIdCommitment: prepared.evidenceVerifierKeyIdCommitment,
    }, ledger);
    expect(actual.actionKind).toEqual(prepared.actionKind);
    expect(actual.actionPayloadHash).toEqual(prepared.actionPayloadHash);
    expect(actual.actionSequence).toBe(prepared.actionSequence);
    expect(actual.policyVersion).toBe(prepared.policyVersion);
  });

  it("binds the exact finalized action sequence, policy, candidate and verifier key", () => {
    const { input, ledger } = fixture();
    const result = prepareUnsignedLocalMaintainerProposalCall(input, ledger);
    const base = computeCreateMaintainerMembershipPayloadHash(
      input.maintainerId, input.maintainerDidCommitment, input.candidateKeyId,
      input.candidatePublicKey, policy, input.trustLevel, input.evidenceHash,
    );
    expect(result.actionPayloadHash).toEqual(computeMaintainerEvidenceBoundProposalPayloadHash(
      base, verifierAuthorizationId, verifierKeyId, policy, 1n,
    ));
    expect(result.actionKind).toEqual(encodeCompactActionKind("tr:maintainer:propose"));
    expect(result.actionSequence).toBe(18n);
    expect(result.requiredThreshold).toBe(1n);
    expect(result.contractAddress).toEqual(Buffer.from("a".repeat(64), "hex"));
  });

  it("rejects mismatched deployment and candidate identity", () => {
    const { input, ledger } = fixture();
    expect(() => prepareUnsignedLocalMaintainerProposalCall({
      ...input, maintainerLabel: "participant:maintainer:other:v1",
    }, ledger)).toThrow(/identity binding/u);
    expect(() => prepareUnsignedLocalMaintainerProposalCall(input, {
      ...ledger, deploymentNetworkIdCommitment: bytes32Commitment("other"),
    })).toThrow(/registry, or network/u);
  });

  it("rejects stale policy, reused key and current DID membership", () => {
    const { input, ledger } = fixture();
    expect(() => prepareUnsignedLocalMaintainerProposalCall({
      ...input, policyId: bytes32Commitment("stale"),
    }, ledger)).toThrow(/policy is stale/u);
    expect(() => prepareUnsignedLocalMaintainerProposalCall(input, {
      ...ledger, maintainerKeyIds: { ...ledger.maintainerKeyIds, member: () => true },
    })).toThrow(/already registered/u);
    expect(() => prepareUnsignedLocalMaintainerProposalCall(input, {
      ...ledger, maintainerProposalEvidenceRecords: {
        ...ledger.maintainerProposalEvidenceRecords, member: () => true,
      },
    })).toThrow(/already registered/u);
    expect(() => prepareUnsignedLocalMaintainerProposalCall(input, {
      ...ledger, currentMaintainerMembershipIdsByDidCommitment: {
        ...ledger.currentMaintainerMembershipIdsByDidCommitment, member: () => true,
      },
    })).toThrow(/live membership/u);
    expect(() => prepareUnsignedLocalMaintainerProposalCall(input, {
      ...ledger,
      currentMaintainerMembershipIdsByDidCommitment: {
        ...ledger.currentMaintainerMembershipIdsByDidCommitment, member: () => true,
      },
      maintainerMembershipRecords: {
        ...ledger.maintainerMembershipRecords,
        lookup: () => ({ status: AuthorizationStatus.revoked }),
      },
    } as unknown as TrustRegistryContract.Ledger)).not.toThrow();
  });

  it("rejects a reused public key even when its key ID differs", () => {
    const { input, ledger } = fixture();
    expect(() => prepareUnsignedLocalMaintainerProposalCall(input, {
      ...ledger,
      maintainerKeyIds: {
        ...ledger.maintainerKeyIds,
        member: () => false,
        *[Symbol.iterator]() { yield bytes32Commitment("existing-maintainer-key"); },
      },
    })).toThrow(/public key is already registered/u);
  });

  it("rejects an inactive or substituted evidence verifier", () => {
    const { input, ledger } = fixture();
    expect(() => prepareUnsignedLocalMaintainerProposalCall({
      ...input, evidenceVerifierKeyIdCommitment: bytes32Commitment("substituted"),
    }, ledger)).toThrow(/not current/u);
    expect(() => prepareUnsignedLocalMaintainerProposalCall(input, {
      ...ledger, currentEvidenceVerifierKeyIdsByScopeKey: {
        ...ledger.currentEvidenceVerifierKeyIdsByScopeKey, member: () => false,
      },
    })).toThrow(/not current/u);
  });

  it("rejects a candidate key outside the prime-order subgroup", () => {
    const { input, ledger } = fixture();
    expect(() => prepareUnsignedLocalMaintainerProposalCall({
      ...input, candidatePublicKey: { x: 0n, y: 1n },
    }, ledger)).toThrow(/prime-order/u);
  });
});

describe("local maintainer proposal one-shot submission", () => {
  it("verifies evidence and signer signatures against the finalized action", () => {
    const { call, ledger } = signedFixture();
    const prepared = prepareLocalMaintainerProposalCall(call, ledger);
    expect(prepared.actionSequence).toBe(18n);
    expect(prepared.authorizationBundle.signerCount).toBe(1n);
    expect(() => prepareLocalMaintainerProposalCall({
      ...call, evidenceHash: bytes32Commitment("substituted-evidence"),
    }, ledger)).toThrow(/evidence signature/u);
    expect(() => prepareLocalMaintainerProposalCall({
      ...call, signers: [call.signers[0]!, call.signers[0]!],
    }, ledger)).toThrow(/public keys must be distinct/u);
  });

  it("rejects an unbound journal, wrong chain, or unsafe provider before submission", async () => {
    const { call, ledger } = signedFixture();
    const journal = { assertDeploymentBinding: vi.fn(async () => {}), executeOnce: vi.fn() };
    const readFinalizedLedger = vi.fn(async () => ({
      contractAddress: call.contractAddress, genesisHash, ledger,
    }));
    const providers = { midnightProvider: {
      supportedEras: {},
      submitTxWithBroadcastGuard: async () => ({ txId: "unused" }),
    } } as unknown as Parameters<typeof submitLocalMaintainerProposalCall>[0]["providers"];
    const unsafeProviders = {} as Parameters<typeof submitLocalMaintainerProposalCall>[0]["providers"];
    const readSubmissionProviderIdentity = async () => ({ contractAddress: call.contractAddress, genesisHash });
    await expect(submitLocalMaintainerProposalCall({
      call, expectedGenesisHash: `0x${"0".repeat(64)}`, readFinalizedLedger,
      providers, readSubmissionProviderIdentity, journal,
    })).rejects.toThrow(/pinned nonzero genesis/u);
    expect(journal.assertDeploymentBinding).not.toHaveBeenCalled();
    journal.assertDeploymentBinding.mockRejectedValueOnce(new Error("wrong deployment"));
    await expect(submitLocalMaintainerProposalCall({
      call, expectedGenesisHash: genesisHash, readFinalizedLedger,
      providers, readSubmissionProviderIdentity, journal,
    })).rejects.toThrow(/wrong deployment/u);
    expect(journal.executeOnce).not.toHaveBeenCalled();
    await expect(preflightLocalMaintainerProposalSubmission({
      call, expectedGenesisHash: genesisHash,
      readFinalizedLedger: async () => ({
        contractAddress: call.contractAddress, genesisHash: `0x${"e".repeat(64)}`, ledger,
      }),
      providers, readSubmissionProviderIdentity,
    })).rejects.toThrow(/pinned deployment/u);
    await expect(executeLocalMaintainerProposalAfterReservation({
      call, expectedGenesisHash: genesisHash, readFinalizedLedger,
      providers: unsafeProviders, readSubmissionProviderIdentity,
    }, prepareLocalMaintainerProposalCall(call, ledger), async () => {}))
      .rejects.toThrow(/transport broadcast guard/u);
    await expect(submitLocalMaintainerProposalCall({
      call, expectedGenesisHash: genesisHash, readFinalizedLedger,
      providers: unsafeProviders, readSubmissionProviderIdentity, journal,
    })).rejects.toThrow(/transport broadcast guard/u);
    expect(journal.executeOnce).not.toHaveBeenCalled();
    expect(mocks.submitCallTx).not.toHaveBeenCalled();
  });

  it("submits once through a guarded transport and returns the prepared event", async () => {
    const { call, ledger } = signedFixture();
    const prepared = prepareLocalMaintainerProposalCall(call, ledger);
    let guardedBroadcasts = 0;
    const providers = {
      midnightProvider: {
        supportedEras: {},
        submitTxWithBroadcastGuard: async (_tx: unknown, guard: () => Promise<void>) => {
          await guard();
          guardedBroadcasts += 1;
          return { txId: "tx-local-maintainer" };
        },
      },
    } as unknown as Parameters<typeof submitLocalMaintainerProposalCall>[0]["providers"];
    mocks.submitCallTx.mockImplementationOnce(async (selectedProviders, options) => {
      expect(options.circuitId).toBe("proposeMaintainerMembership");
      expect(options.args[0]).toEqual(prepared.authorizationBundle);
      expect(options.args[1]).toEqual(call.maintainerId);
      await selectedProviders.midnightProvider.submitTx({});
      return {
        private: { result: prepared.expectedEventHash },
        public: { txId: "tx-local-maintainer" },
      };
    });
    const journal = {
      assertDeploymentBinding: vi.fn(async () => {}),
      executeOnce: vi.fn(async (
        _role: "maintainer", _id: string, _evidence: string,
        execute: () => Promise<{ eventHash: string }>,
      ) => execute()),
    };
    const result = await submitLocalMaintainerProposalCall({
      call, expectedGenesisHash: genesisHash,
      readFinalizedLedger: async () => ({ contractAddress: call.contractAddress, genesisHash, ledger }),
      providers,
      readSubmissionProviderIdentity: async () => ({ contractAddress: call.contractAddress, genesisHash }),
      journal,
    });
    expect(result.eventHash).toBe(`0x${Buffer.from(prepared.expectedEventHash).toString("hex")}`);
    expect(journal.executeOnce).toHaveBeenCalledOnce();
    expect(guardedBroadcasts).toBe(1);
    expect(mocks.submitCallTx).toHaveBeenCalledOnce();
  });

  it("rechecks the reserved sequence before broadcast on a busy shared chain", async () => {
    const { call, ledger } = signedFixture();
    let readCount = 0;
    let broadcastCount = 0;
    const readFinalizedLedger = async () => {
      readCount += 1;
      return {
        contractAddress: call.contractAddress,
        genesisHash,
        ledger: readCount >= 3 ? { ...ledger, governanceActionCount: 19n } : ledger,
      };
    };
    const providers = {
      midnightProvider: {
        supportedEras: {},
        submitTxWithBroadcastGuard: async (_tx: unknown, guard: () => Promise<void>) => {
          await guard();
          broadcastCount += 1;
          return { txId: "unused" };
        },
      },
    } as unknown as Parameters<typeof submitLocalMaintainerProposalCall>[0]["providers"];
    mocks.submitCallTx.mockImplementationOnce(async (selectedProviders) => {
      await selectedProviders.midnightProvider.submitTx({});
      return { private: { result: new Uint8Array(32) }, public: { txId: "unused" } };
    });
    const journal = {
      assertDeploymentBinding: vi.fn(async () => {}),
      executeOnce: vi.fn(async (
        _role: "maintainer", _id: string, _evidence: string,
        execute: () => Promise<{ eventHash: string }>,
      ) => execute()),
    };
    await expect(submitLocalMaintainerProposalCall({
      call, expectedGenesisHash: genesisHash, readFinalizedLedger, providers,
      readSubmissionProviderIdentity: async () => ({ contractAddress: call.contractAddress, genesisHash }),
      journal,
    })).rejects.toThrow(/signature does not bind the current proposal/u);
    expect(journal.executeOnce).toHaveBeenCalledOnce();
    expect(readCount).toBe(3);
    expect(broadcastCount).toBe(0);
  });
});
