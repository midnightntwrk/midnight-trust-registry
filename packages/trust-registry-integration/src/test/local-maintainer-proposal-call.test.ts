import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import {
  AuthorizationStatus,
  computeCreateMaintainerMembershipPayloadHash,
  computeMaintainerEvidenceBoundProposalPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
  EvidenceVerifierKeyStatus,
  TrustRegistryContract,
} from "@midnight-ntwrk/trust-registry-contract";

import {
  prepareUnsignedLocalMaintainerProposalCall,
  type UnsignedLocalMaintainerProposalCall,
} from "../local-maintainer-proposal-call.js";
import { createMaintainerAuthorizationScopeFixture, createMaintainerScenarioFixture } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

const registryLabel = "registry:local-maintainer-call";
const maintainerLabel = "participant:maintainer:local-call:v1";
const policy = bytes32Commitment("policy:local-maintainer-call");
const verifierAuthorizationId = bytes32Commitment("evidence-verifier:local-maintainer-call");
const verifierKeyId = bytes32Commitment("evidence-verifier:local-maintainer-key");

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
    maintainerKeyIds: { member: () => false },
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
