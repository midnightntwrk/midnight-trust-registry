import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";
import {
  computeCreateEpochCommitmentPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
  encodeJubjubSignature,
  pureCircuits,
  signPolicyBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  AuthorizationRecordSchema,
  DecisionEvidenceSchema,
  GovernancePolicySnapshotSchema,
  computeAuthorizationStatementLeafHash,
  computeGovernancePolicySnapshotCommitment,
  computeMerkleRootFromProof,
} from "@midnight-ntwrk/trust-registry-domain";

import { assertDecisionEvidenceConsistentWithSuppliedContext } from "../decision-context.js";
import { bytes32Commitment, bytes32Hex, hashHexToBytes32 } from "../utils.js";

const A = `0x${"a".repeat(64)}`;
const B = `0x${"b".repeat(64)}`;
const C = `0x${"c".repeat(64)}`;
const D = `0x${"d".repeat(64)}`;
const E = `0x${"e".repeat(64)}`;
const REGISTRY = "registry:midnight:university";
const EPOCH = "epoch:0001";
const DID = `did:midnight:devnet:${"1".repeat(64)}`;
const REGISTRY_DID = `did:midnight:devnet:${"2".repeat(64)}`;
const MAINTAINER_DIDS = [
  `did:midnight:devnet:${"3".repeat(64)}`,
  `did:midnight:devnet:${"4".repeat(64)}`,
];
const METHOD = `${DID}#key-1`;
const KEY = {
  kty: "EC" as const,
  crv: "Jubjub" as const,
  x: `${"A".repeat(42)}Q`,
  y: `${"B".repeat(42)}g`,
};

function fixture() {
  const grant = AuthorizationRecordSchema.parse({
    authorizationId: "auth:issuer:birth:v1",
    registryId: REGISTRY,
    subjectDid: DID,
    role: "issuer",
    resourceType: "credential-family",
    resourceId: `tr:issuer-resource:v1:${"f".repeat(64)}`,
    policyId: "policy:university:v1",
    trustLevel: "approved",
    statusPolicyBindingCommitment: E,
    status: "active",
    lifecycleEventRoot: B,
    proposedAt: "2026-05-20T00:00:00Z",
    authorizedAt: "2026-05-20T01:00:00Z",
    activeFrom: "2026-05-20T01:00:00Z",
    evidenceHash: D,
  });
  const policy = GovernancePolicySnapshotSchema.parse({
    format: "tr-policy-snapshot-v1",
    registryId: REGISTRY,
    policyId: "policy:university:v1",
    policyVersion: "v1",
    effectiveFrom: "2026-05-20T00:00:00Z",
    effectiveUntil: null,
    contentCommitment: C,
    thresholds: [
      { family: "maintainer", threshold: 2 },
      { family: "member", threshold: 2 },
      { family: "emergency", threshold: 2 },
      { family: "archival", threshold: 2 },
    ],
  });
  const leafHash = computeAuthorizationStatementLeafHash(grant);
  const stateRoot = computeMerkleRootFromProof(leafHash, [B], 0n);
  const policyRoot = computeGovernancePolicySnapshotCommitment(policy);
  const registryIdCommitment = bytes32Commitment(REGISTRY);
  const epochIdCommitment = bytes32Commitment(EPOCH);
  const keys = MAINTAINER_DIDS.map((did, index) => ({
    keyId: `${did}#key-1`,
    seed: new Uint8Array(32).fill(index === 0 ? 13 : 17),
  }));
  const activeMaintainersAtPublication = keys.map(({ keyId, seed }) => ({
    keyId,
    keyIdCommitment: bytes32Commitment(keyId),
    publicKey: deriveJubjubPublicKeyFromSeed(seed),
  }));
  const payload = computeCreateEpochCommitmentPayloadHash(
    epochIdCommitment,
    hashHexToBytes32(stateRoot),
    hashHexToBytes32(B),
    hashHexToBytes32(policyRoot),
    10n,
    20n,
  );
  const signatures = keys.map(({ keyId, seed }) => ({
    keyId,
    algorithm: "jubjub-schnorr" as const,
    signature: `0x${Buffer.from(encodeJubjubSignature(signPolicyBoundMaintainerActionFromSeed(
      seed,
      registryIdCommitment,
      hashHexToBytes32(E),
      encodeCompactActionKind("tr:epoch:publish"),
      payload,
      10n,
    ))).toString("hex")}`,
  }));
  const signerSetHash = pureCircuits.maintainerSignerSetHash(
    2n,
    activeMaintainersAtPublication[0]!.keyIdCommitment,
    activeMaintainersAtPublication[1]!.keyIdCommitment,
    new Uint8Array(32), new Uint8Array(32), new Uint8Array(32),
  );
  const publicationEventHash = bytes32Hex(pureCircuits.governanceEventHash(
    registryIdCommitment,
    hashHexToBytes32(E),
    signerSetHash,
    encodeCompactActionKind("tr:epoch:publish"),
    payload,
    10n,
  ));
  const epoch = {
    epochId: EPOCH,
    registryId: REGISTRY,
    stateRoot,
    eventRoot: B,
    policyRoot,
    publicationPolicyCommitment: E,
    publicationSequence: "10",
    validFromSequence: "10",
    validUntilSequence: "20",
    validFrom: "2026-05-20T02:00:00Z",
    validUntil: "2026-05-20T03:00:00Z",
    quorum: { requiredSignatures: 2, signatures },
  };
  const evidence = DecisionEvidenceSchema.parse({
    format: "tr-decision-evidence-v1",
    role: "issuer",
    registry: { registryId: REGISTRY, registryDid: REGISTRY_DID, networkId: "devnet", contractAddress: A },
    anchorReferences: {
      registryEpoch: { networkId: "devnet", contractAddress: A, transactionHash: B, blockHash: C },
      didState: { networkId: "devnet", blockHash: D },
    },
    epoch,
    grant,
    didMethod: {
      did: DID,
      methodId: METHOD,
      methodType: "JsonWebKey",
      controller: DID,
      publicKeyJwk: KEY,
      relationship: "assertionMethod",
      stateVersion: "3",
      stateEvidence: { evidenceType: "ledger-observation", blockHash: D, transactionHash: E },
    },
    policy,
    inclusionProof: { proofType: "merkle-inclusion", root: stateRoot, leafHash, path: [B], leafIndex: "0" },
    governanceEvents: { grantTransition: A, quorumApproval: B, epochPublication: publicationEventHash, policySnapshot: D },
    decisionSequence: "11",
  });
  const context = {
    acceptedEpoch: {
      registryId: REGISTRY,
      registryDid: REGISTRY_DID,
      networkId: "devnet",
      contractAddress: A,
      transactionHash: B,
      blockHash: C,
      epochId: EPOCH,
      stateRoot,
      eventRoot: B,
      policyRoot,
      publicationPolicyCommitment: E,
      publicationSequence: "10",
      validFromSequence: "10",
      validUntilSequence: "20",
      publicationEventHash,
      validFrom: epoch.validFrom,
      validUntil: epoch.validUntil,
      requiredSignatures: 2,
    },
    publication: {
      registryIdCommitment,
      epochIdCommitment,
      firstSignerKeyIdCommitment: activeMaintainersAtPublication[0]!.keyIdCommitment,
      activeMaintainersAtPublication,
    },
    didState: {
      networkId: "devnet",
      blockHash: D,
      transactionHash: E,
      stateVersion: "3",
      deactivated: false,
      didDocument: {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
        id: DID,
        verificationMethod: [{ id: METHOD, type: "JsonWebKey", controller: DID, publicKeyJwk: KEY }],
        assertionMethod: [METHOD],
      },
    },
    selection: {
      registryId: REGISTRY,
      networkId: "devnet",
      contractAddress: A,
      subjectDid: DID,
      role: "issuer" as const,
      resourceType: "credential-family" as const,
      resourceId: grant.resourceId,
    },
    decisionPoint: { sequence: "11", evaluationTime: "2026-05-20T02:30:00Z" },
  };
  return { evidence, context };
}

describe("decision evidence supplied-context composition", () => {
  it("checks the full two-signer epoch, grant, scope, DID method, and selected sequence", () => {
    const { evidence, context } = fixture();
    expect(() => assertDecisionEvidenceConsistentWithSuppliedContext(evidence, context)).not.toThrow();
  });

  it("fails closed when any supplied context or claimed proof is substituted", () => {
    const { evidence, context } = fixture();
    const signature = evidence.epoch.quorum.signatures[1]!.signature;
    for (const [candidate, supplied] of [
      [evidence, { ...context, decisionPoint: { ...context.decisionPoint, sequence: "12" } }],
      [evidence, { ...context, decisionPoint: { ...context.decisionPoint, evaluationTime: "2026-05-20T04:00:00Z" } }],
      [evidence, { ...context, acceptedEpoch: { ...context.acceptedEpoch, stateRoot: C } }],
      [evidence, { ...context, publication: { ...context.publication, activeMaintainersAtPublication: [] } }],
      [{ ...evidence, epoch: {
        ...evidence.epoch,
        quorum: { ...evidence.epoch.quorum, signatures: [
          evidence.epoch.quorum.signatures[0],
          { ...evidence.epoch.quorum.signatures[1], signature: `${signature.slice(0, -1)}${signature.endsWith("0") ? "1" : "0"}` },
        ] },
      } }, context],
      [{ ...evidence, inclusionProof: { ...evidence.inclusionProof, path: [C] } }, context],
      [evidence, { ...context, selection: { ...context.selection, resourceId: `tr:issuer-resource:v1:${"a".repeat(64)}` } }],
      [evidence, { ...context, didState: { ...context.didState, transactionHash: C } }],
      [evidence, { ...context, didState: { ...context.didState, deactivated: true } }],
    ] as const) {
      expect(() => assertDecisionEvidenceConsistentWithSuppliedContext(candidate, supplied)).toThrow();
    }
  });
});
