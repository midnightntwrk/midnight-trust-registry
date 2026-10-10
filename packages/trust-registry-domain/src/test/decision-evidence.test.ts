import { describe, expect, it } from "vitest";

import {
  AuthorizationRecordSchema,
  DecisionEvidenceJsonSchema,
  DecisionEvidenceSchema,
  GovernancePolicySnapshotSchema,
  assertDecisionEvidenceInclusion,
  assertDecisionEvidencePolicyCommitment,
  computeAuthorizationStatementLeafHash,
  computeGovernancePolicySnapshotCommitment,
  computeMerkleRootFromProof,
} from "../index.js";

const A = `0x${"a".repeat(64)}`;
const B = `0x${"b".repeat(64)}`;
const C = `0x${"c".repeat(64)}`;
const D = `0x${"d".repeat(64)}`;
const E = `0x${"e".repeat(64)}`;
const DID = `did:midnight:devnet:${"1".repeat(64)}`;
const REGISTRY_DID = `did:midnight:devnet:${"2".repeat(64)}`;
const MAINTAINER = `did:midnight:devnet:${"3".repeat(64)}`;
const NOW = "2026-05-20T02:00:00Z";

const issuerEvidence = () => ({
  format: "tr-decision-evidence-v1",
  role: "issuer",
  registry: {
    registryId: "registry:midnight:university",
    registryDid: REGISTRY_DID,
    networkId: "devnet",
    contractAddress: A,
  },
  anchorReferences: {
    registryEpoch: { networkId: "devnet", contractAddress: A, transactionHash: B, blockHash: C },
    didState: { networkId: "devnet", blockHash: D },
  },
  epoch: {
    epochId: "epoch:0001",
    registryId: "registry:midnight:university",
    stateRoot: A,
    eventRoot: B,
    policyRoot: C,
    publicationSequence: "10",
    validFrom: NOW,
    validUntil: "2026-05-20T03:00:00Z",
    quorum: {
      requiredSignatures: 2,
      signatures: [
        { keyId: `${MAINTAINER}#key-1`, algorithm: "jubjub-schnorr", signature: `0x${"a".repeat(192)}` },
        { keyId: `${MAINTAINER}#key-2`, algorithm: "jubjub-schnorr", signature: `0x${"b".repeat(192)}` },
      ],
    },
  },
  grant: {
    authorizationId: "auth:issuer:birth:v1",
    registryId: "registry:midnight:university",
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
  },
  didMethod: {
    did: DID,
    methodId: `${DID}#key-1`,
    methodType: "JsonWebKey",
    controller: DID,
    publicKeyJwk: { kty: "EC", crv: "Jubjub", x: `${"A".repeat(42)}Q`, y: `${"B".repeat(42)}g` },
    stateVersion: "3",
    relationship: "assertionMethod",
    stateEvidence: { evidenceType: "ledger-observation", blockHash: D, transactionHash: E },
  },
  policy: {
    format: "tr-policy-snapshot-v1",
    registryId: "registry:midnight:university",
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
  },
  inclusionProof: { proofType: "merkle-inclusion", root: A, leafHash: D, path: [B], leafIndex: "0" },
  governanceEvents: {
    grantTransition: A,
    quorumApproval: B,
    epochPublication: C,
    policySnapshot: D,
  },
  decisionSequence: "11",
});

describe("decision evidence envelope", () => {
  it("accepts structural issuer and verifier claims without authenticating them", () => {
    expect(DecisionEvidenceSchema.safeParse(issuerEvidence()).success).toBe(true);
    const issuer = issuerEvidence();
    const verifier = {
      ...issuer,
      role: "verifier",
      grant: {
        ...issuer.grant,
        role: "verifier",
        resourceType: "request-profile",
        resourceId: `tr:request-resource:v1:${"f".repeat(64)}`,
        statusPolicyBindingCommitment: undefined,
      },
      didMethod: {
        ...issuer.didMethod,
        relationship: "authentication",
        stateEvidence: {
          evidenceType: "state-proof",
          stateRoot: A,
          leafHash: B,
          path: [C],
          leafIndex: "0",
          blockHash: D,
        },
      },
    };
    expect(DecisionEvidenceSchema.safeParse(verifier).success).toBe(true);
    expect(DecisionEvidenceSchema.safeParse({
      ...verifier,
      didMethod: { ...verifier.didMethod, relationship: "capabilityInvocation" },
    }).success).toBe(true);
  });

  it("rejects wrong roles, absent DID version, malformed method/key/scope/root, and undersized quorum", () => {
    const evidence = issuerEvidence();
    const invalid = [
      { ...evidence, role: "auditor" },
      { ...evidence, grant: { ...evidence.grant, role: "verifier" } },
      { ...evidence, didMethod: { ...evidence.didMethod, relationship: "authentication" } },
      { ...evidence, didMethod: { ...evidence.didMethod, stateVersion: undefined } },
      { ...evidence, didMethod: { ...evidence.didMethod, stateVersion: "0" } },
      { ...evidence, didMethod: { ...evidence.didMethod, stateVersion: "01" } },
      { ...evidence, didMethod: { ...evidence.didMethod, stateVersion: "18446744073709551616" } },
      { ...evidence, epoch: { ...evidence.epoch, publicationSequence: Number.MAX_SAFE_INTEGER + 1 } },
      { ...evidence, decisionSequence: "18446744073709551616" },
      { ...evidence, decisionSequence: "9" },
      { ...evidence, epoch: { ...evidence.epoch, validUntil: NOW } },
      { ...evidence, epoch: { ...evidence.epoch, validUntil: "2026-05-20T01:00:00Z" } },
      { ...evidence, didMethod: { ...evidence.didMethod, methodId: "#key-1" } },
      { ...evidence, didMethod: { ...evidence.didMethod, publicKeyJwk: { ...evidence.didMethod.publicKeyJwk, x: "bad!" } } },
      { ...evidence, grant: { ...evidence.grant, resourceId: "birth" } },
      { ...evidence, epoch: { ...evidence.epoch, stateRoot: "not-a-root" } },
      { ...evidence, epoch: { ...evidence.epoch, quorum: { ...evidence.epoch.quorum, signatures: evidence.epoch.quorum.signatures.slice(0, 1) } } },
      { ...evidence, epoch: { ...evidence.epoch, quorum: { ...evidence.epoch.quorum, signatures: [{ ...evidence.epoch.quorum.signatures[0], algorithm: "ed25519" }, evidence.epoch.quorum.signatures[1]] } } },
      { ...evidence, epoch: { ...evidence.epoch, quorum: { ...evidence.epoch.quorum, signatures: [{ ...evidence.epoch.quorum.signatures[0], signature: "not-hex" }, evidence.epoch.quorum.signatures[1]] } } },
      { ...evidence, epoch: { ...evidence.epoch, quorum: { ...evidence.epoch.quorum, signatures: [evidence.epoch.quorum.signatures[0], evidence.epoch.quorum.signatures[0]] } } },
      { ...evidence, governanceEvents: { ...evidence.governanceEvents, grantTransition: "event:unanchored" } },
      { ...evidence, inclusionProof: { ...evidence.inclusionProof, root: C } },
      { ...evidence, anchorReferences: { ...evidence.anchorReferences, didState: { networkId: "devnet", blockHash: C } } },
      { ...evidence, registry: { ...evidence.registry, networkId: "mainnet" } },
    ];
    for (const candidate of invalid) {
      expect(DecisionEvidenceSchema.safeParse(candidate).success).toBe(false);
    }
  });

  it("rejects extra properties at every object boundary", () => {
    const evidence = issuerEvidence();
    const invalid = [
      { ...evidence, trusted: true },
      { ...evidence, registry: { ...evidence.registry, trusted: true } },
      { ...evidence, anchorReferences: { ...evidence.anchorReferences, registryEpoch: { ...evidence.anchorReferences.registryEpoch, accepted: true } } },
      { ...evidence, epoch: { ...evidence.epoch, quorum: { ...evidence.epoch.quorum, accepted: true } } },
      { ...evidence, grant: { ...evidence.grant, trusted: true } },
      { ...evidence, didMethod: { ...evidence.didMethod, publicKeyJwk: { ...evidence.didMethod.publicKeyJwk, d: "secret" } } },
      { ...evidence, policy: { ...evidence.policy, trusted: true } },
      { ...evidence, inclusionProof: { ...evidence.inclusionProof, verified: true } },
    ];
    for (const candidate of invalid) {
      expect(DecisionEvidenceSchema.safeParse(candidate).success).toBe(false);
    }
  });

  it("exports a versioned draft-2020-12 JSON Schema with strict variants", () => {
    expect(DecisionEvidenceJsonSchema.$id).toMatch(/decision-evidence-v1\.json$/u);
    expect(DecisionEvidenceJsonSchema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(JSON.stringify(DecisionEvidenceJsonSchema)).toContain('"additionalProperties":false');
    expect(JSON.stringify(DecisionEvidenceJsonSchema)).toContain('"const":"tr-decision-evidence-v1"');
    expect(JSON.stringify(DecisionEvidenceJsonSchema)).toContain('"const":"verifier"');
  });

  it("checks exact grant inclusion using a uint64 leaf index without authenticating the root", () => {
    const evidence = issuerEvidence();
    const leafHash = computeAuthorizationStatementLeafHash(AuthorizationRecordSchema.parse(evidence.grant));
    const index = 1n << 53n;
    const path = Array(54).fill(B) as string[];
    const root = computeMerkleRootFromProof(leafHash, path, index);
    evidence.epoch.stateRoot = root;
    evidence.inclusionProof = { proofType: "merkle-inclusion", root, leafHash, path, leafIndex: index.toString() };
    expect(() => assertDecisionEvidenceInclusion(evidence)).not.toThrow();
    const genericPath = [C, ...path.slice(1)];
    const genericRoot = computeMerkleRootFromProof(leafHash, genericPath, index);
    expect(() => assertDecisionEvidenceInclusion({
      ...evidence,
      epoch: { ...evidence.epoch, stateRoot: genericRoot },
      inclusionProof: { ...evidence.inclusionProof, root: genericRoot, path: genericPath },
    })).not.toThrow();
    expect(() => assertDecisionEvidenceInclusion({
      ...evidence,
      grant: { ...evidence.grant, evidenceHash: E },
    })).toThrow(/grant leaf hash mismatch/u);
    expect(() => assertDecisionEvidenceInclusion({
      ...evidence,
      inclusionProof: { ...evidence.inclusionProof, leafIndex: "0" },
    })).toThrow(/Merkle root mismatch/u);
    expect(() => assertDecisionEvidenceInclusion({
      ...evidence,
      inclusionProof: { ...evidence.inclusionProof, path: [C, ...path.slice(1)] },
    })).toThrow(/Merkle root mismatch/u);
    expect(() => assertDecisionEvidenceInclusion({
      ...evidence,
      epoch: { ...evidence.epoch, stateRoot: D },
      inclusionProof: { ...evidence.inclusionProof, root: D },
    })).toThrow(/Merkle root mismatch/u);
  });

  it("checks the policy snapshot against the claimed epoch root", () => {
    const evidence = issuerEvidence();
    evidence.epoch.policyRoot = computeGovernancePolicySnapshotCommitment(
      GovernancePolicySnapshotSchema.parse(evidence.policy),
    );
    expect(() => assertDecisionEvidencePolicyCommitment(evidence)).not.toThrow();
    expect(() => assertDecisionEvidencePolicyCommitment({
      ...evidence,
      policy: { ...evidence.policy, contentCommitment: A },
    })).toThrow(/policy root mismatch/u);
    expect(() => assertDecisionEvidencePolicyCommitment({
      ...evidence,
      epoch: { ...evidence.epoch, policyRoot: D },
    })).toThrow(/policy root mismatch/u);
  });
});
