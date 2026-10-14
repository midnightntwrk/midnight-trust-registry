import { Buffer } from "node:buffer";

import { describe, expect, it, vi } from "vitest";
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
  computeAuthorizationScopeCommitment,
  computeGovernancePolicySnapshotCommitment,
  computeIssuerStatusPolicyBindingCommitment,
  computeMerkleRootFromProof,
  issuerGovernedResourceId,
  requestGovernedResourceId,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  assertDecisionEvidenceConsistentWithSuppliedContext,
  assertInactiveDecisionEvidenceConsistentWithSuppliedContext,
  verifyDecisionEvidenceWithTrustedReaders,
  verifyInactiveDecisionEvidenceWithTrustedReaders,
} from "../decision-context.js";
import { verifyDecisionEvidenceFromApi } from "../decision-evidence-http.js";
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
const ISSUER_SCOPE = {
  version: "tr-scope-v1",
  role: "issuer",
  credentialFamilyId: "credential-family:birth",
  schemaId: "schema:birth",
  schemaVersion: "1.0.0",
  credentialDefinitionId: "credential-definition:birth",
  statusMethod: "midnight-status-registry-v1",
} as const;
const VERIFIER_SCOPE = {
  version: "tr-scope-v1" as const,
  role: "verifier" as const,
  requestProfileId: "request-profile:birth",
  purpose: "age-verification",
  credentialScopeCommitment: C,
  allowedAttributes: ["age"],
  allowedPredicates: ["over-18"],
  disclosureLevel: "minimal",
};
const KEY = {
  kty: "EC" as const,
  crv: "Jubjub" as const,
  x: `${"A".repeat(42)}Q`,
  y: `${"B".repeat(42)}g`,
};

function fixture(
  role: "issuer" | "verifier" = "issuer",
  status: "active" | "suspended" | "revoked" | "superseded" | "archived" = "active",
) {
  const statusPolicyBinding = {
    version: "tr-issuer-status-policy-v1" as const,
    trustRegistryId: REGISTRY,
    issuerAuthorizationId: "auth:issuer:birth:v1",
    statusRegistryId: D,
    statusAuthorityVerificationMethod: METHOD,
    statusPolicyId: "policy:status:v1",
    statusPolicyVersion: "v1",
    statusPolicyContentCommitment: C,
  };
  const grant = AuthorizationRecordSchema.parse({
    authorizationId: `auth:${role}:birth:v1`,
    registryId: REGISTRY,
    subjectDid: DID,
    role,
    resourceType: role === "issuer" ? "credential-family" : "request-profile",
    resourceId: role === "issuer"
      ? issuerGovernedResourceId(ISSUER_SCOPE, "credentialFamily")
      : requestGovernedResourceId(VERIFIER_SCOPE),
    policyId: "policy:university:v1",
    trustLevel: "approved",
    ...(role === "issuer" ? { statusPolicyBindingCommitment: computeIssuerStatusPolicyBindingCommitment(statusPolicyBinding) } : {}),
    status,
    lifecycleEventRoot: B,
    proposedAt: "2026-05-20T00:00:00Z",
    authorizedAt: "2026-05-20T01:00:00Z",
    activeFrom: "2026-05-20T01:00:00Z",
    ...(status === "suspended" ? { suspendedAt: "2026-05-20T02:15:00Z" } : {}),
    ...(status === "revoked" ? { revokedAt: "2026-05-20T02:15:00Z" } : {}),
    ...(status === "superseded" ? { supersededAt: "2026-05-20T02:15:00Z" } : {}),
    ...(status === "archived" ? { archivedAt: "2026-05-20T02:15:00Z" } : {}),
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
    role,
    registry: { registryId: REGISTRY, registryDid: REGISTRY_DID, networkId: "devnet", contractAddress: A },
    anchorReferences: {
      registryEpoch: { networkId: "devnet", contractAddress: A, transactionHash: B, blockHash: C },
      didState: { networkId: "devnet", blockHash: D },
    },
    epoch,
    grant,
    scope: role === "issuer" ? ISSUER_SCOPE : VERIFIER_SCOPE,
    didMethod: {
      did: DID,
      methodId: METHOD,
      methodType: "JsonWebKey",
      controller: DID,
      publicKeyJwk: KEY,
      relationship: role === "issuer" ? "assertionMethod" : "authentication",
      stateVersion: "3",
      stateEvidence: { evidenceType: "ledger-observation", blockHash: D, transactionHash: E },
    },
    ...(role === "issuer" ? { statusPolicyBinding } : {}),
    policy,
    inclusionProof: { proofType: "merkle-inclusion", root: stateRoot, leafHash, path: [B], leafIndex: "0" },
    governanceEvents: {
      grantTransition: A,
      quorumApproval: B,
      epochPublication: publicationEventHash,
      policySnapshot: D,
      ...(status === "superseded" ? { supersession: E } : {}),
    },
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
        authentication: [METHOD],
      },
    },
    selection: {
      registryId: REGISTRY,
      networkId: "devnet",
      contractAddress: A,
      subjectDid: DID,
      role,
      resourceType: grant.resourceType,
      resourceId: grant.resourceId,
      scope: role === "issuer" ? ISSUER_SCOPE : VERIFIER_SCOPE,
    },
    decisionPoint: {
      sequence: "11",
      evaluationTime: "2026-05-20T02:30:00Z",
      currentPolicy: {
        root: policyRoot,
        observedAtSequence: "11",
      },
      currentGrant: {
        authorizationId: grant.authorizationId,
        lifecycleEventRoot: grant.lifecycleEventRoot,
        status: "active",
        observedAtSequence: "11",
      },
    },
  };
  return { evidence, context };
}

describe("decision evidence supplied-context composition", () => {
  it("rejects a superseded policy even when the included grant remains active", () => {
    const { evidence, context } = fixture();
    const replacementPolicyRoot = computeGovernancePolicySnapshotCommitment({
      ...evidence.policy,
      policyId: "policy:university:v2",
      policyVersion: "v2",
    });
    for (const currentPolicy of [
      { root: replacementPolicyRoot, observedAtSequence: "11" },
      { root: context.decisionPoint.currentPolicy.root, observedAtSequence: "10" },
    ]) {
      expect(() => assertDecisionEvidenceConsistentWithSuppliedContext(evidence, {
        ...context,
        decisionPoint: { ...context.decisionPoint, currentPolicy },
      })).toThrow(/current policy mismatch/i);
    }
  });

  it("rejects a grant replaced or changed after epoch inclusion", () => {
    const { evidence, context } = fixture();
    for (const currentGrant of [
      { ...context.decisionPoint.currentGrant, authorizationId: "auth:issuer:replacement" },
      { ...context.decisionPoint.currentGrant, lifecycleEventRoot: C },
      { ...context.decisionPoint.currentGrant, status: "suspended" },
      { ...context.decisionPoint.currentGrant, observedAtSequence: "10" },
    ]) {
      expect(() => assertDecisionEvidenceConsistentWithSuppliedContext(evidence, {
        ...context,
        decisionPoint: { ...context.decisionPoint, currentGrant },
      })).toThrow(/current grant mismatch/i);
    }
  });

  it("checks the full two-signer epoch, grant, scope, DID method, and selected sequence", () => {
    const { evidence, context } = fixture();
    expect(() => assertDecisionEvidenceConsistentWithSuppliedContext(evidence, context)).not.toThrow();
  });

  it("checks an exact verifier request profile and authentication method", () => {
    const { evidence, context } = fixture("verifier");
    expect(() => assertDecisionEvidenceConsistentWithSuppliedContext(evidence, context)).not.toThrow();
    for (const supplied of [
      { ...context, selection: { ...context.selection, resourceId: `tr:request-resource:v1:${"a".repeat(64)}` } },
      { ...context, selection: { ...context.selection, networkId: "mainnet" } },
      { ...context, didState: { ...context.didState, didDocument: {
        ...context.didState.didDocument, authentication: [],
      } } },
    ]) {
      expect(() => assertDecisionEvidenceConsistentWithSuppliedContext(evidence, supplied)).toThrow();
    }
  });

  it("rejects a claimed DID state proof even when its document matches the observed key", () => {
    const { evidence, context } = fixture("verifier");
    expect(() => assertDecisionEvidenceConsistentWithSuppliedContext({
      ...evidence,
      didMethod: {
        ...evidence.didMethod,
        stateEvidence: {
          evidenceType: "state-proof",
          stateRoot: D,
          leafHash: D,
          path: [D],
          leafIndex: "0",
          blockHash: D,
        },
      },
    }, context)).toThrow(/requires a DID-ledger proof verifier/u);
  });

  it.each(["suspended", "revoked", "superseded", "archived"] as const)(
    "rejects a %s grant even with an otherwise valid two-signer epoch and inclusion proof",
    (status) => {
      const { evidence, context } = fixture("issuer", status);
      expect(() => assertDecisionEvidenceConsistentWithSuppliedContext(evidence, context))
        .toThrow(/grant is not active/u);
    },
  );

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

describe("HTTP decision-evidence consumer", () => {
  it("requires independently authenticated registry and DID readers before producing a candidate", async () => {
    const { evidence, context } = fixture();
    const readers = {
      readCurrentFinalizedRegistryDecision: vi.fn(async () => ({
        acceptedEpoch: context.acceptedEpoch,
        publication: context.publication,
        decisionPoint: context.decisionPoint,
      })),
      readCurrentFinalizedDidState: vi.fn(async () => context.didState),
    };
    const fetchImpl = vi.fn(async () => Response.json({ verification: "client-required", evidence })) as typeof fetch;
    const candidate = await verifyDecisionEvidenceFromApi(
      "https://registry.example", evidence.grant.authorizationId, context.selection, readers, fetchImpl,
    );
    expect(candidate.authorizationId).toBe(evidence.grant.authorizationId);
    expect(readers.readCurrentFinalizedRegistryDecision).toHaveBeenCalledOnce();
    expect(readers.readCurrentFinalizedDidState).toHaveBeenCalledOnce();
    expect(fetchImpl).toHaveBeenCalledWith(
      expect.objectContaining({ pathname: `/v1/decision-evidence/issuer/${encodeURIComponent(evidence.grant.authorizationId)}` }),
      { cache: "no-store" },
    );
    await expect(verifyDecisionEvidenceFromApi("https://registry.example", evidence.grant.authorizationId,
      context.selection, { ...readers, readCurrentFinalizedDidState: async () => null }, fetchImpl))
      .rejects.toThrow(/DID state is unavailable/u);
    await expect(verifyDecisionEvidenceFromApi("https://registry.example", evidence.grant.authorizationId,
      context.selection, readers, vi.fn(async () => Response.json({ verification: "verified", evidence })) as typeof fetch))
      .rejects.toThrow();
    await expect(verifyDecisionEvidenceFromApi("http://registry.example", evidence.grant.authorizationId,
      context.selection, readers, fetchImpl)).rejects.toThrow(/HTTPS or loopback/u);
    await expect(verifyDecisionEvidenceFromApi("https://registry.example", evidence.grant.authorizationId,
      { ...context.selection, role: "auditor" } as unknown as typeof context.selection, readers, fetchImpl))
      .rejects.toThrow(/Invalid decision-evidence role/u);
  });
});

describe("decision evidence trusted-reader candidate", () => {
  it("rejects a runtime active-state injection through the inactive entry point", async () => {
    const { evidence, context } = fixture();
    const readers = {
      readCurrentFinalizedRegistryDecision: vi.fn(async () => ({
        acceptedEpoch: context.acceptedEpoch,
        publication: context.publication,
        decisionPoint: context.decisionPoint,
      })),
      readCurrentFinalizedDidState: vi.fn(async () => context.didState),
    };
    await expect(verifyInactiveDecisionEvidenceWithTrustedReaders(
      evidence, context.selection, readers, "active" as "suspended",
    )).rejects.toThrow(/state is invalid/u);
    expect(readers.readCurrentFinalizedRegistryDecision).not.toHaveBeenCalled();
  });

  it.each(["issuer", "verifier"] as const)("verifies explicit inactive %s states without authorizing an active candidate", async (role) => {
    for (const state of ["suspended", "revoked"] as const) {
      const { evidence, context } = fixture(role, state);
      const current = {
        ...context,
        decisionPoint: {
          ...context.decisionPoint,
          currentGrant: { ...context.decisionPoint.currentGrant, status: state },
        },
      };
      const readers = {
        readCurrentFinalizedRegistryDecision: async () => ({
          acceptedEpoch: current.acceptedEpoch,
          publication: current.publication,
          decisionPoint: current.decisionPoint,
        }),
        readCurrentFinalizedDidState: async () => current.didState,
      };
      const candidate = await verifyInactiveDecisionEvidenceWithTrustedReaders(
        evidence, current.selection, readers, state,
      );
      expect(candidate).toMatchObject({ role, grantStatus: state, authorizationId: evidence.grant.authorizationId });
      await expect(verifyDecisionEvidenceWithTrustedReaders(evidence, current.selection, readers))
        .rejects.toThrow(/current grant mismatch/u);
      expect(() => assertInactiveDecisionEvidenceConsistentWithSuppliedContext(
        evidence, current, state === "suspended" ? "revoked" : "suspended",
      )).toThrow(/current grant mismatch/u);
      await expect(verifyInactiveDecisionEvidenceWithTrustedReaders(
        evidence, current.selection, {
          ...readers,
          readCurrentFinalizedRegistryDecision: async () => ({
            acceptedEpoch: current.acceptedEpoch,
            publication: current.publication,
            decisionPoint: {
              ...current.decisionPoint,
              currentGrant: { ...current.decisionPoint.currentGrant, lifecycleEventRoot: C },
            },
          }),
        }, state,
      )).rejects.toThrow(/current grant mismatch/u);
      await expect(verifyInactiveDecisionEvidenceWithTrustedReaders(
        evidence, current.selection, {
          ...readers,
          readCurrentFinalizedDidState: async () => ({ ...current.didState, stateVersion: "4" }),
        }, state,
      )).rejects.toThrow(/DID state anchor mismatch/u);
      const beforeTransition = {
        ...current,
        decisionPoint: { ...current.decisionPoint, evaluationTime: "2026-05-20T02:14:59Z" },
      };
      expect(() => assertInactiveDecisionEvidenceConsistentWithSuppliedContext(
        evidence, beforeTransition, state,
      )).toThrow(/claimed .* window/u);
    }
  });

  it.each(["issuer", "verifier"] as const)("returns an exact %s candidate after both authenticated reads", async (role) => {
    const { evidence, context } = fixture(role);
    const readRegistry = vi.fn(async () => ({
      acceptedEpoch: context.acceptedEpoch,
      publication: context.publication,
      decisionPoint: context.decisionPoint,
    }));
    const readDid = vi.fn(async () => context.didState);
    const candidate = await verifyDecisionEvidenceWithTrustedReaders(
      evidence,
      context.selection,
      {
        readCurrentFinalizedRegistryDecision: readRegistry,
        readCurrentFinalizedDidState: readDid,
      },
    );
    expect(readRegistry).toHaveBeenCalledWith(context.selection, evidence.epoch.epochId);
    expect(readDid).toHaveBeenCalledWith(context.selection.subjectDid, context.selection.networkId, "11");
    expect(candidate).toMatchObject({
      role,
      registryId: REGISTRY,
      authorizationId: evidence.grant.authorizationId,
      subjectDid: DID,
      resourceId: evidence.grant.resourceId,
      scope: evidence.scope,
      scopeCommitment: computeAuthorizationScopeCommitment(evidence.scope),
      policyId: evidence.policy.policyId,
      policyVersion: evidence.policy.policyVersion,
      policyRoot: evidence.epoch.policyRoot,
      decisionSequence: "11",
      evaluationTime: context.decisionPoint.evaluationTime,
      didMethod: evidence.didMethod,
      didStateVersion: "3",
      publicationEventHash: evidence.governanceEvents.epochPublication,
    });
    if (role === "issuer") {
      expect(candidate.statusPolicyBinding).toEqual(evidence.statusPolicyBinding);
    } else {
      expect(candidate).not.toHaveProperty("statusPolicyBinding");
    }
  });

  it("fails closed for unavailable or stale finalized state and does not derive anchors from the bundle", async () => {
    const { evidence, context } = fixture();
    const registry = {
      acceptedEpoch: context.acceptedEpoch,
      publication: context.publication,
      decisionPoint: context.decisionPoint,
    };
    const readDid = vi.fn(async () => context.didState);
    await expect(verifyDecisionEvidenceWithTrustedReaders(evidence, context.selection, {
      readCurrentFinalizedRegistryDecision: async () => null,
      readCurrentFinalizedDidState: readDid,
    })).rejects.toThrow(/registry decision is unavailable/u);
    expect(readDid).not.toHaveBeenCalled();
    await expect(verifyDecisionEvidenceWithTrustedReaders(evidence, context.selection, {
      readCurrentFinalizedRegistryDecision: async () => registry,
      readCurrentFinalizedDidState: async () => null,
    })).rejects.toThrow(/DID state is unavailable/u);
    for (const changed of [
      { ...registry, acceptedEpoch: { ...registry.acceptedEpoch, stateRoot: C } },
      { ...registry, decisionPoint: { ...registry.decisionPoint, sequence: "12" } },
      { ...registry, decisionPoint: {
        ...registry.decisionPoint,
        currentPolicy: { ...registry.decisionPoint.currentPolicy, root: C },
      } },
      { ...registry, decisionPoint: {
        ...registry.decisionPoint,
        currentGrant: { ...registry.decisionPoint.currentGrant, status: "suspended" },
      } },
    ]) {
      await expect(verifyDecisionEvidenceWithTrustedReaders(evidence, context.selection, {
        readCurrentFinalizedRegistryDecision: async () => changed,
        readCurrentFinalizedDidState: async () => context.didState,
      })).rejects.toThrow();
    }
    await expect(verifyDecisionEvidenceWithTrustedReaders(evidence, context.selection, {
      readCurrentFinalizedRegistryDecision: async () => registry,
      readCurrentFinalizedDidState: async () => ({ ...context.didState, stateVersion: "4" }),
    })).rejects.toThrow(/DID state anchor mismatch/u);
    await expect(verifyDecisionEvidenceWithTrustedReaders(evidence, {
      ...context.selection,
      resourceId: `tr:issuer-resource:v1:${"a".repeat(64)}`,
    }, {
      readCurrentFinalizedRegistryDecision: async () => registry,
      readCurrentFinalizedDidState: async () => context.didState,
    })).rejects.toThrow(/role or resource scope mismatch/u);
  });
});
