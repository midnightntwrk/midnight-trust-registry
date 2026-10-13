import { Buffer } from "node:buffer";

import { createCircuitContext, sampleContractAddress, type CircuitResults } from "@midnight-ntwrk/compact-runtime";
import { signJubjubDigestFromSeed, type JubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { describe, expect, it } from "vitest";

import {
  computeCreateEvidenceVerifierKeyPayloadHash,
  computeCreateVerifierAuthorizationPayloadHash,
  computeUpdateEvidenceVerifierKeyPayloadHash,
  computeUpdateMaintainerThresholdPolicyPayloadHash,
  computeUpdateVerifierAuthorizationPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
  signPolicyBoundMaintainerActionFromSeed,
} from "../signing.js";
import { createMaintainerFixture, labelToBytes32, TrustRegistrySimulator } from "../testing.js";
import {
  AuthorizationStatus,
  pureCircuits,
  type MaintainerAuthorizationBundle,
} from "../managed/trust-registry/contract/index.js";
import { type TrustRegistryPrivateState } from "../witnesses.js";

const bytesEqual = (actual: Uint8Array, expected: Uint8Array) =>
  expect(Buffer.from(actual)).toEqual(Buffer.from(expected));

const proposal = (label = "first") => ({
  authorizationId: labelToBytes32(`verifier-authorization:${label}`),
  subjectDidCommitment: labelToBytes32(`did:midnight:requester:${label}`),
  requestResourceId: labelToBytes32(`request-resource:${label}`),
  allowedAttributeSetCommitment: labelToBytes32(`attributes:${label}`),
  allowedPredicateSetCommitment: labelToBytes32(`predicates:${label}`),
  disclosureLevelCommitment: labelToBytes32(`disclosure:${label}`),
  policyId: labelToBytes32(`policy-id:${label}`),
  trustLevel: labelToBytes32("approved"),
  evidenceHash: labelToBytes32(`evidence:${label}`),
});

const setup = () => {
  const simulator = new TrustRegistrySimulator();
  const registryId = labelToBytes32("registry:verifier-proposal-evidence");
  const registryDidCommitment = labelToBytes32("did:midnight:verifier-proposal-registry");
  const policy = labelToBytes32("policy:verifier-evidence:first");
  const maintainer = createMaintainerFixture("verifier-proposal", 44);
  const maintainerPublicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const verifierSeed = new Uint8Array(32).fill(45);
  const evidenceVerifier = {
    authorizationId: labelToBytes32("evidence-verifier:verifier-proposal"),
    didCommitment: labelToBytes32("did:midnight:evidence-verifier:verifier-proposal"),
    keyIdCommitment: labelToBytes32("evidence-verifier-key:verifier-proposal"),
    publicKey: deriveJubjubPublicKeyFromSeed(verifierSeed),
    suite: labelToBytes32("jubjub-schnorr"),
  };
  simulator.initializeRegistry(
    registryId, registryDidCommitment, policy, maintainer.maintainerId,
    maintainer.didCommitment, maintainer.keyId, maintainerPublicKey, 1n,
  );
  const sign = (kind: string, payloadHash: Uint8Array) => signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed, registryId, simulator.getLedger().governancePolicyCommitment,
    encodeCompactActionKind(kind), payloadHash, simulator.getLedger().governanceActionCount,
  );
  const keyPayload = computeCreateEvidenceVerifierKeyPayloadHash(
    evidenceVerifier.authorizationId, evidenceVerifier.didCommitment,
    evidenceVerifier.keyIdCommitment, evidenceVerifier.publicKey, evidenceVerifier.suite,
    policy, 1n,
  );
  simulator.registerEvidenceVerifierKey(
    maintainer.keyId, maintainerPublicKey,
    sign("tr:evidence-verifier:register", keyPayload),
    evidenceVerifier.authorizationId, evidenceVerifier.didCommitment,
    evidenceVerifier.keyIdCommitment, evidenceVerifier.publicKey, evidenceVerifier.suite,
    policy, 1n,
  );
  const bundle = (kind: string, payloadHash: Uint8Array): MaintainerAuthorizationBundle => {
    const blank = {
      keyId: new Uint8Array(32), publicKey: { x: 0n, y: 0n },
      signature: { announcement: { x: 0n, y: 0n }, response: 0n },
    };
    return {
      signerCount: 1n,
      signer1: { keyId: maintainer.keyId, publicKey: maintainerPublicKey, signature: sign(kind, payloadHash) },
      signer2: blank, signer3: blank, signer4: blank, signer5: blank,
    };
  };
  const commit = <T>(result: CircuitResults<TrustRegistryPrivateState, T>): T => {
    simulator.circuitContext = createCircuitContext(
      sampleContractAddress(),
      result.context.currentZswapLocalState,
      result.context.currentQueryContext.state,
      result.context.currentPrivateState,
    );
    return result.result;
  };
  const call = (
    fields: ReturnType<typeof proposal>,
    signerBundle: MaintainerAuthorizationBundle,
    authorizationId = evidenceVerifier.authorizationId,
    keyIdCommitment = evidenceVerifier.keyIdCommitment,
    evidenceSignature = { announcement: { x: 0n, y: 0n }, response: 0n },
  ) => simulator.contract.impureCircuits.proposeVerifierAuthorization(
    simulator.circuitContext, signerBundle,
    fields.authorizationId, fields.subjectDidCommitment, fields.requestResourceId,
    fields.allowedAttributeSetCommitment, fields.allowedPredicateSetCommitment,
    fields.disclosureLevelCommitment, fields.policyId, fields.trustLevel, fields.evidenceHash,
    authorizationId, keyIdCommitment, evidenceSignature,
  );
  const proof = (fields: ReturnType<typeof proposal>) => {
    const baseHash = computeCreateVerifierAuthorizationPayloadHash(
      fields.authorizationId, fields.subjectDidCommitment, fields.requestResourceId,
      fields.allowedAttributeSetCommitment, fields.allowedPredicateSetCommitment,
      fields.disclosureLevelCommitment, fields.policyId, fields.trustLevel, fields.evidenceHash,
    );
    const boundHash = pureCircuits.verifierEvidenceBoundProposalPayloadHash(
      baseHash, evidenceVerifier.authorizationId, evidenceVerifier.keyIdCommitment,
      simulator.getLedger().governancePolicyCommitment,
      simulator.getLedger().governancePolicyVersion,
    );
    const digest = pureCircuits.verifierProposalEvidenceSignatureDigest(
      registryId, evidenceVerifier.keyIdCommitment, boundHash,
    ) as JubjubDigest;
    return {
      baseHash,
      boundHash,
      evidenceSignature: signJubjubDigestFromSeed(verifierSeed, digest),
      bundle: bundle("tr:verifier:propose", boundHash),
    };
  };
  return { simulator, registryId, policy, maintainer, evidenceVerifier, sign, bundle, call, commit, proof };
};

describe("verifier proposal evidence binding", () => {
  it("stores an append-only verifier-specific snapshot and rejects duplicate proposals", () => {
    const registry = setup();
    const fields = proposal();
    const { boundHash, evidenceSignature, bundle } = registry.proof(fields);
    const issuerDomain = pureCircuits.issuerEvidenceBoundProposalPayloadHash(
      registry.proof(fields).baseHash,
      registry.evidenceVerifier.authorizationId,
      registry.evidenceVerifier.keyIdCommitment,
      registry.policy, 1n,
    );
    expect(boundHash).not.toEqual(issuerDomain);
    expect(() => registry.simulator.contract.impureCircuits.getVerifierProposalEvidence(
      registry.simulator.circuitContext, fields.authorizationId,
    )).toThrow(/not registered/);

    const eventHash = registry.commit(registry.call(fields, bundle, undefined, undefined, evidenceSignature));
    const evidence = registry.simulator.contract.impureCircuits.getVerifierProposalEvidence(
      registry.simulator.circuitContext, fields.authorizationId,
    ).result;
    bytesEqual(evidence.evidenceVerifierAuthorizationId, registry.evidenceVerifier.authorizationId);
    bytesEqual(evidence.evidenceVerifierDidCommitment, registry.evidenceVerifier.didCommitment);
    bytesEqual(evidence.evidenceVerifierKeyIdCommitment, registry.evidenceVerifier.keyIdCommitment);
    bytesEqual(evidence.evidenceVerifierSuite, registry.evidenceVerifier.suite);
    bytesEqual(evidence.activePolicyCommitment, registry.policy);
    expect(evidence.activePolicyVersion).toBe(1n);
    bytesEqual(evidence.evidenceCommitment, fields.evidenceHash);
    expect(evidence.verifierSignatureAnnouncement).toEqual(evidenceSignature.announcement);
    expect(evidence.verifierSignatureResponse).toBe(evidenceSignature.response);
    bytesEqual(evidence.proposalGovernanceEventHash, eventHash);
    expect(registry.simulator.getLedger().verifierAuthorizationCount).toBe(1n);
    bytesEqual(registry.simulator.getLedger().lastAuthorizedActionPayloadHash, boundHash);
    expect(() => registry.call(fields, registry.bundle("tr:verifier:propose", boundHash),
      undefined, undefined, evidenceSignature))
      .toThrow(/already exists/);
    expect(registry.simulator.getLedger().verifierAuthorizationCount).toBe(1n);
  });

  it("rejects an unregistered or wrong verifier key, an altered full payload, and absent quorum", () => {
    const registry = setup();
    const fields = proposal("tamper");
    const { baseHash, boundHash, evidenceSignature, bundle } = registry.proof(fields);
    expect(() => registry.call(fields, bundle, labelToBytes32("missing-key"), undefined, evidenceSignature))
      .toThrow(/not registered/);
    expect(() => registry.call(fields, bundle, undefined, labelToBytes32("wrong-key-id"), evidenceSignature))
      .toThrow(/key id does not match/);
    for (const change of [
      { subjectDidCommitment: labelToBytes32("did:midnight:other-subject") },
      { requestResourceId: labelToBytes32("request:other") },
      { allowedAttributeSetCommitment: labelToBytes32("attributes:other") },
      { allowedPredicateSetCommitment: labelToBytes32("predicates:other") },
      { disclosureLevelCommitment: labelToBytes32("disclosure:other") },
      { policyId: labelToBytes32("policy:other") },
      { trustLevel: labelToBytes32("trust:other") },
      { evidenceHash: labelToBytes32("evidence:other") },
    ]) {
      expect(() => registry.call({ ...fields, ...change }, bundle, undefined, undefined, evidenceSignature))
        .toThrow(/invalid jubjub schnorr signature/i);
    }
    expect(() => registry.call({ ...fields, authorizationId: labelToBytes32("other-id") }, bundle,
      undefined, undefined, evidenceSignature)).toThrow(/invalid jubjub schnorr signature/i);
    const issuerDigest = pureCircuits.issuerProposalEvidenceSignatureDigest(
      registry.registryId, registry.evidenceVerifier.keyIdCommitment, boundHash,
    ) as JubjubDigest;
    expect(() => registry.call(fields, bundle, undefined, undefined,
      signJubjubDigestFromSeed(new Uint8Array(32).fill(45), issuerDigest)))
      .toThrow(/invalid jubjub schnorr signature/i);
    expect(() => registry.call(fields, registry.bundle("tr:verifier:propose", baseHash),
      undefined, undefined, evidenceSignature)).toThrow(/invalid jubjub schnorr signature/i);
    expect(() => registry.call(fields, { ...bundle, signerCount: 0n },
      undefined, undefined, evidenceSignature)).toThrow(/threshold/);
    expect(registry.simulator.getLedger().verifierAuthorizationCount).toBe(0n);
    expect(registry.simulator.getLedger().governanceActionCount).toBe(2n);
  });

  it("authorizes and activates while retaining the original proposal evidence", () => {
    const registry = setup();
    const fields = proposal("active-lifecycle");
    const { bundle, evidenceSignature } = registry.proof(fields);
    const proposalEvent = registry.commit(registry.call(
      fields, bundle, undefined, undefined, evidenceSignature,
    ));
    const authorizeRecord = registry.simulator.contract.impureCircuits.getVerifierAuthorization(
      registry.simulator.circuitContext, fields.authorizationId,
    ).result;
    const authorizeHash = computeUpdateVerifierAuthorizationPayloadHash(
      fields.authorizationId, authorizeRecord.lifecycleEventHash, fields.evidenceHash,
    );
    registry.commit(registry.simulator.contract.impureCircuits.authorizeVerifierAuthorization(
      registry.simulator.circuitContext,
      registry.bundle("tr:verifier:authorize", authorizeHash),
      fields.authorizationId, fields.evidenceHash,
    ));
    const activateRecord = registry.simulator.contract.impureCircuits.getVerifierAuthorization(
      registry.simulator.circuitContext, fields.authorizationId,
    ).result;
    const activateHash = computeUpdateVerifierAuthorizationPayloadHash(
      fields.authorizationId, activateRecord.lifecycleEventHash, fields.evidenceHash,
    );
    registry.commit(registry.simulator.contract.impureCircuits.activateVerifierAuthorization(
      registry.simulator.circuitContext,
      registry.bundle("tr:verifier:activate", activateHash),
      fields.authorizationId, fields.evidenceHash,
    ));
    expect(registry.simulator.contract.impureCircuits.getVerifierAuthorization(
      registry.simulator.circuitContext, fields.authorizationId,
    ).result.status).toBe(AuthorizationStatus.active);
    bytesEqual(registry.simulator.contract.impureCircuits.getVerifierProposalEvidence(
      registry.simulator.circuitContext, fields.authorizationId,
    ).result.proposalGovernanceEventHash, proposalEvent);
  });

  it("rejects inactive keys and stale-policy approvals while preserving proposal evidence", () => {
    const registry = setup();
    const fields = proposal("lifecycle");
    const { bundle, evidenceSignature } = registry.proof(fields);
    registry.commit(registry.call(fields, bundle, undefined, undefined, evidenceSignature));
    const initialEvent = registry.simulator.getLedger().lastGovernanceEventHash;
    const record = registry.simulator.contract.impureCircuits.getVerifierAuthorization(
      registry.simulator.circuitContext, fields.authorizationId,
    ).result;
    const authorizeHash = computeUpdateVerifierAuthorizationPayloadHash(
      fields.authorizationId, record.lifecycleEventHash, fields.evidenceHash,
    );
    const authorize = () => registry.simulator.contract.impureCircuits.authorizeVerifierAuthorization(
      registry.simulator.circuitContext,
      registry.bundle("tr:verifier:authorize", authorizeHash),
      fields.authorizationId, fields.evidenceHash,
    );
    const newPolicy = labelToBytes32("policy:verifier-evidence:second");
    const policyHash = computeUpdateMaintainerThresholdPolicyPayloadHash(
      registry.policy, newPolicy, 2n, 1n, 1n, 1n,
    );
    registry.simulator.updateMaintainerThresholdPolicy(
      registry.maintainer.keyId,
      deriveJubjubPublicKeyFromSeed(registry.maintainer.seed),
      registry.sign("tr:policy:thresholds:update", policyHash),
      newPolicy, 2n, 1n, 1n, 1n,
    );
    expect(() => authorize()).toThrow(/proposal evidence policy is not current/);
    const preserved = registry.simulator.contract.impureCircuits.getVerifierProposalEvidence(
      registry.simulator.circuitContext, fields.authorizationId,
    ).result;
    bytesEqual(preserved.proposalGovernanceEventHash, initialEvent);
    expect(registry.simulator.contract.impureCircuits.getVerifierAuthorization(
      registry.simulator.circuitContext, fields.authorizationId,
    ).result.status).toBe(AuthorizationStatus.proposed);
  });

  it("rejects a suspended verifier key before proposal", () => {
    const registry = setup();
    const fields = proposal("inactive");
    const { bundle, evidenceSignature } = registry.proof(fields);
    const keyRecord = registry.simulator.getEvidenceVerifierKey(registry.evidenceVerifier.authorizationId);
    const reason = labelToBytes32("incident:verifier-proposal");
    const suspendHash = computeUpdateEvidenceVerifierKeyPayloadHash(
      registry.evidenceVerifier.authorizationId, keyRecord.lifecycleEventHash, reason,
    );
    registry.simulator.suspendEvidenceVerifierKey(
      registry.maintainer.keyId, deriveJubjubPublicKeyFromSeed(registry.maintainer.seed),
      registry.sign("tr:evidence-verifier:suspend", suspendHash),
      registry.evidenceVerifier.authorizationId, reason,
    );
    expect(() => registry.call(fields, bundle, undefined, undefined, evidenceSignature))
      .toThrow(/key is not active/);
  });

  it("rejects proposal signatures after the registered key policy becomes stale", () => {
    const registry = setup();
    const fields = proposal("stale-at-proposal");
    const { bundle, evidenceSignature } = registry.proof(fields);
    const newPolicy = labelToBytes32("policy:verifier-evidence:new");
    const policyHash = computeUpdateMaintainerThresholdPolicyPayloadHash(
      registry.policy, newPolicy, 2n, 1n, 1n, 1n,
    );
    registry.simulator.updateMaintainerThresholdPolicy(
      registry.maintainer.keyId,
      deriveJubjubPublicKeyFromSeed(registry.maintainer.seed),
      registry.sign("tr:policy:thresholds:update", policyHash),
      newPolicy, 2n, 1n, 1n, 1n,
    );
    expect(() => registry.call(fields, bundle, undefined, undefined, evidenceSignature))
      .toThrow(/key policy is not current/);
    expect(registry.simulator.getLedger().verifierAuthorizationCount).toBe(0n);
  });
});
