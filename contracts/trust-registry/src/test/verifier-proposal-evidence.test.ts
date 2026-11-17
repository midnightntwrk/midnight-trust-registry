import { Buffer } from "node:buffer";

import { encodeContractAddress } from "@midnight-ntwrk/compact-runtime";
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
  signDeploymentBoundMaintainerActionFromSeed,
} from "../signing.js";
import { createMaintainerFixture, labelToBytes32, TrustRegistrySimulator } from "../testing.js";
import {
  AuthorizationStatus,
  pureCircuits,
  type MaintainerAuthorizationBundle,
} from "../managed/trust-registry/contract/index.js";

const bytesEqual = (actual: Uint8Array, expected: Uint8Array) =>
  expect(Buffer.from(actual)).toEqual(Buffer.from(expected));
const FIXTURE_NETWORK_ID_COMMITMENT = labelToBytes32("network:undeployed");

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

const setup = async () => {
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
  const simulator = new TrustRegistrySimulator({
    registryId,
    networkIdCommitment: FIXTURE_NETWORK_ID_COMMITMENT,
    registryDidCommitment,
    governancePolicyCommitment: policy,
    maintainerId: maintainer.maintainerId,
    maintainerDidCommitment: maintainer.didCommitment,
    maintainerKeyId: maintainer.keyId,
    maintainerPublicKey,
    maintainerThreshold: 1n,
  });
  const sign = async (kind: string, payloadHash: Uint8Array) => {
    const state = await simulator.getLedger();
    return signDeploymentBoundMaintainerActionFromSeed(
      maintainer.seed, registryId, FIXTURE_NETWORK_ID_COMMITMENT, encodeContractAddress(simulator.contractAddress),
      state.governancePolicyCommitment,
      encodeCompactActionKind(kind), payloadHash, state.governanceActionCount,
    );
  };
  const keyPayload = computeCreateEvidenceVerifierKeyPayloadHash(
    evidenceVerifier.authorizationId, evidenceVerifier.didCommitment,
    evidenceVerifier.keyIdCommitment, evidenceVerifier.publicKey, evidenceVerifier.suite,
    policy, 1n,
  );
  await simulator.registerEvidenceVerifierKey(
    maintainer.keyId, maintainerPublicKey,
    await sign("tr:evidence-verifier:register", keyPayload),
    evidenceVerifier.authorizationId, evidenceVerifier.didCommitment,
    evidenceVerifier.keyIdCommitment, evidenceVerifier.publicKey, evidenceVerifier.suite,
    policy, 1n,
  );
  const bundle = async (kind: string, payloadHash: Uint8Array): Promise<MaintainerAuthorizationBundle> => {
    const blank = {
      keyId: new Uint8Array(32), publicKey: { x: 0n, y: 0n },
      signature: { announcement: { x: 0n, y: 0n }, response: 0n },
    };
    return {
      signerCount: 1n,
      signer1: { keyId: maintainer.keyId, publicKey: maintainerPublicKey, signature: await sign(kind, payloadHash) },
      signer2: blank, signer3: blank, signer4: blank, signer5: blank,
    };
  };
  const call = (
    fields: ReturnType<typeof proposal>,
    signerBundle: MaintainerAuthorizationBundle,
    authorizationId = evidenceVerifier.authorizationId,
    keyIdCommitment = evidenceVerifier.keyIdCommitment,
    evidenceSignature = { announcement: { x: 0n, y: 0n }, response: 0n },
  ) => simulator.runCircuit("proposeVerifierAuthorization", (context) =>
    simulator.contract.impureCircuits.proposeVerifierAuthorization(
      context, signerBundle,
      fields.authorizationId, fields.subjectDidCommitment, fields.requestResourceId,
      fields.allowedAttributeSetCommitment, fields.allowedPredicateSetCommitment,
      fields.disclosureLevelCommitment, fields.policyId, fields.trustLevel, fields.evidenceHash,
      authorizationId, keyIdCommitment, evidenceSignature,
    ));
  const proof = async (fields: ReturnType<typeof proposal>) => {
    const state = await simulator.getLedger();
    const baseHash = computeCreateVerifierAuthorizationPayloadHash(
      fields.authorizationId, fields.subjectDidCommitment, fields.requestResourceId,
      fields.allowedAttributeSetCommitment, fields.allowedPredicateSetCommitment,
      fields.disclosureLevelCommitment, fields.policyId, fields.trustLevel, fields.evidenceHash,
    );
    const boundHash = pureCircuits.verifierEvidenceBoundProposalPayloadHash(
      baseHash, evidenceVerifier.authorizationId, evidenceVerifier.keyIdCommitment,
      state.governancePolicyCommitment,
      state.governancePolicyVersion,
    );
    const digest = pureCircuits.verifierProposalEvidenceSignatureDigest(
      registryId, FIXTURE_NETWORK_ID_COMMITMENT, encodeContractAddress(simulator.contractAddress),
      evidenceVerifier.keyIdCommitment, boundHash,
    ) as JubjubDigest;
    return {
      baseHash,
      boundHash,
      evidenceSignature: signJubjubDigestFromSeed(verifierSeed, digest),
      bundle: await bundle("tr:verifier:propose", boundHash),
    };
  };
  return { simulator, registryId, policy, maintainer, evidenceVerifier, sign, bundle, call, proof };
};

describe("verifier proposal evidence binding", () => {
  it("stores an append-only verifier-specific snapshot and rejects duplicate proposals", async () => {
    const registry = await setup();
    const fields = proposal();
    const { boundHash, evidenceSignature, bundle, baseHash } = await registry.proof(fields);
    const issuerDomain = pureCircuits.issuerEvidenceBoundProposalPayloadHash(
      baseHash,
      registry.evidenceVerifier.authorizationId,
      registry.evidenceVerifier.keyIdCommitment,
      registry.policy, 1n,
    );
    expect(boundHash).not.toEqual(issuerDomain);
    await expect(registry.simulator.getVerifierProposalEvidence(fields.authorizationId))
      .rejects.toThrow(/not registered/);

    const eventHash = await registry.call(fields, bundle, undefined, undefined, evidenceSignature);
    const evidence = await registry.simulator.getVerifierProposalEvidence(fields.authorizationId);
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
    expect((await registry.simulator.getLedger()).verifierAuthorizationCount).toBe(1n);
    bytesEqual((await registry.simulator.getLedger()).lastAuthorizedActionPayloadHash, boundHash);
    await expect(registry.call(fields, await registry.bundle("tr:verifier:propose", boundHash),
      undefined, undefined, evidenceSignature))
      .rejects.toThrow(/already exists/);
    expect((await registry.simulator.getLedger()).verifierAuthorizationCount).toBe(1n);
  });

  it("rejects an unregistered or wrong verifier key, an altered full payload, and absent quorum", async () => {
    const registry = await setup();
    const fields = proposal("tamper");
    const { baseHash, boundHash, evidenceSignature, bundle } = await registry.proof(fields);
    await expect(registry.call(fields, bundle, labelToBytes32("missing-key"), undefined, evidenceSignature))
      .rejects.toThrow(/not registered/);
    await expect(registry.call(fields, bundle, undefined, labelToBytes32("wrong-key-id"), evidenceSignature))
      .rejects.toThrow(/key id does not match/);
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
      await expect(registry.call({ ...fields, ...change }, bundle, undefined, undefined, evidenceSignature))
        .rejects.toThrow(/invalid jubjub schnorr signature/i);
    }
    await expect(registry.call({ ...fields, authorizationId: labelToBytes32("other-id") }, bundle,
      undefined, undefined, evidenceSignature)).rejects.toThrow(/invalid jubjub schnorr signature/i);
    const issuerDigest = pureCircuits.issuerProposalEvidenceSignatureDigest(
      registry.registryId, FIXTURE_NETWORK_ID_COMMITMENT,
      encodeContractAddress(registry.simulator.contractAddress),
      registry.evidenceVerifier.keyIdCommitment, boundHash,
    ) as JubjubDigest;
    await expect(registry.call(fields, bundle, undefined, undefined,
      signJubjubDigestFromSeed(new Uint8Array(32).fill(45), issuerDigest)))
      .rejects.toThrow(/invalid jubjub schnorr signature/i);
    await expect(registry.call(fields, await registry.bundle("tr:verifier:propose", baseHash),
      undefined, undefined, evidenceSignature)).rejects.toThrow(/invalid jubjub schnorr signature/i);
    await expect(registry.call(fields, { ...bundle, signerCount: 0n },
      undefined, undefined, evidenceSignature)).rejects.toThrow(/threshold/);
    expect((await registry.simulator.getLedger()).verifierAuthorizationCount).toBe(0n);
    expect((await registry.simulator.getLedger()).governanceActionCount).toBe(2n);
  });

  it("authorizes and activates while retaining the original proposal evidence", async () => {
    const registry = await setup();
    const fields = proposal("active-lifecycle");
    const { bundle, evidenceSignature } = await registry.proof(fields);
    const proposalEvent = await registry.call(
      fields, bundle, undefined, undefined, evidenceSignature,
    );
    const authorizeRecord = await registry.simulator.getVerifierAuthorization(fields.authorizationId);
    const authorizeHash = computeUpdateVerifierAuthorizationPayloadHash(
      fields.authorizationId, authorizeRecord.lifecycleEventHash, fields.evidenceHash,
    );
    const authorizationBundle = await registry.bundle("tr:verifier:authorize", authorizeHash);
    await registry.simulator.runCircuit("authorizeVerifierAuthorization", (context) =>
      registry.simulator.contract.impureCircuits.authorizeVerifierAuthorization(
        context,
        authorizationBundle,
        fields.authorizationId, fields.evidenceHash,
      ));
    const activateRecord = await registry.simulator.getVerifierAuthorization(fields.authorizationId);
    const activateHash = computeUpdateVerifierAuthorizationPayloadHash(
      fields.authorizationId, activateRecord.lifecycleEventHash, fields.evidenceHash,
    );
    const activationBundle = await registry.bundle("tr:verifier:activate", activateHash);
    await registry.simulator.runCircuit("activateVerifierAuthorization", (context) =>
      registry.simulator.contract.impureCircuits.activateVerifierAuthorization(
        context,
        activationBundle,
        fields.authorizationId, fields.evidenceHash,
      ));
    expect((await registry.simulator.getVerifierAuthorization(fields.authorizationId)).status)
      .toBe(AuthorizationStatus.active);
    bytesEqual((await registry.simulator.getVerifierProposalEvidence(fields.authorizationId)).proposalGovernanceEventHash,
      proposalEvent);
  });

  it("rejects inactive keys and stale-policy approvals while preserving proposal evidence", async () => {
    const registry = await setup();
    const fields = proposal("lifecycle");
    const { bundle, evidenceSignature } = await registry.proof(fields);
    await registry.call(fields, bundle, undefined, undefined, evidenceSignature);
    const initialEvent = (await registry.simulator.getLedger()).lastGovernanceEventHash;
    const record = await registry.simulator.getVerifierAuthorization(fields.authorizationId);
    const authorizeHash = computeUpdateVerifierAuthorizationPayloadHash(
      fields.authorizationId, record.lifecycleEventHash, fields.evidenceHash,
    );
    const authorizationBundle = await registry.bundle("tr:verifier:authorize", authorizeHash);
    const authorize = () => registry.simulator.runCircuit("authorizeVerifierAuthorization", (context) =>
      registry.simulator.contract.impureCircuits.authorizeVerifierAuthorization(
        context,
        authorizationBundle,
        fields.authorizationId, fields.evidenceHash,
      ));
    const newPolicy = labelToBytes32("policy:verifier-evidence:second");
    const policyHash = computeUpdateMaintainerThresholdPolicyPayloadHash(
      registry.policy, newPolicy, 2n, 1n, 1n, 1n,
    );
    await registry.simulator.updateMaintainerThresholdPolicy(
      registry.maintainer.keyId,
      deriveJubjubPublicKeyFromSeed(registry.maintainer.seed),
      await registry.sign("tr:policy:thresholds:update", policyHash),
      newPolicy, 2n, 1n, 1n, 1n,
    );
    await expect(authorize()).rejects.toThrow(/proposal evidence policy is not current/);
    const preserved = await registry.simulator.getVerifierProposalEvidence(fields.authorizationId);
    bytesEqual(preserved.proposalGovernanceEventHash, initialEvent);
    expect((await registry.simulator.getVerifierAuthorization(fields.authorizationId)).status)
      .toBe(AuthorizationStatus.proposed);
  });

  it("rejects a suspended verifier key before proposal", async () => {
    const registry = await setup();
    const fields = proposal("inactive");
    const { bundle, evidenceSignature } = await registry.proof(fields);
    const keyRecord = await registry.simulator.getEvidenceVerifierKey(registry.evidenceVerifier.authorizationId);
    const reason = labelToBytes32("incident:verifier-proposal");
    const suspendHash = computeUpdateEvidenceVerifierKeyPayloadHash(
      registry.evidenceVerifier.authorizationId, keyRecord.lifecycleEventHash, reason,
    );
    await registry.simulator.suspendEvidenceVerifierKey(
      registry.maintainer.keyId, deriveJubjubPublicKeyFromSeed(registry.maintainer.seed),
      await registry.sign("tr:evidence-verifier:suspend", suspendHash),
      registry.evidenceVerifier.authorizationId, reason,
    );
    await expect(registry.call(fields, bundle, undefined, undefined, evidenceSignature))
      .rejects.toThrow(/key is not active/);
  });

  it("rejects proposal signatures after the registered key policy becomes stale", async () => {
    const registry = await setup();
    const fields = proposal("stale-at-proposal");
    const { bundle, evidenceSignature } = await registry.proof(fields);
    const newPolicy = labelToBytes32("policy:verifier-evidence:new");
    const policyHash = computeUpdateMaintainerThresholdPolicyPayloadHash(
      registry.policy, newPolicy, 2n, 1n, 1n, 1n,
    );
    await registry.simulator.updateMaintainerThresholdPolicy(
      registry.maintainer.keyId,
      deriveJubjubPublicKeyFromSeed(registry.maintainer.seed),
      await registry.sign("tr:policy:thresholds:update", policyHash),
      newPolicy, 2n, 1n, 1n, 1n,
    );
    await expect(registry.call(fields, bundle, undefined, undefined, evidenceSignature))
      .rejects.toThrow(/key policy is not current/);
    expect((await registry.simulator.getLedger()).verifierAuthorizationCount).toBe(0n);
  });
});
