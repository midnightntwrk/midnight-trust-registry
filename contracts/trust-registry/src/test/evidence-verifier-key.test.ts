import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  computeCreateEvidenceVerifierKeyPayloadHash,
  computeRotateEvidenceVerifierKeyPayloadHash,
  computeUpdateEvidenceVerifierKeyPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
  signPolicyBoundMaintainerActionFromSeed,
} from "../signing.js";
import {
  createMaintainerFixture,
  labelToBytes32,
  TrustRegistrySimulator,
} from "../testing.js";
import { EvidenceVerifierKeyStatus } from "../managed/trust-registry/contract/index.js";

const REGISTER = encodeCompactActionKind("tr:evidence-verifier:register");
const SUSPEND = encodeCompactActionKind("tr:evidence-verifier:suspend");
const REVOKE = encodeCompactActionKind("tr:evidence-verifier:revoke");
const ROTATE = encodeCompactActionKind("tr:evidence-verifier:rotate");

const fixture = () => {
  const simulator = new TrustRegistrySimulator();
  const registryId = labelToBytes32("registry:evidence-test");
  const policyCommitment = labelToBytes32("policy:evidence-test");
  const maintainer = createMaintainerFixture("evidence-test", 11);
  const maintainerPublicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  simulator.initializeRegistry(
    registryId,
    labelToBytes32("did:midnight:evidence-registry"),
    policyCommitment,
    maintainer.maintainerId,
    maintainer.didCommitment,
    maintainer.keyId,
    maintainerPublicKey,
    1n,
  );
  const sign = (kind: Uint8Array, payloadHash: Uint8Array) =>
    signPolicyBoundMaintainerActionFromSeed(
      maintainer.seed,
      registryId,
      simulator.getLedger().governancePolicyCommitment,
      kind,
      payloadHash,
      simulator.getLedger().governanceActionCount,
    );
  return { simulator, registryId, policyCommitment, maintainer, maintainerPublicKey, sign };
};

const key = (label: string, seedByte: number) => {
  const seed = new Uint8Array(32).fill(seedByte);
  return {
    authorizationId: labelToBytes32(`ev-authorization:${label}`),
    didCommitment: labelToBytes32(`did:midnight:evidence-verifier:${label}`),
    keyIdCommitment: labelToBytes32(`did-key:${label}`),
    publicKey: deriveJubjubPublicKeyFromSeed(seed),
    suite: labelToBytes32("jubjub-schnorr"),
  };
};

const register = (
  registry: ReturnType<typeof fixture>,
  candidate: ReturnType<typeof key>,
  payloadOverride?: Uint8Array,
) => {
  const { simulator, maintainer, maintainerPublicKey, policyCommitment, sign } = registry;
  const payload = computeCreateEvidenceVerifierKeyPayloadHash(
    candidate.authorizationId,
    candidate.didCommitment,
    candidate.keyIdCommitment,
    candidate.publicKey,
    candidate.suite,
    policyCommitment,
    simulator.getLedger().governancePolicyVersion,
  );
  return simulator.registerEvidenceVerifierKey(
    maintainer.keyId,
    maintainerPublicKey,
    sign(REGISTER, payloadOverride ?? payload),
    candidate.authorizationId,
    candidate.didCommitment,
    candidate.keyIdCommitment,
    candidate.publicKey,
    candidate.suite,
    policyCommitment,
    simulator.getLedger().governancePolicyVersion,
  );
};

describe("governed evidence verifier keys", () => {
  it("registers one DID-bound key under the active policy and rejects duplicate scopes and keys", () => {
    const registry = fixture();
    const first = key("first", 21);
    register(registry, first);
    const record = registry.simulator.getEvidenceVerifierKey(first.authorizationId);
    expect(record.status).toBe(EvidenceVerifierKeyStatus.active);
    expect(Buffer.from(record.verifierDidCommitment)).toEqual(Buffer.from(first.didCommitment));
    expect(Buffer.from(record.keyIdCommitment)).toEqual(Buffer.from(first.keyIdCommitment));
    expect(record.policyVersion).toBe(1n);

    const sameDid = { ...key("second", 22), didCommitment: first.didCommitment };
    expect(() => register(registry, sameDid)).toThrow();
    const sameKey = { ...key("third", 23), keyIdCommitment: first.keyIdCommitment };
    expect(() => register(registry, sameKey)).toThrow();
    expect(() => register(registry, first)).toThrow();
  });

  it("rejects a stale policy and a signature over another verifier payload", () => {
    const registry = fixture();
    const candidate = key("policy", 24);
    const unrelated = key("unrelated", 25);
    const unrelatedPayload = computeCreateEvidenceVerifierKeyPayloadHash(
      unrelated.authorizationId,
      unrelated.didCommitment,
      unrelated.keyIdCommitment,
      unrelated.publicKey,
      unrelated.suite,
      registry.policyCommitment,
      1n,
    );
    expect(() => register(registry, candidate, unrelatedPayload)).toThrow();
    const wrongPolicySignature = registry.sign(
      REGISTER,
      computeCreateEvidenceVerifierKeyPayloadHash(
        candidate.authorizationId,
        candidate.didCommitment,
        candidate.keyIdCommitment,
        candidate.publicKey,
        candidate.suite,
        registry.policyCommitment,
        2n,
      ),
    );
    expect(() => registry.simulator.registerEvidenceVerifierKey(
      registry.maintainer.keyId,
      registry.maintainerPublicKey,
      wrongPolicySignature,
      candidate.authorizationId,
      candidate.didCommitment,
      candidate.keyIdCommitment,
      candidate.publicKey,
      candidate.suite,
      registry.policyCommitment,
      2n,
    )).toThrow();
    expect(registry.simulator.getLedger().governanceActionCount).toBe(1n);
  });

  it("rejects a suite without an implemented on-ledger verifier", () => {
    const registry = fixture();
    expect(() => register(registry, {
      ...key("other-suite", 30),
      suite: labelToBytes32("ed25519"),
    })).toThrow(/Jubjub Schnorr/);
  });

  it("prevents a maintainer from approving their own verifier DID", () => {
    const registry = fixture();
    const candidate = {
      ...key("self-approval", 31),
      didCommitment: registry.maintainer.didCommitment,
    };
    expect(() => register(registry, candidate)).toThrow(/own onboarding/);
    expect(registry.simulator.getLedger().governanceActionCount).toBe(1n);
  });

  it("suspends and revokes a key without allowing it to be reused", () => {
    const registry = fixture();
    const candidate = key("suspend", 26);
    register(registry, candidate);
    const reason = labelToBytes32("incident:evidence-verifier");
    const record = registry.simulator.getEvidenceVerifierKey(candidate.authorizationId);
    const suspendHash = computeUpdateEvidenceVerifierKeyPayloadHash(
      candidate.authorizationId, record.lifecycleEventHash, reason,
    );
    registry.simulator.suspendEvidenceVerifierKey(
      registry.maintainer.keyId, registry.maintainerPublicKey,
      registry.sign(SUSPEND, suspendHash), candidate.authorizationId, reason,
    );
    expect(registry.simulator.getEvidenceVerifierKey(candidate.authorizationId).status)
      .toBe(EvidenceVerifierKeyStatus.suspended);

    const replacement = key("suspended-rotation", 32);
    const proposedNewPayload = computeCreateEvidenceVerifierKeyPayloadHash(
      replacement.authorizationId,
      candidate.didCommitment,
      replacement.keyIdCommitment,
      replacement.publicKey,
      candidate.suite,
      registry.policyCommitment,
      1n,
    );
    const suspendedRecord = registry.simulator.getEvidenceVerifierKey(candidate.authorizationId);
    const rotateHash = computeRotateEvidenceVerifierKeyPayloadHash(
      candidate.authorizationId, suspendedRecord.lifecycleEventHash, proposedNewPayload, reason,
    );
    expect(() => registry.simulator.rotateEvidenceVerifierKey(
      registry.maintainer.keyId, registry.maintainerPublicKey,
      registry.sign(ROTATE, rotateHash), candidate.authorizationId,
      replacement.authorizationId, replacement.keyIdCommitment, replacement.publicKey, reason,
    )).toThrow(/active to rotate/);

    const suspended = registry.simulator.getEvidenceVerifierKey(candidate.authorizationId);
    const revokeHash = computeUpdateEvidenceVerifierKeyPayloadHash(
      candidate.authorizationId, suspended.lifecycleEventHash, reason,
    );
    registry.simulator.revokeEvidenceVerifierKey(
      registry.maintainer.keyId, registry.maintainerPublicKey,
      registry.sign(REVOKE, revokeHash), candidate.authorizationId, reason,
    );
    expect(registry.simulator.getEvidenceVerifierKey(candidate.authorizationId).status)
      .toBe(EvidenceVerifierKeyStatus.revoked);
    const reuse = { ...key("replacement", 27), keyIdCommitment: candidate.keyIdCommitment };
    expect(() => register(registry, reuse)).toThrow();
  });

  it("rotates atomically and preserves the retired key record", () => {
    const registry = fixture();
    const first = key("rotate", 28);
    register(registry, first);
    const second = key("rotate-next", 29);
    const reason = labelToBytes32("rotation:evidence-verifier");
    const oldRecord = registry.simulator.getEvidenceVerifierKey(first.authorizationId);
    const newPayload = computeCreateEvidenceVerifierKeyPayloadHash(
      second.authorizationId,
      first.didCommitment,
      second.keyIdCommitment,
      second.publicKey,
      first.suite,
      registry.policyCommitment,
      1n,
    );
    const payload = computeRotateEvidenceVerifierKeyPayloadHash(
      first.authorizationId, oldRecord.lifecycleEventHash, newPayload, reason,
    );
    registry.simulator.rotateEvidenceVerifierKey(
      registry.maintainer.keyId, registry.maintainerPublicKey,
      registry.sign(ROTATE, payload), first.authorizationId,
      second.authorizationId, second.keyIdCommitment, second.publicKey, reason,
    );
    expect(registry.simulator.getEvidenceVerifierKey(first.authorizationId).status)
      .toBe(EvidenceVerifierKeyStatus.retired);
    const current = registry.simulator.getEvidenceVerifierKey(second.authorizationId);
    expect(current.status).toBe(EvidenceVerifierKeyStatus.active);
    expect(Buffer.from(current.verifierDidCommitment)).toEqual(Buffer.from(first.didCommitment));
    expect(Buffer.from(current.predecessorAuthorizationId)).toEqual(Buffer.from(first.authorizationId));
  });
});
