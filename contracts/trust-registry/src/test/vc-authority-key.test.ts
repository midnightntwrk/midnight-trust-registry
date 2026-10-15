import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { encodeContractAddress } from "@midnight-ntwrk/compact-runtime";
import { describe, expect, it } from "vitest";

import { pureCircuits, VcAuthorityKeyStatus } from "../managed/trust-registry/contract/index.js";
import {
  computeCreateVcAuthorityKeyPayloadHash,
  computeRotateVcAuthorityKeyPayloadHash,
  computeUpdateVcAuthorityKeyPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
  signPolicyBoundMaintainerActionFromSeed,
} from "../signing.js";
import { createMaintainerFixture, labelToBytes32, TrustRegistrySimulator } from "../testing.js";

const REGISTER = encodeCompactActionKind("tr:vc-authority:key:register");
const SUSPEND = encodeCompactActionKind("tr:vc-authority:key:suspend");
const REVOKE = encodeCompactActionKind("tr:vc-authority:key:revoke");
const ROTATE = encodeCompactActionKind("tr:vc-authority:key:rotate");
const committed = (value: string): Uint8Array => new Uint8Array(createHash("sha256").update(value).digest());

const fixture = () => {
  const registryId = committed("registry:vc-authority-test");
  const policyCommitment = labelToBytes32("policy:vc-authority-test");
  const maintainer = createMaintainerFixture("vc-authority-test", 31);
  const maintainerPublicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const simulator = new TrustRegistrySimulator({
    registryId,
    registryDidCommitment: labelToBytes32("did:midnight:vc-authority-registry"),
    governancePolicyCommitment: policyCommitment,
    maintainerId: maintainer.maintainerId,
    maintainerDidCommitment: maintainer.didCommitment,
    maintainerKeyId: maintainer.keyId,
    maintainerPublicKey,
    maintainerThreshold: 1n,
  });
  return { simulator, registryId, policyCommitment, maintainer, maintainerPublicKey };
};

const candidate = (label: string, seedByte: number) => ({
  keyIdCommitment: labelToBytes32(`vc-authority:key:${label}`),
  authorityDidCommitment: committed(`did:midnight:vc-authority:${label}`),
  authorityMethodIdCommitment: committed(`did:midnight:vc-authority:${label}#key-1`),
  publicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(seedByte)),
  networkIdCommitment: committed("local"),
  consumerContractAddress: labelToBytes32("consumer:vc-proof"),
});

const register = (
  registry: ReturnType<typeof fixture>,
  key: ReturnType<typeof candidate>,
  payloadOverride?: Uint8Array,
) => {
  const { simulator, registryId, maintainer, maintainerPublicKey } = registry;
  const policy = simulator.getLedger().governancePolicyCommitment;
  const policyVersion = simulator.getLedger().governancePolicyVersion;
  const domain = pureCircuits.createVcAuthorityDomainCommitment(
    key.networkIdCommitment,
    key.consumerContractAddress,
    registryId,
    encodeContractAddress(simulator.contractAddress),
    key.authorityDidCommitment,
    key.authorityMethodIdCommitment,
  );
  const payload = computeCreateVcAuthorityKeyPayloadHash(
    key.keyIdCommitment,
    key.authorityDidCommitment,
    key.authorityMethodIdCommitment,
    key.publicKey,
    key.networkIdCommitment,
    key.consumerContractAddress,
    domain,
    policy,
    policyVersion,
  );
  const signature = signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    registryId,
    policy,
    REGISTER,
    payloadOverride ?? payload,
    simulator.getLedger().governanceActionCount,
  );
  return simulator.registerVcAuthorityKey(
    maintainer.keyId,
    maintainerPublicKey,
    signature,
    key.keyIdCommitment,
    key.authorityDidCommitment,
    key.authorityMethodIdCommitment,
    key.publicKey,
    key.networkIdCommitment,
    key.consumerContractAddress,
    policy,
    policyVersion,
  );
};

const update = (
  registry: ReturnType<typeof fixture>,
  keyIdCommitment: Uint8Array,
  kind: "suspend" | "revoke",
  reasonHash: Uint8Array,
) => {
  const { simulator, registryId, maintainer, maintainerPublicKey } = registry;
  const payload = computeUpdateVcAuthorityKeyPayloadHash(
    keyIdCommitment,
    simulator.getVcAuthorityKey(keyIdCommitment).lifecycleEventHash,
    reasonHash,
  );
  const signature = signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    registryId,
    simulator.getLedger().governancePolicyCommitment,
    kind === "suspend" ? SUSPEND : REVOKE,
    payload,
    simulator.getLedger().governanceActionCount,
  );
  return kind === "suspend"
    ? simulator.suspendVcAuthorityKey(maintainer.keyId, maintainerPublicKey, signature, keyIdCommitment, reasonHash)
    : simulator.revokeVcAuthorityKey(maintainer.keyId, maintainerPublicKey, signature, keyIdCommitment, reasonHash);
};

const rotate = (
  registry: ReturnType<typeof fixture>,
  oldKeyIdCommitment: Uint8Array,
  replacement: ReturnType<typeof candidate>,
  reasonHash: Uint8Array,
  payloadOverride?: Uint8Array,
) => {
  const { simulator, registryId, maintainer, maintainerPublicKey } = registry;
  const old = simulator.getVcAuthorityKey(oldKeyIdCommitment);
  const newDomain = pureCircuits.createVcAuthorityDomainCommitment(
    old.networkIdCommitment,
    old.consumerContractAddress,
    registryId,
    encodeContractAddress(simulator.contractAddress),
    old.authorityDidCommitment,
    replacement.authorityMethodIdCommitment,
  );
  const newCreatePayload = computeCreateVcAuthorityKeyPayloadHash(
    replacement.keyIdCommitment,
    old.authorityDidCommitment,
    replacement.authorityMethodIdCommitment,
    replacement.publicKey,
    old.networkIdCommitment,
    old.consumerContractAddress,
    newDomain,
    simulator.getLedger().governancePolicyCommitment,
    simulator.getLedger().governancePolicyVersion,
  );
  const payload = computeRotateVcAuthorityKeyPayloadHash(
    oldKeyIdCommitment,
    old.lifecycleEventHash,
    newCreatePayload,
    reasonHash,
  );
  const signature = signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    registryId,
    simulator.getLedger().governancePolicyCommitment,
    ROTATE,
    payloadOverride ?? payload,
    simulator.getLedger().governanceActionCount,
  );
  return simulator.rotateVcAuthorityKey(
    maintainer.keyId,
    maintainerPublicKey,
    signature,
    oldKeyIdCommitment,
    replacement.keyIdCommitment,
    replacement.authorityMethodIdCommitment,
    replacement.publicKey,
    reasonHash,
  );
};

describe("governed VC authority keys", () => {
  it("uses the emergency quorum for VC authority suspension and revocation", () => {
    expect(pureCircuits.actionScopedMaintainerThreshold(REGISTER, 2n, 1n, 3n)).toBe(2n);
    expect(pureCircuits.actionScopedMaintainerThreshold(SUSPEND, 2n, 1n, 3n)).toBe(1n);
    expect(pureCircuits.actionScopedMaintainerThreshold(REVOKE, 2n, 1n, 3n)).toBe(1n);
    expect(pureCircuits.actionScopedMaintainerThreshold(ROTATE, 2n, 1n, 3n)).toBe(2n);
  });

  it("registers an exact DID/method/consumer-bound key with committed event evidence", () => {
    const registry = fixture();
    const key = candidate("one", 41);
    const eventHash = register(registry, key);
    const record = registry.simulator.getVcAuthorityKey(key.keyIdCommitment);
    const current = registry.simulator.getCurrentVcAuthorityKey(key.consumerContractAddress);
    expect(current.status).toBe(VcAuthorityKeyStatus.active);
    expect(Buffer.from(current.keyIdCommitment)).toEqual(Buffer.from(key.keyIdCommitment));
    expect(Buffer.from(record.authorityDidCommitment)).toEqual(Buffer.from(key.authorityDidCommitment));
    expect(Buffer.from(record.authorityMethodIdCommitment)).toEqual(Buffer.from(key.authorityMethodIdCommitment));
    expect(Buffer.from(record.lifecycleEventHash)).toEqual(Buffer.from(eventHash));
    expect(record.policyVersion).toBe(1n);
    expect(Buffer.from(record.domainCommitment)).toEqual(Buffer.from(
      pureCircuits.createVcAuthorityDomainCommitment(
        key.networkIdCommitment,
        key.consumerContractAddress,
        registry.registryId,
        encodeContractAddress(registry.simulator.contractAddress),
        key.authorityDidCommitment,
        key.authorityMethodIdCommitment,
      ),
    ));
  });

  it("rejects reused key ids and a second live key for the same consumer", () => {
    const registry = fixture();
    const first = candidate("one", 41);
    register(registry, first);
    expect(() => register(registry, first)).toThrow();
    expect(() => register(registry, candidate("two", 42))).toThrow();
    expect(() => registry.simulator.getCurrentVcAuthorityKey(labelToBytes32("consumer:unknown"))).toThrow();
  });

  it("rejects substituted consumer/domain payload and authority self-approval", () => {
    const registry = fixture();
    const first = candidate("one", 41);
    const wrongConsumer = { ...first, consumerContractAddress: labelToBytes32("consumer:other") };
    const wrongDomain = pureCircuits.createVcAuthorityDomainCommitment(
      wrongConsumer.networkIdCommitment,
      wrongConsumer.consumerContractAddress,
      registry.registryId,
      encodeContractAddress(registry.simulator.contractAddress),
      wrongConsumer.authorityDidCommitment,
      wrongConsumer.authorityMethodIdCommitment,
    );
    const wrongPayload = computeCreateVcAuthorityKeyPayloadHash(
      wrongConsumer.keyIdCommitment,
      wrongConsumer.authorityDidCommitment,
      wrongConsumer.authorityMethodIdCommitment,
      wrongConsumer.publicKey,
      wrongConsumer.networkIdCommitment,
      wrongConsumer.consumerContractAddress,
      wrongDomain,
      registry.policyCommitment,
      1n,
    );
    expect(() => register(registry, first, wrongPayload)).toThrow();
    expect(() => register(registry, {
      ...first,
      authorityDidCommitment: registry.maintainer.didCommitment,
    })).toThrow();
  });

  it("suspends and revokes a key without erasing historical evidence, then admits a successor", () => {
    const registry = fixture();
    const first = candidate("one", 41);
    register(registry, first);
    const suspendedEvent = update(registry, first.keyIdCommitment, "suspend", labelToBytes32("reason:suspend"));
    expect(registry.simulator.getVcAuthorityKey(first.keyIdCommitment).status).toBe(VcAuthorityKeyStatus.suspended);
    expect(Buffer.from(registry.simulator.getVcAuthorityKey(first.keyIdCommitment).lifecycleEventHash))
      .toEqual(Buffer.from(suspendedEvent));
    expect(() => registry.simulator.getCurrentVcAuthorityKey(first.consumerContractAddress)).toThrow();
    expect(() => register(registry, candidate("two", 42))).toThrow();
    expect(() => update(registry, first.keyIdCommitment, "suspend", labelToBytes32("reason:again"))).toThrow();

    const revokedEvent = update(registry, first.keyIdCommitment, "revoke", labelToBytes32("reason:revoke"));
    const historical = registry.simulator.getVcAuthorityKey(first.keyIdCommitment);
    expect(historical.status).toBe(VcAuthorityKeyStatus.revoked);
    expect(Buffer.from(historical.lifecycleEventHash)).toEqual(Buffer.from(revokedEvent));
    expect(() => registry.simulator.getCurrentVcAuthorityKey(first.consumerContractAddress)).toThrow();
    expect(() => update(registry, first.keyIdCommitment, "revoke", labelToBytes32("reason:again"))).toThrow();

    const successor = candidate("two", 42);
    register(registry, successor);
    expect(Buffer.from(registry.simulator.getCurrentVcAuthorityKey(successor.consumerContractAddress).keyIdCommitment))
      .toEqual(Buffer.from(successor.keyIdCommitment));
    expect(registry.simulator.getVcAuthorityKey(first.keyIdCommitment).status).toBe(VcAuthorityKeyStatus.revoked);
  });

  it("atomically retires an active or suspended key and links the current replacement", () => {
    for (const suspendFirst of [false, true]) {
      const registry = fixture();
      const first = candidate("one", 41);
      const replacement = candidate("two", 42);
      register(registry, first);
      if (suspendFirst) update(registry, first.keyIdCommitment, "suspend", labelToBytes32("reason:suspend"));
      const eventHash = rotate(registry, first.keyIdCommitment, replacement, labelToBytes32("reason:rotate"));
      const retired = registry.simulator.getVcAuthorityKey(first.keyIdCommitment);
      const current = registry.simulator.getCurrentVcAuthorityKey(first.consumerContractAddress);
      expect(retired.status).toBe(VcAuthorityKeyStatus.retired);
      expect(retired.retiredAtSequence).toBe(current.registeredAtSequence);
      expect(Buffer.from(retired.lifecycleEventHash)).toEqual(Buffer.from(eventHash));
      expect(current.status).toBe(VcAuthorityKeyStatus.active);
      expect(Buffer.from(current.predecessorKeyIdCommitment)).toEqual(Buffer.from(first.keyIdCommitment));
      expect(Buffer.from(current.authorityDidCommitment)).toEqual(Buffer.from(first.authorityDidCommitment));
      expect(Buffer.from(current.authorityMethodIdCommitment)).toEqual(Buffer.from(replacement.authorityMethodIdCommitment));
      expect(Buffer.from(current.lifecycleEventHash)).toEqual(Buffer.from(eventHash));
      expect(() => rotate(registry, first.keyIdCommitment, candidate("three", 43), labelToBytes32("reason:again")))
        .toThrow();
    }
  });

  it("rejects a substituted rotation payload and keeps the old key current", () => {
    const registry = fixture();
    const first = candidate("one", 41);
    register(registry, first);
    const replacement = candidate("two", 42);
    expect(() => rotate(
      registry,
      first.keyIdCommitment,
      replacement,
      labelToBytes32("reason:rotate"),
      labelToBytes32("wrong:rotation-payload"),
    )).toThrow();
    expect(Buffer.from(registry.simulator.getCurrentVcAuthorityKey(first.consumerContractAddress).keyIdCommitment))
      .toEqual(Buffer.from(first.keyIdCommitment));
  });
});
