import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { encodeContractAddress } from "@midnight-ntwrk/compact-runtime";
import { describe, expect, it } from "vitest";

import { pureCircuits, VcAuthorityKeyStatus } from "../managed/trust-registry/contract/index.js";
import {
  computeCreateVcAuthorityKeyPayloadHash,
  computeUpdateVcAuthorityKeyPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
  signPolicyBoundMaintainerActionFromSeed,
} from "../signing.js";
import { createMaintainerFixture, labelToBytes32, TrustRegistrySimulator } from "../testing.js";

const REGISTER = encodeCompactActionKind("tr:vc-authority:key:register");
const SUSPEND = encodeCompactActionKind("tr:vc-authority:key:suspend");
const REVOKE = encodeCompactActionKind("tr:vc-authority:key:revoke");
const committed = (value: string): Uint8Array => new Uint8Array(createHash("sha256").update(value).digest());

const fixture = () => {
  const simulator = new TrustRegistrySimulator();
  const registryId = committed("registry:vc-authority-test");
  const policyCommitment = labelToBytes32("policy:vc-authority-test");
  const maintainer = createMaintainerFixture("vc-authority-test", 31);
  const maintainerPublicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  simulator.initializeRegistry(
    registryId,
    labelToBytes32("did:midnight:vc-authority-registry"),
    policyCommitment,
    maintainer.maintainerId,
    maintainer.didCommitment,
    maintainer.keyId,
    maintainerPublicKey,
    1n,
  );
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

describe("governed VC authority keys", () => {
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
});
