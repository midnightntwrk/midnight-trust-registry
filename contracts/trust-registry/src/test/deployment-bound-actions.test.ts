import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
  signDeploymentBoundMaintainerActionFromSeed,
} from "../signing.js";
import {
  createMaintainerFixture,
  labelToBytes32,
  TrustRegistrySimulator,
} from "../testing.js";

const bootstrap = (networkIdCommitment: Uint8Array, contractAddress?: string) => {
  const maintainer = createMaintainerFixture("bootstrap", 19);
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const registryId = labelToBytes32("registry:replay-test");
  const simulator = new TrustRegistrySimulator({
    registryId,
    networkIdCommitment,
    ...(contractAddress === undefined ? {} : { contractAddress }),
    registryDidCommitment: labelToBytes32("did:midnight:replay-test"),
    governancePolicyCommitment: labelToBytes32("policy:replay-test"),
    maintainerId: maintainer.maintainerId,
    maintainerDidCommitment: maintainer.didCommitment,
    maintainerKeyId: maintainer.keyId,
    maintainerPublicKey: publicKey,
    maintainerThreshold: 1n,
  });
  return { maintainer, publicKey, registryId, simulator };
};

const signAudit = async (source: ReturnType<typeof bootstrap>, payloadHash: Uint8Array) => {
  const state = await source.simulator.getLedger();
  return signDeploymentBoundMaintainerActionFromSeed(
    source.maintainer.seed,
    source.registryId,
    state.deploymentNetworkIdCommitment,
    Buffer.from(source.simulator.contractAddress, "hex"),
    state.governancePolicyCommitment,
    encodeCompactActionKind("tr:audit:generic"),
    payloadHash,
    state.governanceActionCount,
  );
};

describe("deployment-bound governed actions", () => {
  it("rejects a vote replayed at another contract address", async () => {
    const network = labelToBytes32("network:replay-test");
    const source = bootstrap(network);
    const target = bootstrap(network);
    expect(source.simulator.contractAddress).not.toBe(target.simulator.contractAddress);

    const payload = labelToBytes32("audit:replay-test");
    const signature = await signAudit(source, payload);
    const targetActionCount = (await target.simulator.getLedger()).governanceActionCount;
    const sourceActionCount = (await source.simulator.getLedger()).governanceActionCount;
    await expect(target.simulator.authorizeMaintainerAuditEvent(
      target.maintainer.keyId, target.publicKey, signature, payload,
    )).rejects.toThrow();
    expect((await target.simulator.getLedger()).governanceActionCount).toBe(targetActionCount);

    expect(await source.simulator.authorizeMaintainerAuditEvent(
      source.maintainer.keyId, source.publicKey, signature, payload,
    )).toHaveLength(32);
    expect((await source.simulator.getLedger()).governanceActionCount).toBe(sourceActionCount + 1n);
  });

  it("rejects a vote signed for another pinned network", async () => {
    const contractAddress = Buffer.from(labelToBytes32("contract:shared")).toString("hex");
    const source = bootstrap(labelToBytes32("network:source"), contractAddress);
    const target = bootstrap(labelToBytes32("network:target"), contractAddress);
    expect(source.simulator.contractAddress).toBe(target.simulator.contractAddress);
    const payload = labelToBytes32("audit:network-replay-test");
    const signature = await signAudit(source, payload);
    const targetActionCount = (await target.simulator.getLedger()).governanceActionCount;
    const sourceActionCount = (await source.simulator.getLedger()).governanceActionCount;

    await expect(target.simulator.authorizeMaintainerAuditEvent(
      target.maintainer.keyId, target.publicKey, signature, payload,
    )).rejects.toThrow();
    expect((await target.simulator.getLedger()).governanceActionCount).toBe(targetActionCount);
    expect(await source.simulator.authorizeMaintainerAuditEvent(
      source.maintainer.keyId, source.publicKey, signature, payload,
    )).toHaveLength(32);
    expect((await source.simulator.getLedger()).governanceActionCount).toBe(sourceActionCount + 1n);
  });

  it("rejects a stale same-deployment vote after another action consumes its sequence", async () => {
    const source = bootstrap(labelToBytes32("network:sequence-replay-test"));
    const stalePayload = labelToBytes32("audit:reserved-before-other-action");
    const otherPayload = labelToBytes32("audit:other-finalized-action");
    const staleSignature = await signAudit(source, stalePayload);
    const otherSignature = await signAudit(source, otherPayload);
    const reservedSequence = (await source.simulator.getLedger()).governanceActionCount;

    await source.simulator.authorizeMaintainerAuditEvent(
      source.maintainer.keyId, source.publicKey, otherSignature, otherPayload,
    );
    expect((await source.simulator.getLedger()).governanceActionCount).toBe(reservedSequence + 1n);
    await expect(source.simulator.authorizeMaintainerAuditEvent(
      source.maintainer.keyId, source.publicKey, staleSignature, stalePayload,
    )).rejects.toThrow();
    expect((await source.simulator.getLedger()).governanceActionCount).toBe(reservedSequence + 1n);
  });

  it("serializes simultaneous votes against one action sequence", async () => {
    const source = bootstrap(labelToBytes32("network:concurrent-vote-test"));
    const payload = labelToBytes32("audit:concurrent-vote-test");
    const signature = await signAudit(source, payload);
    const sequence = (await source.simulator.getLedger()).governanceActionCount;
    const first = source.simulator.authorizeMaintainerAuditEvent(
      source.maintainer.keyId, source.publicKey, signature, payload,
    );
    const second = source.simulator.authorizeMaintainerAuditEvent(
      source.maintainer.keyId, source.publicKey, signature, payload,
    );
    expect(await first).toHaveLength(32);
    await expect(second).rejects.toThrow();
    expect((await source.simulator.getLedger()).governanceActionCount).toBe(sequence + 1n);
  });
});
