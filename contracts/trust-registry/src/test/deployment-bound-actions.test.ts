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

const signAudit = (source: ReturnType<typeof bootstrap>, payloadHash: Uint8Array) =>
  signDeploymentBoundMaintainerActionFromSeed(
    source.maintainer.seed,
    source.registryId,
    source.simulator.getLedger().deploymentNetworkIdCommitment,
    Buffer.from(source.simulator.contractAddress, "hex"),
    source.simulator.getLedger().governancePolicyCommitment,
    encodeCompactActionKind("tr:audit:generic"),
    payloadHash,
    source.simulator.getLedger().governanceActionCount,
  );

describe("deployment-bound governed actions", () => {
  it("rejects a vote replayed at another contract address", () => {
    const network = labelToBytes32("network:replay-test");
    const source = bootstrap(network);
    const target = bootstrap(network);
    expect(source.simulator.contractAddress).not.toBe(target.simulator.contractAddress);

    const payload = labelToBytes32("audit:replay-test");
    const signature = signAudit(source, payload);
    const targetActionCount = target.simulator.getLedger().governanceActionCount;
    const sourceActionCount = source.simulator.getLedger().governanceActionCount;
    expect(() => target.simulator.authorizeMaintainerAuditEvent(
      target.maintainer.keyId, target.publicKey, signature, payload,
    )).toThrow();
    expect(target.simulator.getLedger().governanceActionCount).toBe(targetActionCount);

    expect(source.simulator.authorizeMaintainerAuditEvent(
      source.maintainer.keyId, source.publicKey, signature, payload,
    )).toHaveLength(32);
    expect(source.simulator.getLedger().governanceActionCount).toBe(sourceActionCount + 1n);
  });

  it("rejects a vote signed for another pinned network", () => {
    const contractAddress = Buffer.from(labelToBytes32("contract:shared")).toString("hex");
    const source = bootstrap(labelToBytes32("network:source"), contractAddress);
    const target = bootstrap(labelToBytes32("network:target"), contractAddress);
    expect(source.simulator.contractAddress).toBe(target.simulator.contractAddress);
    const payload = labelToBytes32("audit:network-replay-test");
    const signature = signAudit(source, payload);
    const targetActionCount = target.simulator.getLedger().governanceActionCount;
    const sourceActionCount = source.simulator.getLedger().governanceActionCount;

    expect(() => target.simulator.authorizeMaintainerAuditEvent(
      target.maintainer.keyId, target.publicKey, signature, payload,
    )).toThrow();
    expect(target.simulator.getLedger().governanceActionCount).toBe(targetActionCount);
    expect(source.simulator.authorizeMaintainerAuditEvent(
      source.maintainer.keyId, source.publicKey, signature, payload,
    )).toHaveLength(32);
    expect(source.simulator.getLedger().governanceActionCount).toBe(sourceActionCount + 1n);
  });
});
