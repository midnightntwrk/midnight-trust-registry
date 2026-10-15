import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { createMaintainerFixture } from "@midnight-ntwrk/trust-registry-contract/testing";
import { createDemoSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import { bytes32Commitment, LocalTrustRegistryIntegrationHarness } from "@midnight-ntwrk/trust-registry-integration";

import { type PreparedGovernedEpochPublication } from "../governed-epoch-publication.js";
import { createTrustRegistryApiServer } from "../server.js";
import { createInMemorySource } from "../source.js";

const bytes = (value: string): Uint8Array => Buffer.from(value.slice(2), "hex");
const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;

describe("governed epoch HTTP boundary", () => {
  it("fails closed when no Compact-backed publication port is configured", async () => {
    const server = createTrustRegistryApiServer({
      source: createInMemorySource(createDemoSnapshot({ label: "epoch-port-unavailable" })),
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("TCP address unavailable");
      const response = await fetch(`http://127.0.0.1:${address.port}/v1/governed/epochs/prepare`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ label: "unavailable" }),
      });
      expect(response.status).toBe(503);
      expect((await response.json()).type).toMatch(/governed-epoch-unavailable$/u);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("exposes the deployment signing domain and rejects wrong-network votes before Compact execution", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("epoch-http-domain");
    const maintainer = createMaintainerFixture("bootstrap", 17);
    maintainer.keyId = bytes32Commitment(`${harness.maintainerDid}#key-1`);
    const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
    const server = createTrustRegistryApiServer({
      source: createInMemorySource(createDemoSnapshot({ label: "epoch-http-domain" })),
      governedEpochPublication: {
        async prepare(label) {
          return harness.prepareRegistryEpochPublicationAction(label);
        },
        async execute(label, signers) {
          const epoch = harness.executeRegistryEpochPublicationWithSignatures(label, signers);
          return { epoch, eventHash: harness.getEpochPublicationWitness(epoch.epochId).eventHash };
        },
      },
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("TCP address unavailable");
      const url = `http://127.0.0.1:${address.port}/v1/governed/epochs`;
      const post = (route: string, body: unknown) => fetch(`${url}/${route}`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
      });
      const preparedResponse = await post("prepare", { label: "current" });
      expect(preparedResponse.status).toBe(200);
      const prepared = await preparedResponse.json() as PreparedGovernedEpochPublication;
      expect(prepared.networkIdCommitment).toBe(hex(harness.simulator.getLedger().deploymentNetworkIdCommitment));
      expect(prepared.contractAddress).toBe(`0x${harness.simulator.contractAddress}`);
      const vote = (networkIdCommitment: string) => ({
        keyId: hex(maintainer.keyId),
        publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
        signature: hex(encodeJubjubSignature(signDeploymentBoundMaintainerActionFromSeed(
          maintainer.seed,
          bytes(prepared.registryId),
          bytes(networkIdCommitment),
          bytes(prepared.contractAddress),
          bytes(prepared.policyCommitment),
          bytes(prepared.actionKind),
          bytes(prepared.actionPayloadHash),
          BigInt(prepared.actionSequence),
        ))),
      });
      const before = harness.simulator.getLedger().governanceActionCount;
      expect((await post("publish", { label: "current", prepared, signers: [
        vote(hex(bytes32Commitment("wrong-network"))),
      ] })).status).toBe(403);
      expect(harness.simulator.getLedger().governanceActionCount).toBe(before);
      const published = await post("publish", { label: "current", prepared, signers: [
        vote(prepared.networkIdCommitment),
      ] });
      expect(published.status).toBe(202);
      expect((await published.json()).eventHash).toMatch(/^0x[0-9a-f]{64}$/u);
      expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => error ? reject(error) : resolve()));
    }
  }, 120_000);
});
