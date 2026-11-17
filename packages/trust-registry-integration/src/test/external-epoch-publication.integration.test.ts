import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  compareMaintainerKeyIds,
  deriveJubjubPublicKeyFromSeed,
  pureCircuits,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import type { MaintainerCoAuthorizer } from "@midnight-ntwrk/trust-registry-contract/testing";

import { createMaintainerScenarioFixture, type MaintainerScenarioFixture } from "../fixtures.js";
import {
  LocalTrustRegistryIntegrationHarness,
  type PreparedRegistryEpochPublicationAction,
} from "../local-simulator-harness.js";

const signPrepared = async (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: MaintainerScenarioFixture,
  prepared: PreparedRegistryEpochPublicationAction,
): Promise<MaintainerCoAuthorizer> => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed,
    prepared.registryId,
    (await harness.simulator.getLedger()).deploymentNetworkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"),
    prepared.policyCommitment,
    prepared.actionKind,
    prepared.actionPayloadHash,
    prepared.actionSequence,
  ),
});

describe("externally signed registry epoch publication", () => {
  it("requires current, distinct maintainer quorum and records the canonical first signer", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-epoch");
    const second = createMaintainerScenarioFixture("epoch-second");
    const third = createMaintainerScenarioFixture("epoch-third");
    const outsider = createMaintainerScenarioFixture("epoch-outsider");
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(third);
    await harness.updateMaintainerThresholdPolicy(2n, 2n, 2n);
    const prepared = await harness.prepareRegistryEpochPublicationAction("external-quorum");
    const secondSignature = await signPrepared(harness, second, prepared);
    const thirdSignature = await signPrepared(harness, third, prepared);
    const before = (await harness.simulator.getLedger()).governanceActionCount;

    await expect(harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [secondSignature],
    )).rejects.toThrow();
    await expect(harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [secondSignature, secondSignature],
    )).rejects.toThrow();
    await expect(harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [secondSignature, await signPrepared(harness, outsider, prepared)],
    )).rejects.toThrow();
    await expect(harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [
        await signPrepared(harness, second, { ...prepared, policyCommitment: new Uint8Array(32).fill(1) }),
        thirdSignature,
      ],
    )).rejects.toThrow();
    await expect(harness.executeRegistryEpochPublicationWithSignatures(
      "wrong-label", [secondSignature, thirdSignature],
    )).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before);

    const sorted = [second, third].sort((left, right) =>
      compareMaintainerKeyIds(left.keyId, right.keyId));
    const noncanonicalInput = sorted.map((signer) =>
      signer === second ? secondSignature : thirdSignature).reverse();
    const epoch = await harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", noncanonicalInput,
    );
    expect(epoch.epochId).toBe(prepared.epochId);
    expect(epoch.maintainerSignatures[0]?.keyId).toBe(`${sorted[0]!.subjectDid}#key-1`);
    const witness = await harness.getEpochPublicationWitness(epoch.epochId);
    expect(witness.signatures.map((signer) => signer.keyId)).toEqual(
      sorted.map((signer) => `${signer.subjectDid}#key-1`),
    );
    const zero = new Uint8Array(32);
    const signerSetHash = pureCircuits.maintainerSignerSetHash(
      2n, sorted[0]!.keyId, sorted[1]!.keyId, zero, zero, zero,
    );
    expect((await harness.simulator.getLedger()).lastAuthorizedSignerSetHash).toEqual(signerSetHash);
    const expectedEventHash = pureCircuits.governanceEventHash(
      prepared.registryId,
      prepared.networkIdCommitment,
      prepared.contractAddress,
      prepared.policyCommitment,
      signerSetHash,
      prepared.actionKind,
      prepared.actionPayloadHash,
      prepared.actionSequence,
    );
    expect(witness.eventHash).toBe(`0x${Buffer.from(expectedEventHash).toString("hex")}`);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before + 1n);
    await expect(harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [secondSignature, thirdSignature],
    )).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before + 1n);
  });
});
