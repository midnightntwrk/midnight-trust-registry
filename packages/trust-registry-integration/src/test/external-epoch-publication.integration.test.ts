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

const signPrepared = (
  harness: LocalTrustRegistryIntegrationHarness,
  maintainer: MaintainerScenarioFixture,
  prepared: PreparedRegistryEpochPublicationAction,
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed,
    prepared.registryId,
    harness.simulator.getLedger().deploymentNetworkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"),
    prepared.policyCommitment,
    prepared.actionKind,
    prepared.actionPayloadHash,
    prepared.actionSequence,
  ),
});

describe("externally signed registry epoch publication", () => {
  it("requires current, distinct maintainer quorum and records the canonical first signer", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-epoch");
    const second = createMaintainerScenarioFixture("epoch-second");
    const third = createMaintainerScenarioFixture("epoch-third");
    const outsider = createMaintainerScenarioFixture("epoch-outsider");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 2n, 2n);
    const prepared = harness.prepareRegistryEpochPublicationAction("external-quorum");
    const secondSignature = signPrepared(harness, second, prepared);
    const thirdSignature = signPrepared(harness, third, prepared);
    const before = harness.simulator.getLedger().governanceActionCount;

    expect(() => harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [secondSignature],
    )).toThrow();
    expect(() => harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [secondSignature, secondSignature],
    )).toThrow();
    expect(() => harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [secondSignature, signPrepared(harness, outsider, prepared)],
    )).toThrow();
    expect(() => harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [
        signPrepared(harness, second, { ...prepared, policyCommitment: new Uint8Array(32) }),
        thirdSignature,
      ],
    )).toThrow();
    expect(() => harness.executeRegistryEpochPublicationWithSignatures(
      "wrong-label", [secondSignature, thirdSignature],
    )).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before);

    const sorted = [second, third].sort((left, right) =>
      compareMaintainerKeyIds(left.keyId, right.keyId));
    const noncanonicalInput = sorted.map((signer) =>
      signer === second ? secondSignature : thirdSignature).reverse();
    const epoch = harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", noncanonicalInput,
    );
    expect(epoch.epochId).toBe(prepared.epochId);
    expect(epoch.maintainerSignatures[0]?.keyId).toBe(`${sorted[0]!.subjectDid}#key-1`);
    const witness = harness.getEpochPublicationWitness(epoch.epochId);
    expect(witness.signatures.map((signer) => signer.keyId)).toEqual(
      sorted.map((signer) => `${signer.subjectDid}#key-1`),
    );
    const zero = new Uint8Array(32);
    const signerSetHash = pureCircuits.maintainerSignerSetHash(
      2n, sorted[0]!.keyId, sorted[1]!.keyId, zero, zero, zero,
    );
    expect(harness.simulator.getLedger().lastAuthorizedSignerSetHash).toEqual(signerSetHash);
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
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);
    expect(() => harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [secondSignature, thirdSignature],
    )).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);
  });
});
