import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  signPolicyBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import type { MaintainerCoAuthorizer } from "@midnight-ntwrk/trust-registry-contract/testing";

import { createMaintainerScenarioFixture, type MaintainerScenarioFixture } from "../fixtures.js";
import {
  LocalTrustRegistryIntegrationHarness,
  type PreparedRegistryEpochPublicationAction,
} from "../local-simulator-harness.js";

const signPrepared = (
  maintainer: MaintainerScenarioFixture,
  prepared: PreparedRegistryEpochPublicationAction,
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    prepared.registryId,
    prepared.policyCommitment,
    prepared.actionKind,
    prepared.actionPayloadHash,
    prepared.actionSequence,
  ),
});

describe("externally signed registry epoch publication", () => {
  it("requires current, distinct maintainer quorum and records the actual primary signer", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-epoch");
    const second = createMaintainerScenarioFixture("epoch-second");
    const third = createMaintainerScenarioFixture("epoch-third");
    const outsider = createMaintainerScenarioFixture("epoch-outsider");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 2n, 2n);
    const prepared = harness.prepareRegistryEpochPublicationAction("external-quorum");
    const secondSignature = signPrepared(second, prepared);
    const thirdSignature = signPrepared(third, prepared);
    const before = harness.simulator.getLedger().governanceActionCount;

    expect(() => harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [secondSignature],
    )).toThrow();
    expect(() => harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [secondSignature, secondSignature],
    )).toThrow();
    expect(() => harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [secondSignature, signPrepared(outsider, prepared)],
    )).toThrow();
    expect(() => harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [
        signPrepared(second, { ...prepared, policyCommitment: new Uint8Array(32) }),
        thirdSignature,
      ],
    )).toThrow();
    expect(() => harness.executeRegistryEpochPublicationWithSignatures(
      "wrong-label", [secondSignature, thirdSignature],
    )).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before);

    const epoch = harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [secondSignature, thirdSignature],
    );
    expect(epoch.epochId).toBe(prepared.epochId);
    expect(epoch.maintainerSignatures[0]?.keyId).toBe(`${second.subjectDid}#key-1`);
    const witness = harness.getEpochPublicationWitness(epoch.epochId);
    expect(witness.signatures.map((signer) => signer.keyId)).toEqual([
      `${second.subjectDid}#key-1`, `${third.subjectDid}#key-1`,
    ]);
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);
    expect(() => harness.executeRegistryEpochPublicationWithSignatures(
      "external-quorum", [secondSignature, thirdSignature],
    )).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before + 1n);
  });
});
