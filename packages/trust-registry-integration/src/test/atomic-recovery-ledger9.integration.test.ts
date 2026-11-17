import { describe, expect, it } from "vitest";
import {
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { createMaintainerFixture } from "@midnight-ntwrk/trust-registry-contract/testing";
import { AuthorizationStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import { bytes32Commitment, createMaintainerScenarioFixture } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("Ledger 9 atomic maintainer recovery", () => {
  it("rejects insufficient quorum and commits the recovery and policy together", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("atomic-recovery-ledger9");
    const second = createMaintainerScenarioFixture("atomic-recovery-ledger9-second");
    const target = createMaintainerScenarioFixture("atomic-recovery-ledger9-target");
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(target);
    await harness.updateMaintainerThresholdPolicy(2n, 2n, 2n);

    const before = await harness.simulator.getLedger();
    const evidenceHash = bytes32Commitment("incident:atomic-recovery-ledger9");
    const prepared = await harness.prepareAtomicMaintainerRecoveryAction(target, evidenceHash, 1n, 1n, 1n);
    const bootstrap = createMaintainerFixture("bootstrap", 17);
    bootstrap.keyId = bytes32Commitment(`${harness.maintainerDid}#key-1`);
    const sign = (maintainer: { keyId: Uint8Array; seed: Uint8Array }) => ({
      keyId: maintainer.keyId,
      publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
      signature: signDeploymentBoundMaintainerActionFromSeed(
        maintainer.seed,
        prepared.registryId,
        prepared.networkIdCommitment,
        prepared.contractAddress,
        prepared.policyCommitment,
        prepared.actionKind,
        prepared.actionPayloadHash,
        prepared.actionSequence,
      ),
    });
    const bootstrapVote = sign(bootstrap);
    const secondVote = sign(second);
    await expect(harness.executeAtomicMaintainerRecoveryWithSignatures(
      target, evidenceHash, 1n, 1n, 1n, [bootstrapVote],
    )).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before.governanceActionCount);

    const eventHash = await harness.executeAtomicMaintainerRecoveryWithSignatures(
      target, evidenceHash, 1n, 1n, 1n, [bootstrapVote, secondVote],
    );
    const after = await harness.simulator.getLedger();
    expect(eventHash).toHaveLength(32);
    expect(after.governanceActionCount).toBe(before.governanceActionCount + 1n);
    expect(after.activeMaintainerCount).toBe(2n);
    expect(after.maintainerThreshold).toBe(1n);
    expect(after.governancePolicyCommitment).toEqual(Uint8Array.from(prepared.nextPolicyCommitment));
    expect((await harness.simulator.getMaintainerMembership(target.maintainerIdCommitment)).status)
      .not.toBe(AuthorizationStatus.active);
  });
});
