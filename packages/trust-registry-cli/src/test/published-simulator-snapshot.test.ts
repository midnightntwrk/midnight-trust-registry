import { describe, expect, it } from "vitest";

import {
  bytes32Commitment,
  createIssuerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "@midnightntwrk/trust-registry-integration";

import { publishSimulatorSnapshot } from "../workspace.js";

describe("published simulator snapshot", () => {
  it("projects a ledger-recorded epoch but rejects altered roots or validity", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("published-snapshot");
    const epoch = await harness.publishRegistryEpoch("explicit");
    const fixtures = { label: "published-snapshot" };
    const snapshot = await publishSimulatorSnapshot(harness, fixtures, undefined, epoch);
    expect(snapshot.currentEpoch).toEqual(epoch);
    expect(snapshot.epochs).toContainEqual(epoch);
    await expect(publishSimulatorSnapshot(harness, fixtures, undefined, {
      ...epoch, stateRoot: `0x${"11".repeat(32)}`,
    })).rejects.toThrow(/does not match the Compact ledger commitment/u);
    await expect(publishSimulatorSnapshot(harness, fixtures, undefined, {
      ...epoch, validUntil: "2026-06-01T00:00:00Z",
    })).rejects.toThrow(/does not match the Compact ledger commitment/u);
    await expect(publishSimulatorSnapshot(harness, fixtures, undefined, {
      ...epoch, registryId: "registry:other",
    })).rejects.toThrow(/another registry/u);
  }, 60_000);

  it("rejects projection that replaces the latest signed epoch with an older grant epoch", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("current-epoch-projection");
    const issuer = createIssuerScenarioFixture("current-epoch-issuer");
    await harness.authorizeIssuer(issuer);
    const registryEpoch = await harness.publishRegistryEpoch("externally-published-registry");
    const before = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(publishSimulatorSnapshot(harness, {
      label: "current-epoch-projection",
      issuers: [{ label: "issuer", fixture: issuer }],
    }, undefined, registryEpoch)).rejects.toThrow(/requires grant evidence before the signed registry epoch/u);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before);
    expect(Buffer.from((await harness.simulator.getCurrentEpochCommitment()).epochId)).toEqual(
      Buffer.from(bytes32Commitment(registryEpoch.epochId)),
    );
  }, 60_000);

  it("retains the signed registry epoch when grant evidence exists before signing", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("current-epoch-prepared-projection");
    const issuer = createIssuerScenarioFixture("prepared-projection-issuer");
    await harness.authorizeIssuer(issuer);
    await harness.buildIssuerHistoricalEvidence(issuer);
    const registryEpoch = await harness.publishRegistryEpoch("externally-published-registry");
    const snapshot = await publishSimulatorSnapshot(harness, {
      label: "current-epoch-prepared-projection",
      issuers: [{ label: "issuer", fixture: issuer }],
    }, undefined, registryEpoch);
    expect(snapshot.currentEpoch).toEqual(registryEpoch);
    expect(snapshot.epochs).toContainEqual(registryEpoch);
    expect(Buffer.from(bytes32Commitment(snapshot.currentEpoch.epochId))).toEqual(
      Buffer.from((await harness.simulator.getCurrentEpochCommitment()).epochId),
    );
  }, 60_000);
});
