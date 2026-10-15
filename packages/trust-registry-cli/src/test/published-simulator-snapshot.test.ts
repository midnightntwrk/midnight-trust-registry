import { describe, expect, it } from "vitest";

import {
  bytes32Commitment,
  createIssuerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "@midnight-ntwrk/trust-registry-integration";

import { publishSimulatorSnapshot } from "../workspace.js";

describe("published simulator snapshot", () => {
  it("projects a ledger-recorded epoch but rejects altered roots or validity", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("published-snapshot");
    const epoch = harness.publishRegistryEpoch("explicit");
    const fixtures = { label: "published-snapshot" };
    const snapshot = publishSimulatorSnapshot(harness, fixtures, undefined, epoch);
    expect(snapshot.currentEpoch).toEqual(epoch);
    expect(snapshot.epochs).toContainEqual(epoch);
    expect(() => publishSimulatorSnapshot(harness, fixtures, undefined, {
      ...epoch, stateRoot: `0x${"11".repeat(32)}`,
    })).toThrow(/does not match the Compact ledger commitment/u);
    expect(() => publishSimulatorSnapshot(harness, fixtures, undefined, {
      ...epoch, validUntil: "2026-06-01T00:00:00Z",
    })).toThrow(/does not match the Compact ledger commitment/u);
    expect(() => publishSimulatorSnapshot(harness, fixtures, undefined, {
      ...epoch, registryId: "registry:other",
    })).toThrow(/another registry/u);
  }, 60_000);

  it("rejects projection that replaces the latest signed epoch with an older grant epoch", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("current-epoch-projection");
    const issuer = createIssuerScenarioFixture("current-epoch-issuer");
    harness.authorizeIssuer(issuer);
    const registryEpoch = harness.publishRegistryEpoch("externally-published-registry");
    const before = harness.simulator.getLedger().governanceActionCount;
    expect(() => publishSimulatorSnapshot(harness, {
      label: "current-epoch-projection",
      issuers: [{ label: "issuer", fixture: issuer }],
    }, undefined, registryEpoch)).toThrow(/requires grant evidence before the signed registry epoch/u);
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before);
    expect(Buffer.from(harness.simulator.getCurrentEpochCommitment().epochId)).toEqual(
      Buffer.from(bytes32Commitment(registryEpoch.epochId)),
    );
  }, 60_000);

  it("retains the signed registry epoch when grant evidence exists before signing", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("current-epoch-prepared-projection");
    const issuer = createIssuerScenarioFixture("prepared-projection-issuer");
    harness.authorizeIssuer(issuer);
    harness.buildIssuerHistoricalEvidence(issuer);
    const registryEpoch = harness.publishRegistryEpoch("externally-published-registry");
    const snapshot = publishSimulatorSnapshot(harness, {
      label: "current-epoch-prepared-projection",
      issuers: [{ label: "issuer", fixture: issuer }],
    }, undefined, registryEpoch);
    expect(snapshot.currentEpoch).toEqual(registryEpoch);
    expect(snapshot.epochs).toContainEqual(registryEpoch);
    expect(Buffer.from(bytes32Commitment(snapshot.currentEpoch.epochId))).toEqual(
      Buffer.from(harness.simulator.getCurrentEpochCommitment().epochId),
    );
  }, 60_000);
});
