import { describe, expect, it } from "vitest";
import { AuthorizationStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import { createRecognitionScenarioFixture } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("Ledger 9 recognition lifecycle harness", () => {
  it("awaits governed proposal, activation, and every status transition", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("recognition-ledger9");
    const recognition = createRecognitionScenarioFixture("recognition-ledger9");
    await harness.ready;
    const before = (await harness.simulator.getLedger()).governanceActionCount;

    const activationHash = await harness.authorizeRecognition(recognition);
    expect(activationHash).toHaveLength(32);
    expect((await harness.simulator.getRecognition(recognition.recognitionIdCommitment)).status)
      .toBe(AuthorizationStatus.active);
    await harness.suspendRecognition(recognition);
    expect((await harness.simulator.getRecognition(recognition.recognitionIdCommitment)).status)
      .toBe(AuthorizationStatus.suspended);
    await harness.revokeRecognition(recognition);
    expect((await harness.simulator.getRecognition(recognition.recognitionIdCommitment)).status)
      .toBe(AuthorizationStatus.revoked);
    await harness.archiveRecognition(recognition);
    expect((await harness.simulator.getRecognition(recognition.recognitionIdCommitment)).status)
      .toBe(AuthorizationStatus.archived);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before + 6n);
  });
});
