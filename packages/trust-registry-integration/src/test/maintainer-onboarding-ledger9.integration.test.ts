import { describe, expect, it } from "vitest";
import { AuthorizationStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import { createMaintainerScenarioFixture } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("Ledger 9 maintainer onboarding harness", () => {
  it("awaits evidence-backed proposal, authorization, and activation", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("maintainer-onboarding-ledger9");
    const candidate = createMaintainerScenarioFixture("maintainer-onboarding-candidate");
    await harness.ready;
    const before = (await harness.simulator.getLedger()).governanceActionCount;

    const activationHash = await harness.authorizeMaintainer(candidate);
    expect(activationHash).toHaveLength(32);
    expect((await harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment)).status)
      .toBe(AuthorizationStatus.active);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before + 3n);
  });
});
