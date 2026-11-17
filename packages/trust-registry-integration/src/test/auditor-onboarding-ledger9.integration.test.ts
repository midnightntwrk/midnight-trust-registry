import { describe, expect, it } from "vitest";
import { AuthorizationStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import { createAuditorScenarioFixture } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("Ledger 9 auditor onboarding harness", () => {
  it("awaits evidence-backed onboarding and each governed lifecycle action", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("auditor-onboarding-ledger9");
    const auditor = createAuditorScenarioFixture("auditor-onboarding-ledger9");
    await harness.ready;
    const before = (await harness.simulator.getLedger()).governanceActionCount;

    const activationHash = await harness.authorizeAuditor(auditor);
    expect(activationHash).toHaveLength(32);
    expect((await harness.simulator.getAuditorAuthorization(auditor.authorizationIdCommitment)).status)
      .toBe(AuthorizationStatus.active);
    const bundle = await harness.evaluateCurrentAuditorDecision(auditor);
    expect(bundle.authorization?.status).toBe("active");
    await harness.assertPublishedEpochEvidence(bundle);
    await harness.suspendAuditor(auditor);
    expect((await harness.simulator.getAuditorAuthorization(auditor.authorizationIdCommitment)).status)
      .toBe(AuthorizationStatus.suspended);
    await harness.revokeAuditor(auditor);
    expect((await harness.simulator.getAuditorAuthorization(auditor.authorizationIdCommitment)).status)
      .toBe(AuthorizationStatus.revoked);
    await harness.archiveAuditor(auditor);
    expect((await harness.simulator.getAuditorAuthorization(auditor.authorizationIdCommitment)).status)
      .toBe(AuthorizationStatus.archived);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before + 7n);
  });
});
