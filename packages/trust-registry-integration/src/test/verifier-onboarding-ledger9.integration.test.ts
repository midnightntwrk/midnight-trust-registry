import { describe, expect, it } from "vitest";
import { AuthorizationStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import { createVerifierScenarioFixture } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("Ledger 9 verifier onboarding harness", () => {
  it("awaits evidence-backed onboarding and each governed lifecycle action", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("verifier-onboarding-ledger9");
    const verifier = createVerifierScenarioFixture("verifier-onboarding-ledger9");
    await harness.ready;
    const before = (await harness.simulator.getLedger()).governanceActionCount;

    const activationHash = await harness.authorizeVerifier(verifier);
    expect(activationHash).toHaveLength(32);
    expect((await harness.simulator.getVerifierAuthorization(verifier.authorizationIdCommitment)).status)
      .toBe(AuthorizationStatus.active);
    await harness.suspendVerifier(verifier);
    expect((await harness.simulator.getVerifierAuthorization(verifier.authorizationIdCommitment)).status)
      .toBe(AuthorizationStatus.suspended);
    await harness.revokeVerifier(verifier);
    expect((await harness.simulator.getVerifierAuthorization(verifier.authorizationIdCommitment)).status)
      .toBe(AuthorizationStatus.revoked);
    await harness.archiveVerifier(verifier);
    expect((await harness.simulator.getVerifierAuthorization(verifier.authorizationIdCommitment)).status)
      .toBe(AuthorizationStatus.archived);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before + 6n);
  });
});
