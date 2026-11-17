import { describe, expect, it } from "vitest";
import {
  AuthorizationStatus,
  IssuerResourceType,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import { createIssuerScenarioFixture } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("Ledger 9 issuer onboarding harness", () => {
  it("awaits an evidence-backed proposal, authorization, and activation", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("issuer-onboarding-ledger9");
    const issuer = createIssuerScenarioFixture("issuer-onboarding-ledger9", IssuerResourceType.schema);
    await harness.ready;
    const before = (await harness.simulator.getLedger()).governanceActionCount;

    const activationHash = await harness.authorizeIssuer(issuer);
    expect(activationHash).toHaveLength(32);
    expect((await harness.simulator.getIssuerAuthorization(issuer.authorizationIdCommitment)).status)
      .toBe(AuthorizationStatus.active);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before + 3n);
    const bundle = await harness.evaluateCurrentIssuerDecision(issuer);
    expect(bundle.authorization?.status).toBe("active");
    await harness.assertPublishedEpochEvidence(bundle);
    expect((await harness.getEpochPublicationWitness(bundle.epoch.epochId)).signatures).toHaveLength(1);

    await harness.suspendIssuer(issuer);
    expect((await harness.simulator.getIssuerAuthorization(issuer.authorizationIdCommitment)).status)
      .toBe(AuthorizationStatus.suspended);
    await harness.revokeIssuer(issuer);
    expect((await harness.simulator.getIssuerAuthorization(issuer.authorizationIdCommitment)).status)
      .toBe(AuthorizationStatus.revoked);
    await harness.archiveIssuer(issuer);
    expect((await harness.simulator.getIssuerAuthorization(issuer.authorizationIdCommitment)).status)
      .toBe(AuthorizationStatus.archived);
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before + 7n);
  });
});
