import { describe, expect, it } from "vitest";
import { EvidenceVerifierKeyStatus } from "@midnightntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import { createScopedIdentifier } from "@midnightntwrk/trust-registry-domain";

import { bytes32Commitment } from "../fixtures.js";
import { LocalTrustRegistryIntegrationHarness } from "../local-simulator-harness.js";

describe("Ledger 9 policy revision harness", () => {
  it("awaits the governed revision and re-registers the evidence verifier", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("policy-revision-ledger9");
    await harness.ready;
    const before = await harness.simulator.getLedger();
    expect(before.governancePolicyVersion).toBe(1n);

    const eventHash = await harness.updateMaintainerThresholdPolicy(1n, 1n, 1n);
    expect(eventHash).toHaveLength(32);
    const after = await harness.simulator.getLedger();
    expect(after.governancePolicyVersion).toBe(2n);
    expect(after.governanceActionCount).toBe(before.governanceActionCount + 2n);
    expect(harness.evidenceVerifier.keyIds).toEqual([`${harness.evidenceVerifier.did}#assertion-2`]);
    const key = await harness.simulator.getEvidenceVerifierKey(bytes32Commitment(
      createScopedIdentifier("evidence-verifier-key", harness.registryId, "v2"),
    ));
    expect(key.status).toBe(EvidenceVerifierKeyStatus.active);
    expect(key.policyVersion).toBe(2n);
  });
});
