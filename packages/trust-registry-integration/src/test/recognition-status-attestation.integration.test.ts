import { describe, expect, it } from "vitest";

import {
  createRecognitionAccreditationVpScenarioFixture,
  RECOGNITION_VP_FIXTURE_TIME_MS,
} from "../recognition-accreditation-vp-fixtures.js";
import { createAttestedRecognitionStatusSource } from "../recognition-status-attestation.js";
import { verifyRecognitionAccreditationVp } from "../recognition-accreditation-vp.js";

const NOW = RECOGNITION_VP_FIXTURE_TIME_MS;

describe("policy-pinned signed recognition status", () => {
  it("accepts a fresh assertion-method attestation and binds its evidence", async () => {
    const fixture = await createRecognitionAccreditationVpScenarioFixture();
    const verified = await verifyRecognitionAccreditationVp(fixture.input);
    expect(verified.statusDecisionCommitment).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(verified.expiresAtMs).toBe(NOW + 5 * 60_000);
  });

  it("rejects revoked, substituted and future-dated signed status", async () => {
    for (const statusAttestation of [
      { active: false },
      { statusHandleCommitment: `0x${"22".repeat(32)}` },
      { observedAt: new Date(NOW + 2 * 60_000).toISOString(), expiresAt: new Date(NOW + 3 * 60_000).toISOString() },
    ]) {
      const fixture = await createRecognitionAccreditationVpScenarioFixture({ statusAttestation });
      await expect(verifyRecognitionAccreditationVp(fixture.input)).rejects.toThrow();
    }
  });

  it("rejects a replayed challenge and tampered signed bytes", async () => {
    const fixture = await createRecognitionAccreditationVpScenarioFixture();
    const request = {
      anchor: fixture.input.anchor,
      statusHandleCommitment: fixture.claims.statusHandleCommitment,
      evaluatedAtMs: NOW,
      nonce: fixture.input.nonce,
    };
    await expect(fixture.statusSource.verifyPinnedStatus({
      ...request,
      nonce: `0x${"33".repeat(32)}`,
    })).rejects.toThrow(/pinned request/u);
    await expect(fixture.statusSource.verifyPinnedStatus({
      ...request,
      nonce: "0x1234",
    })).rejects.toThrow(/context is invalid/u);
    const tampered = {
      ...fixture.signedStatusAttestation,
      statement: { ...fixture.signedStatusAttestation.statement, active: false },
    };
    const source = createAttestedRecognitionStatusSource({
      resolver: fixture.input.resolver,
      fetchAttestation: async () => tampered,
    });
    await expect(source.verifyPinnedStatus(request)).rejects.toThrow(/signature is invalid/u);
  });

  it("rejects a proof method other than the policy-pinned status method", async () => {
    const fixture = await createRecognitionAccreditationVpScenarioFixture();
    const source = createAttestedRecognitionStatusSource({
      resolver: fixture.input.resolver,
      fetchAttestation: async () => ({
        ...fixture.signedStatusAttestation,
        proof: { ...fixture.signedStatusAttestation.proof, verificationMethodId: `${fixture.input.authorityDid}#assertion-1` },
      }),
    });
    await expect(source.verifyPinnedStatus({
      anchor: fixture.input.anchor,
      statusHandleCommitment: fixture.claims.statusHandleCommitment,
      evaluatedAtMs: NOW,
      nonce: fixture.input.nonce,
    })).rejects.toThrow(/pinned request/u);
  });
});
