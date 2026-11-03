import { describe, expect, it, vi } from "vitest";

import { TrustRegistryAdminConsoleClient } from "../api.js";

const hash = `0x${"a".repeat(64)}`;

describe("governed policy client", () => {
  it("keeps threshold revision and evidence-key registration as separate signed requests", async () => {
    const calls: Array<{ path: string; body: unknown }> = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      calls.push({ path, body: JSON.parse(String(init?.body)) });
      if (path.endsWith("/prepare")) {
        return Response.json({
          registryId: hash, policyCommitment: hash, actionKind: hash,
          actionPayloadHash: hash, actionSequence: "3",
        });
      }
      return Response.json({ eventHash: hash }, { status: 202 });
    });
    const client = new TrustRegistryAdminConsoleClient("http://127.0.0.1:4400", fetchImpl as typeof fetch);
    const thresholds = { default: "3", emergency: "2", archival: "2" };
    const signers = [{ keyId: hash, publicKey: { x: "1", y: "2" }, signature: "0x0102" }];

    const revision = await client.prepareThresholdRevision(thresholds);
    expect(await client.submitThresholdRevision({ thresholds, prepared: revision, signers }))
      .toEqual({ eventHash: hash });
    const registration = await client.prepareEvidenceVerifierRegistration();
    expect(await client.submitEvidenceVerifierRegistration({ prepared: registration, signers }))
      .toEqual({ eventHash: hash });

    expect(calls).toEqual([
      { path: "/v1/governed/policy/thresholds/prepare", body: { thresholds } },
      { path: "/v1/governed/policy/thresholds/submit", body: { thresholds, prepared: revision, signers } },
      { path: "/v1/governed/policy/evidence-verifier/prepare", body: {} },
      { path: "/v1/governed/policy/evidence-verifier/submit", body: { prepared: registration, signers } },
    ]);
  });
});
