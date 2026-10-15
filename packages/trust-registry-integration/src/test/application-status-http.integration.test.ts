import { Buffer } from "node:buffer";

import { signJubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { encodeJubjubSignature } from "@midnight-ntwrk/trust-registry-contract";
import { describe, expect, it, vi } from "vitest";

import { applicationStatusAttestationDigest } from "../application-status-attestation.js";
import { createHttpApplicationStatusSource } from "../application-status-http.js";
import { ApplicationVpDependencyUnavailableError, verifyApplicationVp } from "../application-vp-verifier.js";
import { createApplicationVpScenarioFixture, VP_FIXTURE_NONCE, VP_FIXTURE_TIME_MS } from "../vp-scenario-fixtures.js";

const endpointUrl = "https://status.example.test/attest";

describe("HTTP application status authority adapter", () => {
  it("posts only credential commitments and verifies a governed, DID-signed active answer", async () => {
    const scenario = await createApplicationVpScenarioFixture();
    const fetchImpl = vi.fn<typeof fetch>(async () => Response.json(scenario.signedStatusAttestation));
    const source = createHttpApplicationStatusSource({
      endpointUrl,
      resolver: scenario.input.resolver,
      fetchImpl,
    });
    await expect(source({
      material: scenario.material,
      binding: scenario.fixtureStatusPolicyBinding,
      nonce: VP_FIXTURE_NONCE,
      evaluatedAtMs: VP_FIXTURE_TIME_MS,
    })).resolves.toMatchObject({ validUntilMs: VP_FIXTURE_TIME_MS + 5 * 60_000 });
    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(String(url)).toBe(endpointUrl);
    expect(init).toMatchObject({ method: "POST", cache: "no-store", redirect: "error" });
    expect(JSON.parse(String(init?.body))).toEqual({
      statusRegistryId: scenario.fixtureStatusPolicyBinding.statusRegistryId,
      statusHandleCommitment: `0x${Buffer.from(scenario.material.statusBinding.statusHandleCommitment).toString("hex")}`,
      credentialBodyRoot: `0x${Buffer.from(scenario.material.credentialBodyRoot).toString("hex")}`,
      challengeHash: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
    });
  });

  it("rejects re-signed revoked, substituted, and stale answers rather than trusting HTTP", async () => {
    const scenario = await createApplicationVpScenarioFixture();
    const request = {
      material: scenario.material,
      binding: scenario.fixtureStatusPolicyBinding,
      nonce: VP_FIXTURE_NONCE,
      evaluatedAtMs: VP_FIXTURE_TIME_MS,
    };
    for (const statement of [
      { ...scenario.signedStatusAttestation.statement, active: false },
      { ...scenario.signedStatusAttestation.statement, statusRegistryId: `0x${"99".repeat(32)}` },
      { ...scenario.signedStatusAttestation.statement, observedAt: new Date(VP_FIXTURE_TIME_MS - 6 * 60_000).toISOString() },
    ]) {
      const signed = {
        statement,
        proof: {
          ...scenario.signedStatusAttestation.proof,
          signature: `0x${Buffer.from(encodeJubjubSignature(
            signJubjubDigest(19n, applicationStatusAttestationDigest(statement)),
          )).toString("hex")}`,
        },
      };
      const source = createHttpApplicationStatusSource({
        endpointUrl,
        resolver: scenario.input.resolver,
        fetchImpl: async () => Response.json(signed),
      });
      await expect(source(request)).rejects.toThrow();
    }
  });

  it("drives the published VC/VP application intake without leaking the status witness", async () => {
    const scenario = await createApplicationVpScenarioFixture();
    let signed = scenario.signedStatusAttestation;
    const status = createHttpApplicationStatusSource({
      endpointUrl,
      resolver: scenario.input.resolver,
      fetchImpl: async () => Response.json(signed),
    });
    const input = {
      ...scenario.input,
      family: { ...scenario.input.family, assertStatusActive: (material: typeof scenario.material,
        binding: typeof scenario.fixtureStatusPolicyBinding, context: { nonce: string; evaluatedAtMs: number }) =>
        status({ material, binding, ...context }) },
    };
    const result = await verifyApplicationVp(input);
    expect(result.statusDecisionCommitment).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(JSON.stringify(result)).not.toContain(signed.proof.signature);
    const statement = { ...signed.statement, active: false };
    signed = {
      statement,
      proof: {
        ...signed.proof,
        signature: `0x${Buffer.from(encodeJubjubSignature(
          signJubjubDigest(19n, applicationStatusAttestationDigest(statement)),
        )).toString("hex")}`,
      },
    };
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "ineligible" });
  });

  it("rejects insecure endpoints and fails closed on unavailable or rejected responses", async () => {
    const scenario = await createApplicationVpScenarioFixture();
    for (const url of [
      "http://status.example.test/attest",
      "https://user:secret@status.example.test/attest",
      "https://status.example.test/attest#fragment",
      "https://status.example.test/attest?token=secret",
    ]) {
      expect(() => createHttpApplicationStatusSource({
        endpointUrl: url,
        resolver: scenario.input.resolver,
      })).toThrow();
    }
    const request = {
      material: scenario.material,
      binding: scenario.fixtureStatusPolicyBinding,
      nonce: VP_FIXTURE_NONCE,
      evaluatedAtMs: VP_FIXTURE_TIME_MS,
    };
    for (const [response, unavailable] of [
      [new Response(null, { status: 404 }), false],
      [new Response(null, { status: 429 }), true],
      [new Response(null, { status: 503 }), true],
      [new Response(null, { status: 302 }), false],
    ] as const) {
      const source = createHttpApplicationStatusSource({
        endpointUrl,
        resolver: scenario.input.resolver,
        fetchImpl: async () => response,
      });
      if (unavailable) await expect(source(request)).rejects.toBeInstanceOf(ApplicationVpDependencyUnavailableError);
      else await expect(source(request)).rejects.toThrow();
    }
    const source = createHttpApplicationStatusSource({
      endpointUrl,
      resolver: scenario.input.resolver,
      fetchImpl: async () => { throw new TypeError("network down"); },
    });
    await expect(source(request)).rejects.toBeInstanceOf(ApplicationVpDependencyUnavailableError);
  });
});
