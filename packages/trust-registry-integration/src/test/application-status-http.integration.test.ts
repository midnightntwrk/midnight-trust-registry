import { Buffer } from "node:buffer";
import { once } from "node:events";
import { createServer } from "node:http";

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

  it("rejects a fractionally overlong signed status answer through the VP intake", async () => {
    const scenario = await createApplicationVpScenarioFixture();
    const statement = {
      ...scenario.signedStatusAttestation.statement,
      expiresAt: new Date(VP_FIXTURE_TIME_MS + 5 * 60_000).toISOString().replace(".000Z", ".0000001Z"),
    };
    const signed = {
      statement,
      proof: {
        ...scenario.signedStatusAttestation.proof,
        signature: `0x${Buffer.from(encodeJubjubSignature(
          signJubjubDigest(19n, applicationStatusAttestationDigest(statement)),
        )).toString("hex")}`,
      },
    };
    const status = createHttpApplicationStatusSource({
      endpointUrl,
      resolver: scenario.input.resolver,
      fetchImpl: async () => Response.json(signed),
    });
    await expect(verifyApplicationVp({
      ...scenario.input,
      family: {
        ...scenario.input.family,
        assertStatusActive: (material: typeof scenario.material,
          binding: typeof scenario.fixtureStatusPolicyBinding,
          context: { nonce: string; evaluatedAtMs: number }) =>
          status({ material, binding, ...context }),
      },
    })).rejects.toMatchObject({ category: "ineligible" });
  });

  it("verifies the signed fixture through a real loopback HTTP transport", async () => {
    const scenario = await createApplicationVpScenarioFixture();
    let signed = scenario.signedStatusAttestation;
    const requests: Array<{ method: string | undefined; body: unknown }> = [];
    const server = createServer(async (request, response) => {
      let body = "";
      for await (const chunk of request) body += String(chunk);
      requests.push({ method: request.method, body: JSON.parse(body) as unknown });
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(signed));
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("Loopback status server has no TCP port");
      const status = createHttpApplicationStatusSource({
        endpointUrl: `http://127.0.0.1:${address.port}/attest`,
        resolver: scenario.input.resolver,
      });
      const input = {
        ...scenario.input,
        family: { ...scenario.input.family, assertStatusActive: (material: typeof scenario.material,
          binding: typeof scenario.fixtureStatusPolicyBinding,
          context: { nonce: string; evaluatedAtMs: number }) =>
          status({ material, binding, ...context }) },
      };
      await expect(verifyApplicationVp(input)).resolves.toMatchObject({
        statusDecisionCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
      });
      expect(requests).toHaveLength(1);
      expect(requests[0]).toMatchObject({
        method: "POST",
        body: { statusRegistryId: scenario.fixtureStatusPolicyBinding.statusRegistryId },
      });

      const statement = {
        ...signed.statement,
        expiresAt: new Date(VP_FIXTURE_TIME_MS + 5 * 60_000).toISOString().replace(".000Z", ".0000001Z"),
      };
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
      expect(requests).toHaveLength(2);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
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

    const droppedBody = createHttpApplicationStatusSource({
      endpointUrl,
      resolver: scenario.input.resolver,
      fetchImpl: async () => new Response(new ReadableStream({
        start(controller) { controller.error(new Error("body stream dropped")); },
      }), { status: 200 }),
    });
    await expect(droppedBody(request)).rejects.toBeInstanceOf(ApplicationVpDependencyUnavailableError);
  });

  it("bounds declared and streamed status responses before parsing untrusted JSON", async () => {
    const scenario = await createApplicationVpScenarioFixture();
    const request = {
      material: scenario.material,
      binding: scenario.fixtureStatusPolicyBinding,
      nonce: VP_FIXTURE_NONCE,
      evaluatedAtMs: VP_FIXTURE_TIME_MS,
    };
    const declaredOversize = createHttpApplicationStatusSource({
      endpointUrl,
      resolver: scenario.input.resolver,
      fetchImpl: async () => new Response("{}", {
        status: 200, headers: { "content-length": "65537" },
      }),
    });
    await expect(declaredOversize(request)).rejects.toThrow(/size limit/u);

    let cancelled = false;
    const streamedOversize = createHttpApplicationStatusSource({
      endpointUrl,
      resolver: scenario.input.resolver,
      fetchImpl: async () => new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(65536));
          controller.enqueue(new Uint8Array(1));
        },
        cancel() { cancelled = true; },
      }), { status: 200, headers: { "content-length": "1" } }),
    });
    await expect(streamedOversize(request)).rejects.toThrow(/size limit/u);
    expect(cancelled).toBe(true);
    await expect(verifyApplicationVp({
      ...scenario.input,
      family: {
        ...scenario.input.family,
        assertStatusActive: (material: typeof scenario.material,
          binding: typeof scenario.fixtureStatusPolicyBinding,
          context: { nonce: string; evaluatedAtMs: number }) =>
          streamedOversize({ material, binding, ...context }),
      },
    })).rejects.toMatchObject({ category: "ineligible" });

    const invalidUtf8 = createHttpApplicationStatusSource({
      endpointUrl,
      resolver: scenario.input.resolver,
      fetchImpl: async () => new Response(new Uint8Array([0xff]), { status: 200 }),
    });
    await expect(invalidUtf8(request)).rejects.toThrow();
  });

  it("classifies a bodyless successful status response as ineligible, not retryable", async () => {
    const scenario = await createApplicationVpScenarioFixture();
    const status = createHttpApplicationStatusSource({
      endpointUrl,
      resolver: scenario.input.resolver,
      fetchImpl: async () => new Response(null, { status: 204 }),
    });
    const input = {
      ...scenario.input,
      family: {
        ...scenario.input.family,
        assertStatusActive: (material: typeof scenario.material,
          binding: typeof scenario.fixtureStatusPolicyBinding,
          context: { nonce: string; evaluatedAtMs: number }) =>
          status({ material, binding, ...context }),
      },
    };
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "ineligible" });
  });
});
