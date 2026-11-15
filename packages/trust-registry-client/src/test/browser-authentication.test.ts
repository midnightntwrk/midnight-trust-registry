import { createServer } from "node:http";

import { describe, expect, it, vi } from "vitest";

import { signInActorDid, signOutActorDid } from "../browser-authentication.js";

const NOW = Date.parse("2026-11-15T00:00:00.000Z");
const origin = "http://127.0.0.1:4400";
const actorDid = `did:midnight:undeployed:${"ab".repeat(32)}`;
const actorKeyId = `${actorDid}#auth-1`;
const challenge = {
  version: "tr-actor-authentication-v1" as const,
  registryId: "tr:registry:local",
  genesisHash: `0x${"11".repeat(32)}`,
  contractAddress: `0x${"22".repeat(32)}`,
  origin,
  purpose: "maintainer-session" as const,
  actorDid,
  actorKeyId,
  nonce: `0x${"33".repeat(32)}`,
  issuedAt: new Date(NOW).toISOString(),
  expiresAt: new Date(NOW + 120_000).toISOString(),
};
const signature = { keyId: actorKeyId, algorithm: "jubjub-schnorr" as const, value: `0x${"aa".repeat(96)}` };
const session = { actorDid, actorKeyId, purpose: "maintainer-session" as const,
  accessToken: `trsa_${"a".repeat(43)}`, expiresAt: new Date(NOW + 900_000).toISOString() };

describe("shared browser DID authentication", () => {
  it("requests and verifies a maintainer-purpose identity session without granting authority", async () => {
    const fetchMock = vi.fn(async (url: string, _init?: RequestInit) => Response.json(url.endsWith("/challenges") ? challenge : session));
    const signer = { getIdentity: vi.fn(async () => ({ actorDid, actorKeyId })),
      signDigest: vi.fn(async () => signature) };
    const result = await signInActorDid({ apiBase: origin, pageOrigin: origin,
      registryId: challenge.registryId, purpose: "maintainer-session", signer,
      fetchImpl: fetchMock as unknown as typeof fetch, clock: () => NOW });
    expect(result.purpose).toBe("maintainer-session");
    expect(result).not.toHaveProperty("role");
    expect(signer.signDigest).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls).toHaveLength(2);
    expect(fetchMock.mock.calls.every(([, init]) => init?.redirect === "error" && init.credentials === "omit")).toBe(true);
  });

  it("rejects an applicant-purpose challenge before external signing", async () => {
    const signDigest = vi.fn(async () => signature);
    await expect(signInActorDid({ apiBase: origin, pageOrigin: origin,
      registryId: challenge.registryId, purpose: "maintainer-session",
      signer: { getIdentity: async () => ({ actorDid, actorKeyId }), signDigest },
      fetchImpl: vi.fn(async () => Response.json({ ...challenge, purpose: "applicant-session" })) as unknown as typeof fetch,
      clock: () => NOW })).rejects.toThrow("does not match");
    expect(signDigest).not.toHaveBeenCalled();
  });

  it("does not follow a redirect while revoking an identity session", async () => {
    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => new Response(null, { status: 204 }));
    await signOutActorDid({ apiBase: origin, pageOrigin: origin,
      session: { ...session, registryId: challenge.registryId,
        genesisHash: challenge.genesisHash, contractAddress: challenge.contractAddress },
      fetchImpl: fetchMock as unknown as typeof fetch });
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      method: "DELETE", credentials: "omit", cache: "no-store", redirect: "error",
    });
  });

  it("does not follow a challenge redirect or ask the external signer to sign", async () => {
    let redirected = false;
    const server = createServer((request, response) => {
      if (request.url === "/redirected") {
        redirected = true;
        response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(challenge));
      } else {
        response.writeHead(302, { location: "/redirected" }).end();
      }
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("Missing loopback port");
      const base = `http://127.0.0.1:${address.port}`;
      const signDigest = vi.fn(async () => signature);
      await expect(signInActorDid({ apiBase: base, pageOrigin: base,
        registryId: challenge.registryId, purpose: "maintainer-session",
        signer: { getIdentity: async () => ({ actorDid, actorKeyId }), signDigest },
        clock: () => NOW })).rejects.toThrow();
      expect(redirected).toBe(false);
      expect(signDigest).not.toHaveBeenCalled();
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
