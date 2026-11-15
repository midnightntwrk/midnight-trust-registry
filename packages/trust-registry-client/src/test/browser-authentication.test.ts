import { describe, expect, it, vi } from "vitest";

import { signInActorDid } from "../browser-authentication.js";

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
    const fetchMock = vi.fn(async (url: string) => Response.json(url.endsWith("/challenges") ? challenge : session));
    const signer = { getIdentity: vi.fn(async () => ({ actorDid, actorKeyId })),
      signDigest: vi.fn(async () => signature) };
    const result = await signInActorDid({ apiBase: origin, pageOrigin: origin,
      registryId: challenge.registryId, purpose: "maintainer-session", signer,
      fetchImpl: fetchMock as unknown as typeof fetch, clock: () => NOW });
    expect(result.purpose).toBe("maintainer-session");
    expect(result).not.toHaveProperty("role");
    expect(signer.signDigest).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls).toHaveLength(2);
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
});
