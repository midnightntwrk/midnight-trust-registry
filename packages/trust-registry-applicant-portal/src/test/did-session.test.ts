import { describe, expect, it, vi } from "vitest";

import { signInApplicantDid, signOutApplicantDid, type ApplicantDidSigner } from "../did-session.js";

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
  purpose: "applicant-session" as const,
  actorDid,
  actorKeyId,
  nonce: `0x${"33".repeat(32)}`,
  issuedAt: new Date(NOW).toISOString(),
  expiresAt: new Date(NOW + 120_000).toISOString(),
};
const session = {
  actorDid, actorKeyId, purpose: "applicant-session" as const,
  accessToken: `trsa_${"a".repeat(43)}`,
  expiresAt: new Date(NOW + 900_000).toISOString(),
};
const signer: ApplicantDidSigner = {
  getIdentity: async () => ({ actorDid, actorKeyId }),
  signDigest: vi.fn(async ({ digest }) => {
    expect(digest).toHaveLength(32);
    return { keyId: actorKeyId, algorithm: "jubjub-schnorr" as const, value: `0x${"aa".repeat(96)}` };
  }),
};
const json = (value: unknown, status = 201) => new Response(JSON.stringify(value), {
  status, headers: { "content-type": "application/json" },
});

describe("applicant DID session client", () => {
  it("signs a matching canonical challenge and keeps the bearer token in memory", async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(init?.credentials).toBe("omit");
      return json(url.endsWith("/challenges") ? challenge : session);
    });
    const fetchImpl = fetchMock as unknown as typeof fetch;
    const result = await signInApplicantDid({
      apiBase: origin, pageOrigin: origin, registryId: challenge.registryId,
      signer, fetchImpl, clock: () => NOW,
    });
    expect(result).toEqual({ actorDid, actorKeyId, purpose: "applicant-session", registryId: challenge.registryId,
      genesisHash: challenge.genesisHash, contractAddress: challenge.contractAddress,
      accessToken: session.accessToken, expiresAt: session.expiresAt });
    expect(result).not.toHaveProperty("role");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const signedRequest = fetchMock.mock.calls[1]?.[1];
    expect(JSON.parse(String(signedRequest?.body))).toMatchObject({ challenge,
      signature: { keyId: actorKeyId } });
  });

  it("rejects cross-origin use before calling the signer or API", async () => {
    const fetchImpl = vi.fn() as unknown as typeof fetch;
    const getIdentity = vi.fn(async () => ({ actorDid, actorKeyId }));
    await expect(signInApplicantDid({
      apiBase: "https://unrelated.example", pageOrigin: origin, registryId: challenge.registryId,
      signer: { getIdentity, signDigest: signer.signDigest }, fetchImpl,
    })).rejects.toThrow("same trusted API origin");
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(getIdentity).not.toHaveBeenCalled();
  });

  it("refuses to sign a challenge for another actor, origin, or registry", async () => {
    for (const changed of [
      { actorDid: `did:midnight:undeployed:${"cd".repeat(32)}` },
      { origin: "https://unrelated.example" },
      { registryId: "tr:registry:other" },
    ]) {
      const signDigest = vi.fn(async () => ({
        keyId: actorKeyId, algorithm: "jubjub-schnorr" as const, value: `0x${"aa".repeat(96)}`,
      }));
      const fetchImpl = vi.fn(async () => json({ ...challenge, ...changed })) as unknown as typeof fetch;
      await expect(signInApplicantDid({
        apiBase: origin, pageOrigin: origin, registryId: challenge.registryId,
        signer: { getIdentity: signer.getIdentity, signDigest }, fetchImpl, clock: () => NOW,
      })).rejects.toThrow("does not match");
      expect(signDigest).not.toHaveBeenCalled();
    }
  });

  it("rejects a mismatched session and sends only a same-origin revoke", async () => {
    const fetchImpl = vi.fn(async (url: string) => json(url.endsWith("/challenges") ? challenge
      : { ...session, actorDid: `did:midnight:undeployed:${"cd".repeat(32)}` })) as unknown as typeof fetch;
    await expect(signInApplicantDid({
      apiBase: origin, pageOrigin: origin, registryId: challenge.registryId,
      signer, fetchImpl, clock: () => NOW,
    })).rejects.toThrow("mismatched session");
    const revokeMock = vi.fn(async (_url: string, _init?: RequestInit) => new Response(null, { status: 204 }));
    const revoke = revokeMock as unknown as typeof fetch;
    await signOutApplicantDid({ apiBase: origin, pageOrigin: origin,
      session: { ...session, registryId: challenge.registryId,
        genesisHash: challenge.genesisHash, contractAddress: challenge.contractAddress }, fetchImpl: revoke });
    expect(revokeMock.mock.calls[0]?.[1]).toMatchObject({ method: "DELETE", credentials: "omit",
      headers: { authorization: `Bearer ${session.accessToken}` } });
  });

  it("rejects a challenge bound to another deployment before signing", async () => {
    const signDigest = vi.fn(async () => ({ keyId: actorKeyId,
      algorithm: "jubjub-schnorr" as const, value: `0x${"aa".repeat(96)}` }));
    const fetchImpl = vi.fn(async () => json(challenge)) as unknown as typeof fetch;
    await expect(signInApplicantDid({ apiBase: origin, pageOrigin: origin,
      registryId: challenge.registryId,
      deploymentIdentity: { expectedGenesisHash: challenge.genesisHash,
        contractAddress: `0x${"ff".repeat(32)}` },
      signer: { getIdentity: signer.getIdentity, signDigest }, fetchImpl,
      clock: () => NOW,
    })).rejects.toThrow("does not match");
    expect(signDigest).not.toHaveBeenCalled();
  });

  it("reports when server-side session revocation cannot be confirmed", async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 503 })) as unknown as typeof fetch;
    await expect(signOutApplicantDid({ apiBase: origin, pageOrigin: origin,
      session: { ...session, registryId: challenge.registryId,
        genesisHash: challenge.genesisHash, contractAddress: challenge.contractAddress },
      fetchImpl })).rejects.toThrow("HTTP 503");
  });
});
