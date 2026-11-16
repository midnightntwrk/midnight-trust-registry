import { createServer } from "node:http";

import { describe, expect, it, vi } from "vitest";
import {
  SignedPendingApplicationSchema,
  computeAuthorizationScopeCommitment,
  computePendingApplicationPayloadCommitment,
  computeSignedPendingApplicationCommitment,
} from "@midnight-ntwrk/trust-registry-domain/browser";

import { isActorDidSigner, isSameOriginPrivateApi, listApplicantApplications, reconcileApplicantApplication, registerApplicantApplication, signInActorDid, signOutActorDid } from "../browser-authentication.js";

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
  origin,
  accessToken: `trsa_${"a".repeat(43)}`, expiresAt: new Date(NOW + 900_000).toISOString() };
const applicantSession = { ...session, purpose: "applicant-session" as const,
  registryId: challenge.registryId, genesisHash: challenge.genesisHash,
  contractAddress: challenge.contractAddress };
const applicationId = "application:maintainer:mine:v1";
const authorizationId = "auth:maintainer:mine:v1";
const scope = { version: "tr-scope-v1" as const, role: "maintainer" as const, registryId: challenge.registryId };
const governedResource = { type: "registry" as const, id: challenge.registryId };
const scopeCommitment = computeAuthorizationScopeCommitment(scope);
const signedApplication = SignedPendingApplicationSchema.parse({
  applicationId, authorizationId, scope, governedResource,
  intent: {
    version: "tr-mutation-intent-v1", registryId: challenge.registryId,
    actorDid, actorKeyId, actorRole: "applicant", action: "apply", target: "maintainer", targetId: applicationId,
    scopeCommitment,
    payloadCommitment: computePendingApplicationPayloadCommitment({ applicationId, authorizationId, scope, governedResource }),
    nonce: `0x${"44".repeat(32)}`, expectedWorkspaceCommitment: `0x${"55".repeat(32)}`,
    expectedEpochId: null, issuedAt: new Date(NOW - 60_000).toISOString(),
    expiresAt: new Date(NOW + 60_000).toISOString(),
  },
  signature: { keyId: actorKeyId, algorithm: "jubjub-schnorr", value: `0x${"aa".repeat(96)}` },
});
const pendingRecord = {
  authorizationId,
  binding: { registryId: challenge.registryId, applicationId, subjectDid: actorDid,
    evidenceVerifierDid: actorDid, role: "maintainer", policyId: "policy:membership:v1",
    policyVersion: "v1", scope, scopeCommitment, governedResource },
  status: "pending", createdAt: new Date(NOW).toISOString(),
};

describe("shared browser DID authentication", () => {
  it("accepts IPv6 loopback sign-in on an exact origin and rejects a different origin", async () => {
    const ipv6Origin = "http://[::1]:4400";
    expect(isSameOriginPrivateApi(ipv6Origin, ipv6Origin)).toBe(true);
    expect(isSameOriginPrivateApi(ipv6Origin, origin)).toBe(false);
    expect(isSameOriginPrivateApi("http://registry.example", "http://registry.example")).toBe(false);
    const fetchMock = vi.fn(async (url: string) => Response.json(url.endsWith("/challenges")
      ? { ...challenge, origin: ipv6Origin } : session));
    const result = await signInActorDid({ apiBase: ipv6Origin, pageOrigin: ipv6Origin,
      registryId: challenge.registryId, purpose: "maintainer-session",
      signer: { getIdentity: async () => ({ actorDid, actorKeyId }), signDigest: async () => signature },
      fetchImpl: fetchMock as unknown as typeof fetch, clock: () => NOW });
    expect(result.actorDid).toBe(actorDid);
    expect(result.origin).toBe(ipv6Origin);
    expect(fetchMock.mock.calls).toHaveLength(2);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(`${ipv6Origin}/v1/actor-authentication/challenges`);
  });

  it("offers sign-in only for a host signer with both required methods", () => {
    expect(isActorDidSigner(null)).toBe(false);
    expect(isActorDidSigner({ getIdentity: async () => ({ actorDid, actorKeyId }) })).toBe(false);
    expect(isActorDidSigner({ getIdentity: async () => ({ actorDid, actorKeyId }),
      signDigest: async () => signature })).toBe(true);
    expect(isActorDidSigner(Object.defineProperty({}, "getIdentity", {
      get: () => { throw new Error("broken host integration"); },
    }))).toBe(false);
  });

  it("requests and verifies a maintainer-purpose identity session without granting authority", async () => {
    const fetchMock = vi.fn(async (url: string, _init?: RequestInit) => Response.json(url.endsWith("/challenges") ? challenge : session));
    const signer = { getIdentity: vi.fn(async () => ({ actorDid, actorKeyId })),
      signDigest: vi.fn(async () => signature) };
    const result = await signInActorDid({ apiBase: origin, pageOrigin: origin,
      registryId: challenge.registryId, purpose: "maintainer-session", signer,
      fetchImpl: fetchMock as unknown as typeof fetch, clock: () => NOW });
    expect(result.purpose).toBe("maintainer-session");
    expect(result.origin).toBe(origin);
    expect(result).not.toHaveProperty("role");
    expect(signer.signDigest).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls).toHaveLength(2);
    expect(fetchMock.mock.calls.every(([, init]) => init?.redirect === "error" && init.credentials === "omit")).toBe(true);
  });

  it("accepts a matching off-chain DID challenge only with an Ed25519 authentication signature", async () => {
    const offchainDid = `did:midnight:offchain:${"ab".repeat(32)}:YWJj`;
    const offchainKeyId = `${offchainDid}#auth-1`;
    const offchainChallenge = { ...challenge, version: "tr-actor-authentication-offchain-v1" as const,
      actorDid: offchainDid, actorKeyId: offchainKeyId };
    const offchainSession = { ...session, actorDid: offchainDid, actorKeyId: offchainKeyId };
    const fetchMock = vi.fn(async (url: string) => Response.json(
      url.endsWith("/challenges") ? offchainChallenge : offchainSession,
    ));
    const signer = { getIdentity: async () => ({ actorDid: offchainDid, actorKeyId: offchainKeyId }),
      signDigest: vi.fn(async () => ({ keyId: offchainKeyId, algorithm: "ed25519" as const,
        value: `0x${"aa".repeat(64)}` })) };
    const input = { apiBase: origin, pageOrigin: origin, registryId: challenge.registryId,
      purpose: "maintainer-session" as const, signer, fetchImpl: fetchMock as unknown as typeof fetch,
      clock: () => NOW };
    expect((await signInActorDid(input)).actorDid).toBe(offchainDid);
    expect(signer.signDigest).toHaveBeenCalledOnce();
    const wrongAlgorithm = { ...signer, signDigest: vi.fn(async () => ({
      keyId: offchainKeyId, algorithm: "jubjub-schnorr" as const, value: `0x${"aa".repeat(96)}`,
    })) };
    await expect(signInActorDid({ ...input, signer: wrongAlgorithm })).rejects.toThrow("mismatched signature");
    expect(fetchMock.mock.calls).toHaveLength(3);
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
    await expect(signOutActorDid({ apiBase: origin, pageOrigin: origin,
      session: { ...session, origin: "https://foreign.example", registryId: challenge.registryId,
        genesisHash: challenge.genesisHash, contractAddress: challenge.contractAddress },
      fetchImpl: fetchMock as unknown as typeof fetch })).rejects.toThrow("session origin");
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("returns a typed applicant list, not a role grant", async () => {
    const applicantSession = { ...session, purpose: "applicant-session" as const,
      registryId: challenge.registryId, genesisHash: challenge.genesisHash,
      contractAddress: challenge.contractAddress };
    const entries = [{ applicationId: "application:issuer:mine:v1", authorizationId: "auth:issuer:mine:v1",
      role: "issuer", status: "pending", createdAt: new Date(NOW).toISOString() }];
    const fetchMock = vi.fn(async () => Response.json({ entries }));
    const result = await listApplicantApplications({ apiBase: origin, pageOrigin: origin,
      session: applicantSession, fetchImpl: fetchMock as unknown as typeof fetch, clock: () => NOW });
    expect(result).toEqual({ status: "available", entries });
    expect(result).not.toHaveProperty("role");
    expect(fetchMock.mock.calls).toHaveLength(1);
  });

  it("registers a signed application through the current DID session and validates the returned binding", async () => {
    const fetchMock = vi.fn(async () => Response.json(pendingRecord));
    const input = { apiBase: origin, pageOrigin: origin, session: applicantSession,
      request: signedApplication, fetchImpl: fetchMock as unknown as typeof fetch, clock: () => NOW };
    expect(await registerApplicantApplication(input)).toEqual(pendingRecord);
    expect(fetchMock).toHaveBeenCalledWith(`${origin}/v1/pending-applications`, {
      method: "POST", credentials: "omit", cache: "no-store", redirect: "error",
      headers: { "content-type": "application/json", authorization: `Bearer ${session.accessToken}` },
      body: JSON.stringify(signedApplication),
    });
    await expect(registerApplicantApplication({ ...input, request: {
      ...signedApplication, intent: { ...signedApplication.intent, actorDid: `did:midnight:undeployed:${"cd".repeat(32)}` },
    } })).rejects.toThrow();
    await expect(registerApplicantApplication({ ...input, session: { ...applicantSession, expiresAt: new Date(NOW).toISOString() } }))
      .rejects.toThrow("current applicant DID session");
    await expect(registerApplicantApplication({ ...input, pageOrigin: "https://foreign.example" }))
      .rejects.toThrow("same trusted API origin");
    await expect(registerApplicantApplication({ ...input, session: { ...applicantSession, origin: "https://foreign.example" } }))
      .rejects.toThrow("session origin");
    expect(fetchMock).toHaveBeenCalledOnce();
    await expect(registerApplicantApplication({ ...input,
      fetchImpl: vi.fn(async () => Response.json({ ...pendingRecord,
        binding: { ...pendingRecord.binding, subjectDid: `did:midnight:undeployed:${"cd".repeat(32)}` },
      })) as unknown as typeof fetch })).rejects.toThrow("mismatched record");
    await expect(registerApplicantApplication({ ...input,
      fetchImpl: vi.fn(async () => { throw new Error("socket closed after acceptance"); }) as unknown as typeof fetch,
    })).rejects.toThrow("outcome is unknown");
    await expect(registerApplicantApplication({ ...input,
      fetchImpl: vi.fn(async () => new Response("{", { status: 201 })) as unknown as typeof fetch,
    })).rejects.toThrow("outcome is unknown");
    await expect(registerApplicantApplication({ ...input,
      fetchImpl: vi.fn(async () => new Response(null, { status: 503 })) as unknown as typeof fetch,
    })).rejects.toThrow("outcome is unknown");
    await expect(registerApplicantApplication({ ...input,
      fetchImpl: vi.fn(async () => new Response(null, { status: 403 })) as unknown as typeof fetch,
    })).rejects.toThrow("HTTP 403");
  });

  it.each([408, 429])("reconciles a committed application after an ambiguous HTTP %i", async (status) => {
    let committed = false;
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        committed = true;
        return new Response(null, { status });
      }
      return Response.json({ ...pendingRecord,
        requestCommitment: computeSignedPendingApplicationCommitment(signedApplication),
      });
    });
    const input = { apiBase: origin, pageOrigin: origin, session: applicantSession,
      request: signedApplication, fetchImpl: fetchMock as unknown as typeof fetch, clock: () => NOW };
    await expect(registerApplicantApplication(input)).rejects.toThrow("outcome is unknown");
    expect(committed).toBe(true);
    expect(await reconcileApplicantApplication(input)).toEqual({ status: "observed", record: {
      ...pendingRecord, requestCommitment: computeSignedPendingApplicationCommitment(signedApplication),
    } });
    expect(fetchMock.mock.calls.map(([, init]) => init?.method)).toEqual(["POST", "GET"]);
  });

  it("distinguishes an unconfigured private list from empty, denied, and malformed results", async () => {
    const applicantSession = { ...session, purpose: "applicant-session" as const,
      registryId: challenge.registryId, genesisHash: challenge.genesisHash,
      contractAddress: challenge.contractAddress };
    const input = { apiBase: origin, pageOrigin: origin, session: applicantSession, clock: () => NOW };
    const unavailable = vi.fn(async () => Response.json({
      type: "https://registry.example/problems/pending-application-list-unavailable", status: 503,
    }, { status: 503 }));
    expect(await listApplicantApplications({ ...input, fetchImpl: unavailable as unknown as typeof fetch }))
      .toEqual({ status: "unavailable" });
    expect(await listApplicantApplications({ ...input,
      fetchImpl: vi.fn(async () => Response.json({ entries: [] })) as unknown as typeof fetch }))
      .toEqual({ status: "available", entries: [] });
    await expect(listApplicantApplications({ ...input, fetchImpl: vi.fn(async () => Response.json({
      type: "https://registry.example/problems/source-unavailable", status: 503,
    }, { status: 503 })) as unknown as typeof fetch })).rejects.toThrow("HTTP 503");
    await expect(listApplicantApplications({ ...input, fetchImpl: vi.fn(async () => Response.json({
      entries: [{ applicationId: "mine", authorizationId: "id", role: "maintainer",
        status: "active", createdAt: new Date(NOW).toISOString() }],
    })) as unknown as typeof fetch })).rejects.toThrow("invalid response");
    await expect(listApplicantApplications({ ...input, fetchImpl: vi.fn(async () => Response.json({
      type: "https://registry.example/problems/applicant-session-required", status: 403,
    }, { status: 403 })) as unknown as typeof fetch })).rejects.toThrow("HTTP 403");
    expect(unavailable.mock.calls).toHaveLength(1);
    await expect(listApplicantApplications({ ...input,
      session: { ...applicantSession, purpose: "maintainer-session" } as unknown as typeof applicantSession,
      fetchImpl: unavailable as unknown as typeof fetch })).rejects.toThrow("applicant DID session");
    await expect(listApplicantApplications({ ...input, pageOrigin: "https://foreign.example",
      fetchImpl: unavailable as unknown as typeof fetch })).rejects.toThrow("same trusted API origin");
    await expect(listApplicantApplications({ ...input, session: { ...applicantSession, origin: "https://foreign.example" },
      fetchImpl: unavailable as unknown as typeof fetch })).rejects.toThrow("session origin");
    expect(unavailable.mock.calls).toHaveLength(1);
  });

  it("reconciles only the exact signed request, never a missing or legacy record", async () => {
    const record = { ...pendingRecord,
      requestCommitment: computeSignedPendingApplicationCommitment(signedApplication) };
    const fetchMock = vi.fn(async () => Response.json(record));
    const input = { apiBase: origin, pageOrigin: origin, session: applicantSession,
      request: signedApplication, clock: () => NOW, fetchImpl: fetchMock as unknown as typeof fetch };
    expect(await reconcileApplicantApplication(input)).toEqual({ status: "observed", record });
    expect(fetchMock).toHaveBeenCalledWith(`${origin}/v1/pending-applications/${encodeURIComponent(applicationId)}`, {
      method: "GET", credentials: "omit", cache: "no-store", redirect: "error",
      headers: { authorization: `Bearer ${session.accessToken}` },
    });
    const response = (body: unknown, status = 200) => vi.fn(async () => Response.json(body, { status })) as unknown as typeof fetch;
    expect(await reconcileApplicantApplication({ ...input, fetchImpl: response(pendingRecord) }))
      .toEqual({ status: "unknown" });
    expect(await reconcileApplicantApplication({ ...input, fetchImpl: response({}, 404) }))
      .toEqual({ status: "unknown" });
    expect(await reconcileApplicantApplication({ ...input, fetchImpl: response({}, 503) }))
      .toEqual({ status: "unknown" });
    expect(await reconcileApplicantApplication({ ...input,
      fetchImpl: vi.fn(async () => { throw new Error("socket closed"); }) as unknown as typeof fetch }))
      .toEqual({ status: "unknown" });
    expect(await reconcileApplicantApplication({ ...input,
      fetchImpl: vi.fn(async () => new Response("{", { status: 200 })) as unknown as typeof fetch }))
      .toEqual({ status: "unknown" });
    await expect(reconcileApplicantApplication({ ...input,
      fetchImpl: response({ ...record, requestCommitment: `0x${"99".repeat(32)}` }) }))
      .rejects.toThrow("mismatched record");
    await expect(reconcileApplicantApplication({ ...input, fetchImpl: response({}, 403) }))
      .rejects.toThrow("HTTP 403");
    await expect(reconcileApplicantApplication({ ...input,
      session: { ...applicantSession, purpose: "maintainer-session" } as unknown as typeof applicantSession }))
      .rejects.toThrow("applicant DID session");
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
