import { Buffer } from "node:buffer";
import { generateKeyPairSync, sign as signEd25519 } from "node:crypto";
import type { Server } from "node:http";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signJubjubPayloadFromSeed,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { createLongFormOffchainMidnightDIDString, CurveType, KeyType } from "@midnight-ntwrk/midnight-did-domain";
import { createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import { actorAuthenticationDigestBytes, type ActorAuthenticationChallenge } from "@midnight-ntwrk/trust-registry-domain";
import {
  createMidnightDid,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
} from "@midnight-ntwrk/trust-registry-integration";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createActorAuthenticationService, type ActorAuthenticationChallengeStore } from "../actor-authentication.js";
import { createActorSessionService } from "../actor-sessions.js";
import { InMemoryApplicationChallengeStore } from "../application-challenges.js";
import type { ApplicationVpHttpPort } from "../application-vp-http.js";
import type { PendingApplicationRegistrationPort } from "../pending-application-registration.js";
import { createTrustRegistryApiServer } from "../server.js";
import { createInMemorySource } from "../source.js";

const seed = new Uint8Array(32).fill(23);
const actorDid = createMidnightDid("http-actor-authentication");
const actorKeyId = `${actorDid}#auth-1`;
const START = Date.parse("2026-11-14T00:00:00.000Z");
const expectedOrigin = "http://127.0.0.1:4400";

function challengeStore(): ActorAuthenticationChallengeStore {
  const entries = new Map<string, number>();
  return {
    async insert(digest, _actorHash, expiry, at) {
      for (const [key, value] of entries) if (value <= at) entries.delete(key);
      if (entries.has(digest)) return false;
      entries.set(digest, expiry);
      return true;
    },
    async consume(digest, at) {
      const expiry = entries.get(digest);
      if (expiry === undefined || expiry <= at) return false;
      entries.delete(digest);
      return true;
    },
  };
}

function signatureFor(challenge: ActorAuthenticationChallenge) {
  return {
    keyId: challenge.actorKeyId,
    algorithm: "jubjub-schnorr",
    value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
      seed, actorAuthenticationDigestBytes(challenge),
    ))).toString("hex")}`,
  };
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address expected");
  return `http://127.0.0.1:${address.port.toString()}`;
}

describe("phase-0 DID authentication HTTP", () => {
  let server: Server | undefined;
  let nowMs = START;
  let base = "";

  afterEach(async () => {
    if (server !== undefined) {
      await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve()));
      server = undefined;
    }
  });

  async function start(configured = true, applicationVp?: ApplicationVpHttpPort,
    pendingApplicationRegistration?: PendingApplicationRegistrationPort, ledgerResolver = true) {
    nowMs = START;
    const resolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(actorDid, {
        verificationMethodId: "auth-1",
        schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(seed),
      }),
    ]);
    const challenges = createActorAuthenticationService({
      context: {
        registryId: "tr:registry:local",
        genesisHash: `0x${"11".repeat(32)}`,
        contractAddress: `0x${"22".repeat(32)}`,
        origin: expectedOrigin,
      },
      ...(ledgerResolver ? { resolver } : {}), store: challengeStore(), clock: () => nowMs,
    });
    server = createTrustRegistryApiServer({
      source: createInMemorySource(createOperatorWorkspace({ label: "actor-auth-http" }).snapshot),
      ...(configured ? { actorAuthentication: { challenges, sessions: createActorSessionService(() => nowMs) } } : {}),
      ...(applicationVp === undefined ? {} : { applicationVp }),
      ...(pendingApplicationRegistration === undefined ? {} : { pendingApplicationRegistration }),
    });
    base = await listen(server);
  }

  const post = (path: string, body: unknown, headers: Record<string, string> = {}) => fetch(`${base}${path}`, {
    method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body),
  });

  it("signs in with a self-certifying off-chain DID without a ledger resolver", async () => {
    await start(true, undefined, undefined, false);
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicJwk = publicKey.export({ format: "jwk" });
    const offchainDid = createLongFormOffchainMidnightDIDString({
      version: 1, alsoKnownAs: [], service: [],
      verificationMethod: [{ id: "#auth-1",
        publicKeyJwk: { kty: KeyType.OKP, crv: CurveType.Ed25519, x: publicJwk.x! },
        relationships: { authentication: true, assertionMethod: false, keyAgreement: false,
          capabilityInvocation: false, capabilityDelegation: false } }],
    });
    const offchainKeyId = `${offchainDid}#auth-1`;
    const issued = await post("/v1/actor-authentication/challenges", {
      actorDid: offchainDid, actorKeyId: offchainKeyId, purpose: "applicant-session",
    }, { origin: expectedOrigin });
    expect(issued.status).toBe(201);
    const challenge = await issued.json() as ActorAuthenticationChallenge;
    expect(challenge.version).toBe("tr-actor-authentication-offchain-v1");
    const signature = { keyId: offchainKeyId, algorithm: "ed25519",
      value: `0x${signEd25519(null, actorAuthenticationDigestBytes(challenge), privateKey).toString("hex")}` };
    const verified = await post("/v1/actor-authentication/sessions", { challenge, signature },
      { origin: expectedOrigin });
    expect(verified.status).toBe(201);
    const session = await verified.json() as { accessToken: string; actorDid: string; purpose: string };
    expect(session).toMatchObject({ actorDid: offchainDid, purpose: "applicant-session" });
    expect(session).not.toHaveProperty("role");
    expect((await post("/v1/actor-authentication/sessions", { challenge, signature },
      { origin: expectedOrigin })).status).toBe(401);
  });

  it("signs in once, exposes identity without role, and revokes the bearer token", async () => {
    await start();
    const issued = await post("/v1/actor-authentication/challenges", {
      actorDid, actorKeyId, purpose: "applicant-session",
    }, { origin: expectedOrigin });
    expect(issued.status).toBe(201);
    expect(issued.headers.get("access-control-allow-origin")).toBeNull();
    expect(issued.headers.get("cache-control")).toBe("no-store");
    const challenge = await issued.json() as ActorAuthenticationChallenge;
    const verified = await post("/v1/actor-authentication/sessions", {
      challenge, signature: signatureFor(challenge),
    }, { origin: expectedOrigin });
    expect(verified.status).toBe(201);
    const session = await verified.json() as { accessToken: string; expiresAt: string; actorDid: string; purpose: string };
    expect(session).toMatchObject({ actorDid, purpose: "applicant-session" });
    expect(session).not.toHaveProperty("role");
    expect(session).not.toHaveProperty("vpEligible");
    expect((await post("/v1/actor-authentication/sessions", {
      challenge, signature: signatureFor(challenge),
    })).status).toBe(401);

    const authorization = `Bearer ${session.accessToken}`;
    const identity = await fetch(`${base}/v1/actor-authentication/session`, { headers: { authorization } });
    expect(identity.status).toBe(200);
    expect(await identity.json()).toEqual({ actorDid, actorKeyId, purpose: "applicant-session" });
    expect((await fetch(`${base}/v1/actor-authentication/session`, {
      method: "DELETE", headers: { authorization },
    })).status).toBe(204);
    expect((await fetch(`${base}/v1/actor-authentication/session`, { headers: { authorization } })).status).toBe(401);
  });

  it("lists only minimal request metadata for an authenticated applicant purpose", async () => {
    const listForSubjectDid = vi.fn(async (subjectDid: string) => subjectDid === actorDid ? [{
      subjectDid: actorDid,
      summary: { applicationId: "application:issuer:mine:v1", authorizationId: "auth:issuer:mine:v1",
        role: "issuer" as const, status: "pending" as const, createdAt: "2026-11-14T00:00:00.000Z" },
    }, {
      subjectDid: createMidnightDid("foreign-applicant"),
      summary: { applicationId: "application:issuer:foreign:v1", authorizationId: "auth:issuer:foreign:v1",
        role: "issuer" as const, status: "pending" as const, createdAt: "2026-11-14T00:00:00.000Z" },
    }] : []);
    await start(true, undefined, {
      register: async () => { throw new Error("not used"); }, listForSubjectDid,
    });
    const route = `${base}/v1/pending-applications`;
    expect((await fetch(route)).status).toBe(403);
    const challenge = await (await post("/v1/actor-authentication/challenges", {
      actorDid, actorKeyId, purpose: "applicant-session",
    })).json() as ActorAuthenticationChallenge;
    const sessionResponse = await post("/v1/actor-authentication/sessions", {
      challenge, signature: signatureFor(challenge),
    });
    const session = await sessionResponse.json() as { accessToken: string };
    const response = await fetch(route, { headers: { authorization: `Bearer ${session.accessToken}` } });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({ entries: [{
      applicationId: "application:issuer:mine:v1", authorizationId: "auth:issuer:mine:v1",
      role: "issuer", status: "pending", createdAt: "2026-11-14T00:00:00.000Z",
    }] });
    expect(listForSubjectDid).toHaveBeenCalledExactlyOnceWith(actorDid);

    const maintainerChallenge = await (await post("/v1/actor-authentication/challenges", {
      actorDid, actorKeyId, purpose: "maintainer-session",
    })).json() as ActorAuthenticationChallenge;
    const maintainerSession = await (await post("/v1/actor-authentication/sessions", {
      challenge: maintainerChallenge, signature: signatureFor(maintainerChallenge),
    })).json() as { accessToken: string };
    expect((await fetch(route, { headers: {
      authorization: `Bearer ${maintainerSession.accessToken}`,
    } })).status).toBe(403);
    expect(listForSubjectDid).toHaveBeenCalledTimes(1);
  });

  it("does not report an empty inbox when a signed-in host has no private list port", async () => {
    await start();
    const challenge = await (await post("/v1/actor-authentication/challenges", {
      actorDid, actorKeyId, purpose: "applicant-session",
    })).json() as ActorAuthenticationChallenge;
    const session = await (await post("/v1/actor-authentication/sessions", {
      challenge, signature: signatureFor(challenge),
    })).json() as { accessToken: string };
    const response = await fetch(`${base}/v1/pending-applications`, {
      headers: { authorization: `Bearer ${session.accessToken}` },
    });
    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toMatchObject({ status: 503 });
  });

  it("rejects foreign origins, non-JSON, wrong signatures, and expired sessions", async () => {
    await start();
    const path = "/v1/actor-authentication/challenges";
    const request = { actorDid, actorKeyId, purpose: "maintainer-session" };
    expect((await post(path, request, { origin: "https://unrelated.example" })).status).toBe(403);
    expect((await fetch(`${base}${path}`, {
      method: "POST", headers: { "content-type": "text/plain" }, body: JSON.stringify(request),
    })).status).toBe(415);
    const challenge = await (await post(path, request)).json() as ActorAuthenticationChallenge;
    expect((await post("/v1/actor-authentication/sessions", {
      challenge, signature: { ...signatureFor(challenge), value: `0x${"00".repeat(64)}` },
    })).status).toBe(401);
    const response = await post("/v1/actor-authentication/sessions", {
      challenge, signature: signatureFor(challenge),
    });
    expect(response.status).toBe(201);
    const session = await response.json() as { accessToken: string };
    nowMs += 15 * 60 * 1000;
    expect((await fetch(`${base}/v1/actor-authentication/session`, {
      headers: { authorization: `Bearer ${session.accessToken}` },
    })).status).toBe(401);
  });

  it("fails closed when the optional authentication service is absent", async () => {
    await start(false);
    expect((await post("/v1/actor-authentication/challenges", {
      actorDid, actorKeyId, purpose: "applicant-session",
    })).status).toBe(503);
  });

  it("keeps applicant and maintainer purposes separate and loses tokens on restart", () => {
    nowMs = START;
    const first = createActorSessionService(() => nowMs);
    const session = first.issue({ actorDid, actorKeyId, purpose: "applicant-session" });
    const bearer = `Bearer ${session.accessToken}`;
    expect(first.authenticate(bearer, "applicant-session")).toMatchObject({ actorDid });
    expect(first.authenticate(`bearer ${session.accessToken}`, "applicant-session")).toMatchObject({ actorDid });
    expect(first.authenticate(bearer, "maintainer-session")).toBeNull();
    expect(createActorSessionService(() => nowMs).authenticate(bearer)).toBeNull();
  });

  it("requires an applicant session matching the host identity before VP intake", async () => {
    let authorizeCalls = 0;
    let hostDid = actorDid;
    const applicationVp: ApplicationVpHttpPort = {
      challengeStore: new InMemoryApplicationChallengeStore(),
      authorizeRequest: async () => { authorizeCalls += 1; return hostDid; },
      resolvePendingApplication: async () => null,
      verifyPresentation: async () => { throw new Error("VP not reached"); },
      signEvidence: async () => { throw new Error("VP not reached"); },
      verifyEvidenceSignature: () => false,
      persistRedactedEvidence: async () => { throw new Error("VP not reached"); },
    };
    await start(true, applicationVp);
    const bindingPath = `${base}/v1/application-evidence/application:issuer:one/binding`;
    expect((await fetch(bindingPath)).status).toBe(403);
    expect(authorizeCalls).toBe(0);

    const challenge = await (await post("/v1/actor-authentication/challenges", {
      actorDid, actorKeyId, purpose: "applicant-session",
    })).json() as ActorAuthenticationChallenge;
    const session = await (await post("/v1/actor-authentication/sessions", {
      challenge, signature: signatureFor(challenge),
    })).json() as { accessToken: string };
    hostDid = createMidnightDid("different-vp-host-identity");
    const authorization = `Bearer ${session.accessToken}`;
    expect((await fetch(bindingPath, { headers: { authorization } })).status).toBe(403);
    hostDid = actorDid;
    expect((await fetch(bindingPath, { headers: { authorization } })).status).toBe(404);
    expect(authorizeCalls).toBe(2);
  });

  it("bounds sessions per DID without denying a different actor and rejects expired revocation", () => {
    nowMs = START;
    const sessions = createActorSessionService(() => nowMs);
    const identity = { actorDid, actorKeyId, purpose: "applicant-session" as const };
    const tokens = Array.from({ length: 5 }, () => sessions.issue(identity).accessToken);
    expect(sessions.authenticate(`Bearer ${tokens[0]}`)).toBeNull();
    expect(sessions.authenticate(`Bearer ${tokens[4]}`)).toMatchObject({ actorDid });
    const otherDid = createMidnightDid("different-http-authentication-actor");
    const other = sessions.issue({
      actorDid: otherDid, actorKeyId: `${otherDid}#auth-1`, purpose: "applicant-session",
    });
    expect(sessions.authenticate(`Bearer ${other.accessToken}`)).toMatchObject({ actorDid: otherDid });
    nowMs += 15 * 60 * 1000;
    expect(sessions.revoke(`Bearer ${tokens[4]}`)).toBe(false);
  });
});
