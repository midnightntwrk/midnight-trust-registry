import { Buffer } from "node:buffer";
import type { Server } from "node:http";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signJubjubPayloadFromSeed,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { createOperatorWorkspace } from "@midnight-ntwrk/trust-registry-cli";
import { actorAuthenticationDigestBytes, type ActorAuthenticationChallenge } from "@midnight-ntwrk/trust-registry-domain";
import {
  createMidnightDid,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
} from "@midnight-ntwrk/trust-registry-integration";
import { afterEach, describe, expect, it } from "vitest";

import { createActorAuthenticationService, type ActorAuthenticationChallengeStore } from "../actor-authentication.js";
import { createActorSessionService } from "../actor-sessions.js";
import { InMemoryApplicationChallengeStore } from "../application-challenges.js";
import type { ApplicationVpHttpPort } from "../application-vp-http.js";
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

  async function start(configured = true, applicationVp?: ApplicationVpHttpPort) {
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
      resolver, store: challengeStore(), clock: () => nowMs,
    });
    server = createTrustRegistryApiServer({
      source: createInMemorySource(createOperatorWorkspace({ label: "actor-auth-http" }).snapshot),
      ...(configured ? { actorAuthentication: { challenges, sessions: createActorSessionService(() => nowMs) } } : {}),
      ...(applicationVp === undefined ? {} : { applicationVp }),
    });
    base = await listen(server);
  }

  const post = (path: string, body: unknown, headers: Record<string, string> = {}) => fetch(`${base}${path}`, {
    method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body),
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
