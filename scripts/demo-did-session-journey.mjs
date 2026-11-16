import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { generateKeyPairSync, sign as signEd25519 } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signJubjubPayloadFromSeed,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { createLongFormOffchainMidnightDIDString, CurveType, KeyType } from "@midnight-ntwrk/midnight-did-domain";

import { createOperatorWorkspace } from "../packages/trust-registry-cli/dist/index.js";
import { actorAuthenticationDigestBytes } from "../packages/trust-registry-domain/dist/index.js";
import {
  createMidnightDid,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  createActorAuthenticationService,
  createActorSessionService,
  createInMemorySource,
  createTrustRegistryApiServer,
  FileActorAuthenticationChallengeStore,
} from "../packages/trust-registry-api/dist/index.js";
import { listApplicantApplications, signInActorDid, signOutActorDid } from "../packages/trust-registry-client/dist/browser-authentication.js";

const seed = new Uint8Array(32).fill(86);
const actorDid = createMidnightDid("headless-did-authentication");
const actorKeyId = `${actorDid}#auth-1`;
let now = Date.parse("2026-11-15T00:00:00.000Z");
const directory = await mkdtemp(join(tmpdir(), "tr-headless-did-auth-"));
const serverOptions = {
  source: createInMemorySource(createOperatorWorkspace({ label: "did-auth-headless" }).snapshot),
};
const server = createTrustRegistryApiServer(serverOptions);

async function expectStatus(response, expected) {
  const body = response.status === 204 ? undefined : await response.json();
  assert.equal(response.status, expected, `HTTP ${response.status}: ${JSON.stringify(body)}`);
  return body;
}

try {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Expected loopback TCP address");
  const origin = `http://127.0.0.1:${address.port}`;
  const resolver = createMidnightDidResolver([
    createMidnightDidLedgerFixture(actorDid, {
      verificationMethodId: "auth-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(seed),
    }),
  ]);
  const sessions = createActorSessionService(() => now);
  serverOptions.actorAuthentication = {
    challenges: createActorAuthenticationService({
      context: {
        registryId: "tr:registry:headless",
        genesisHash: `0x${"11".repeat(32)}`,
        contractAddress: `0x${"22".repeat(32)}`,
        origin,
      },
      resolver,
      store: new FileActorAuthenticationChallengeStore(join(directory, "challenges.json"), () => now),
      clock: () => now,
    }),
    sessions,
  };
  serverOptions.pendingApplicationRegistration = {
    register: async () => { throw new Error("Not used by the private-list journey"); },
    listForSubjectDid: async (subjectDid) => subjectDid === actorDid ? [{
      subjectDid: actorDid,
      summary: { applicationId: "application:issuer:headless:v1", authorizationId: "auth:issuer:headless:v1",
        role: "issuer", status: "pending", createdAt: new Date(now).toISOString() },
    }] : [],
  };
  const post = (route, body, requestOrigin = origin) => fetch(`${origin}${route}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: requestOrigin },
    body: JSON.stringify(body),
  });
  const challengeRoute = "/v1/actor-authentication/challenges";
  const sessionRoute = "/v1/actor-authentication/sessions";
  await expectStatus(await post(challengeRoute, {
    actorDid, actorKeyId, purpose: "applicant-session",
  }, "https://unrelated.example"), 403);
  const challengeResponse = await post(challengeRoute, { actorDid, actorKeyId, purpose: "applicant-session" });
  assert.equal(challengeResponse.headers.get("access-control-allow-origin"), null);
  const challenge = await expectStatus(challengeResponse, 201);
  assert.equal(challenge.origin, origin);
  const signature = {
    keyId: actorKeyId,
    algorithm: "jubjub-schnorr",
    value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
      seed, actorAuthenticationDigestBytes(challenge),
    ))).toString("hex")}`,
  };
  const wrongSignature = {
    ...signature,
    value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
      new Uint8Array(32).fill(87), actorAuthenticationDigestBytes(challenge),
    ))).toString("hex")}`,
  };
  await expectStatus(await post(sessionRoute, { challenge, signature: wrongSignature }), 401);
  await expectStatus(await post(sessionRoute, {
    challenge: { ...challenge, contractAddress: `0x${"33".repeat(32)}` }, signature,
  }), 401);
  await expectStatus(await post(sessionRoute, { challenge, signature }, "https://unrelated.example"), 403);
  const session = await expectStatus(await post(sessionRoute, { challenge, signature }), 201);
  assert.equal(session.actorDid, actorDid);
  assert.equal(session.purpose, "applicant-session");
  assert.equal(Object.hasOwn(session, "role"), false);
  assert.equal(Object.hasOwn(session, "vpEligible"), false);
  await expectStatus(await post(sessionRoute, { challenge, signature }), 401);
  const bearer = { authorization: `Bearer ${session.accessToken}` };
  await expectStatus(await fetch(`${origin}/v1/pending-applications`), 403);
  assert.deepEqual(await expectStatus(await fetch(`${origin}/v1/pending-applications`, {
    headers: bearer,
  }), 200), { entries: [{ applicationId: "application:issuer:headless:v1",
    authorizationId: "auth:issuer:headless:v1", role: "issuer", status: "pending",
    createdAt: new Date(now).toISOString() }] });
  const identity = await expectStatus(await fetch(`${origin}/v1/actor-authentication/session`, { headers: bearer }), 200);
  assert.deepEqual(identity, { actorDid, actorKeyId, purpose: "applicant-session" });
  await expectStatus(await fetch(`${origin}/v1/actor-authentication/session`, {
    method: "DELETE", headers: bearer,
  }), 204);
  await expectStatus(await fetch(`${origin}/v1/actor-authentication/session`, { headers: bearer }), 401);
  await expectStatus(await fetch(`${origin}/v1/pending-applications`, { headers: bearer }), 403);

  const maintainerChallenge = await expectStatus(await post(challengeRoute, {
    actorDid, actorKeyId, purpose: "maintainer-session",
  }), 201);
  const maintainerSignature = {
    ...signature,
    value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
      seed, actorAuthenticationDigestBytes(maintainerChallenge),
    ))).toString("hex")}`,
  };
  const maintainerSession = await expectStatus(await post(sessionRoute, {
    challenge: maintainerChallenge, signature: maintainerSignature,
  }), 201);
  assert.equal(maintainerSession.purpose, "maintainer-session");
  assert.equal(Object.hasOwn(maintainerSession, "role"), false);
  assert.equal(Object.hasOwn(maintainerSession, "vpEligible"), false);
  await expectStatus(await post(sessionRoute, {
    challenge: maintainerChallenge, signature: maintainerSignature,
  }), 401);
  const maintainerBearer = { authorization: `Bearer ${maintainerSession.accessToken}` };
  await expectStatus(await fetch(`${origin}/v1/pending-applications`, { headers: maintainerBearer }), 403);
  assert.equal(sessions.authenticate(maintainerBearer.authorization, "applicant-session"), null);
  assert.deepEqual(sessions.authenticate(maintainerBearer.authorization, "maintainer-session"), {
    actorDid, actorKeyId, purpose: "maintainer-session",
  });
  await expectStatus(await fetch(`${origin}/v1/actor-authentication/session`, {
    method: "DELETE", headers: maintainerBearer,
  }), 204);
  await expectStatus(await fetch(`${origin}/v1/actor-authentication/session`, {
    headers: maintainerBearer,
  }), 401);
  const clientSession = await signInActorDid({
    apiBase: origin, pageOrigin: origin, registryId: "tr:registry:headless",
    purpose: "maintainer-session", clock: () => now,
    signer: {
      getIdentity: async () => ({ actorDid, actorKeyId }),
      signDigest: async ({ digest }) => ({ keyId: actorKeyId, algorithm: "jubjub-schnorr",
        value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(seed, digest))).toString("hex")}` }),
    },
  });
  assert.equal(clientSession.purpose, "maintainer-session");
  assert.equal(Object.hasOwn(clientSession, "role"), false);
  assert.equal(sessions.authenticate(`Bearer ${clientSession.accessToken}`, "applicant-session"), null);
  assert.deepEqual(sessions.authenticate(`Bearer ${clientSession.accessToken}`, "maintainer-session"), {
    actorDid, actorKeyId, purpose: "maintainer-session",
  });
  await signOutActorDid({ apiBase: origin, pageOrigin: origin, session: clientSession });
  assert.equal(sessions.authenticate(`Bearer ${clientSession.accessToken}`, "maintainer-session"), null);

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const offchainDid = createLongFormOffchainMidnightDIDString({
    version: 1,
    alsoKnownAs: [],
    verificationMethod: [{
      id: "./keys#auth",
      publicKeyJwk: { kty: KeyType.OKP, crv: CurveType.Ed25519, x: publicJwk.x },
      relationships: { authentication: true, assertionMethod: false, keyAgreement: false,
        capabilityInvocation: false, capabilityDelegation: false },
    }],
    service: [],
  });
  const offchainKeyId = `${offchainDid}/keys#auth`;
  const offchainSession = await signInActorDid({
    apiBase: origin, pageOrigin: origin, registryId: "tr:registry:headless",
    purpose: "applicant-session", clock: () => now,
    signer: {
      getIdentity: async () => ({ actorDid: offchainDid, actorKeyId: offchainKeyId }),
      signDigest: async ({ digest }) => ({ keyId: offchainKeyId, algorithm: "ed25519",
        value: `0x${signEd25519(null, digest, privateKey).toString("hex")}` }),
    },
  });
  assert.equal(offchainSession.actorDid, offchainDid);
  assert.equal(Object.hasOwn(offchainSession, "role"), false);
  assert.deepEqual(await listApplicantApplications({ apiBase: origin, pageOrigin: origin,
    session: offchainSession, clock: () => now }), { status: "available", entries: [] });
  assert.equal(sessions.authenticate(`Bearer ${offchainSession.accessToken}`, "maintainer-session"), null);
  await signOutActorDid({ apiBase: origin, pageOrigin: origin, session: offchainSession });
  assert.equal(sessions.authenticate(`Bearer ${offchainSession.accessToken}`, "applicant-session"), null);

  const expiringSession = await signInActorDid({
    apiBase: origin, pageOrigin: origin, registryId: "tr:registry:headless",
    purpose: "applicant-session", clock: () => now,
    signer: {
      getIdentity: async () => ({ actorDid, actorKeyId }),
      signDigest: async ({ digest }) => ({ keyId: actorKeyId, algorithm: "jubjub-schnorr",
        value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(seed, digest))).toString("hex")}` }),
    },
  });
  assert.deepEqual(await listApplicantApplications({ apiBase: origin, pageOrigin: origin,
    session: expiringSession, clock: () => now }), {
    status: "available", entries: [{ applicationId: "application:issuer:headless:v1",
      authorizationId: "auth:issuer:headless:v1", role: "issuer", status: "pending",
      createdAt: new Date(now).toISOString() }],
  });
  const expiringChallenge = await expectStatus(await post(challengeRoute, {
    actorDid, actorKeyId, purpose: "applicant-session",
  }), 201);
  const expiringSignature = {
    ...signature,
    value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
      seed, actorAuthenticationDigestBytes(expiringChallenge),
    ))).toString("hex")}`,
  };
  now = Date.parse(expiringChallenge.expiresAt);
  await expectStatus(await post(sessionRoute, {
    challenge: expiringChallenge, signature: expiringSignature,
  }), 401);
  const expiringBearer = { authorization: `Bearer ${expiringSession.accessToken}` };
  await expectStatus(await fetch(`${origin}/v1/actor-authentication/session`, { headers: expiringBearer }), 200);
  now = Date.parse(expiringSession.expiresAt);
  await expectStatus(await fetch(`${origin}/v1/actor-authentication/session`, { headers: expiringBearer }), 401);
  await assert.rejects(listApplicantApplications({ apiBase: origin, pageOrigin: origin,
    session: expiringSession, clock: () => now }), /current applicant DID session/u);
  process.stdout.write("[did-auth-headless] Ledger and off-chain DID challenge sessions, shared-client applicant-only populated and empty request lists, bad-signature and deployment-context denial, one-use replay, origin denial, purpose isolation, identity-only claims, exact-boundary challenge/session expiry, and revocation passed. No role grant or deployed finality was inferred.\n");
} finally {
  server.closeAllConnections();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  await rm(directory, { recursive: true, force: true });
}
