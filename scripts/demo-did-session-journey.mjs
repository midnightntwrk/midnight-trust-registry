import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
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
import {
  actorAuthenticationDigestBytes,
  computeAuthorizationScopeCommitment,
  computePendingApplicationPayloadCommitment,
  computeSignedPendingApplicationCommitment,
  issuerGovernedResourceId,
  mutationIntentDigestBytes,
} from "../packages/trust-registry-domain/dist/index.js";
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
  InMemoryPendingApplicationRegistrationPort,
  computeOperatorWorkspaceCommitment,
} from "../packages/trust-registry-api/dist/index.js";
import { listApplicantApplications, registerApplicantApplication, signInActorDid, signOutActorDid } from "../packages/trust-registry-client/dist/browser-authentication.js";

const seed = new Uint8Array(32).fill(86);
const actorDid = createMidnightDid("headless-did-authentication");
const actorKeyId = `${actorDid}#auth-1`;
let now = Date.now();
const directory = await mkdtemp(join(tmpdir(), "tr-headless-did-auth-"));
const workspace = createOperatorWorkspace({ label: "did-auth-headless" });
const registryId = workspace.snapshot.registry.registryId;
const serverOptions = {
  source: createInMemorySource(workspace.snapshot),
};
const server = createTrustRegistryApiServer(serverOptions);

async function runActorCli(command, apiBase, input) {
  const child = spawn(process.execPath, ["packages/trust-registry-cli/bin/trust-registry.mjs",
    command, "--api-base", apiBase],
  { cwd: process.cwd(), stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
  child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
  const exit = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  child.stdin.end(JSON.stringify(input));
  const code = await exit;
  assert.equal(stdout.includes(input.session.accessToken), false);
  assert.equal(stderr.includes(input.session.accessToken), false);
  return { code, stdout, stderr };
}

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
        registryId,
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
  const registration = new InMemoryPendingApplicationRegistrationPort({
    workspace, applications: [], consumedNonces: [],
  }, actorDid, resolver);
  serverOptions.pendingApplicationRegistration = {
    register: (request, date) => registration.register(request, date),
    readForSubjectDid: (subjectDid, applicationId) => registration.readForSubjectDid(subjectDid, applicationId),
    listForSubjectDid: async (subjectDid) => [
      ...(subjectDid === actorDid ? [{
        subjectDid: actorDid,
        summary: { applicationId: "application:issuer:headless:v1", authorizationId: "auth:issuer:headless:v1",
          role: "issuer", status: "pending", createdAt: new Date(now).toISOString() },
      }] : []),
      ...await registration.listForSubjectDid(subjectDid),
    ],
  };
  serverOptions.authorizePendingApplicationRegistration = async (request) => {
    if (sessions.authenticate(request.headers.authorization, "applicant-session")?.actorDid !== actorDid) {
      throw new Error("Applicant session required");
    }
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
  const applicationId = "application:maintainer:cli-headless:v1";
  const authorizationId = "auth:maintainer:cli-headless:v1";
  const scope = { version: "tr-scope-v1", role: "maintainer", registryId };
  const governedResource = { type: "registry", id: registryId };
  const payload = { applicationId, authorizationId, scope, governedResource };
  const intent = {
    version: "tr-mutation-intent-v1", registryId, actorDid, actorKeyId,
    actorRole: "applicant", action: "apply", target: "maintainer", targetId: applicationId,
    scopeCommitment: computeAuthorizationScopeCommitment(scope),
    payloadCommitment: computePendingApplicationPayloadCommitment(payload),
    nonce: `0x${"33".repeat(32)}`,
    expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(workspace),
    expectedEpochId: workspace.snapshot.currentEpoch.epochId,
    issuedAt: new Date(now - 10_000).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
  };
  const signedRequest = { ...payload, intent, signature: {
    keyId: actorKeyId, algorithm: "jubjub-schnorr",
    value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
      seed, mutationIntentDigestBytes(intent),
    ))).toString("hex")}`,
  } };
  const cliSession = { ...session, origin, registryId, genesisHash: challenge.genesisHash,
    contractAddress: challenge.contractAddress };
  const wrongOrigin = await runActorCli("api-register", "https://foreign.example",
    { session: cliSession, request: signedRequest });
  assert.equal(wrongOrigin.code, 1);
  assert.match(wrongOrigin.stderr, /same trusted API origin/u);
  const wrongActor = await runActorCli("api-register", origin, {
    session: { ...cliSession, actorDid: `did:midnight:undeployed:${"cc".repeat(32)}` },
    request: signedRequest,
  });
  assert.equal(wrongActor.code, 1);
  assert.match(wrongActor.stderr, /does not match/u);
  const acceptedCli = await runActorCli("api-register", origin, { session: cliSession, request: signedRequest });
  assert.equal(acceptedCli.code, 0, acceptedCli.stderr);
  const registered = JSON.parse(acceptedCli.stdout);
  assert.equal(registered.status, "pending");
  assert.equal(registered.binding.applicationId, applicationId);
  assert.equal(registered.binding.subjectDid, actorDid);
  const replayCli = await runActorCli("api-register", origin, { session: cliSession, request: signedRequest });
  assert.equal(replayCli.code, 1);
  assert.match(replayCli.stderr, /HTTP 409/u);
  const listCli = await runActorCli("api-applications", origin, { session: cliSession });
  assert.equal(listCli.code, 0, listCli.stderr);
  assert.deepEqual(JSON.parse(listCli.stdout).entries.map((entry) => entry.applicationId).sort(),
    ["application:issuer:headless:v1", applicationId].sort());
  const lostScope = { version: "tr-scope-v1", role: "issuer",
    credentialFamilyId: "headless-lost-response", schemaId: "headless-schema",
    schemaVersion: "1.0.0", credentialDefinitionId: "headless-definition",
    statusMethod: "headless-status" };
  const lostPayload = {
    applicationId: "application:issuer:cli-lost-response:v1",
    authorizationId: "auth:issuer:cli-lost-response:v1", scope: lostScope,
    governedResource: { type: "credentialFamily", id: issuerGovernedResourceId(lostScope, "credentialFamily") },
  };
  const lostIntent = { ...intent, target: "issuer", targetId: lostPayload.applicationId,
    scopeCommitment: computeAuthorizationScopeCommitment(lostScope),
    payloadCommitment: computePendingApplicationPayloadCommitment(lostPayload),
    nonce: `0x${"44".repeat(32)}` };
  const lostRequest = { ...lostPayload, intent: lostIntent, signature: {
    keyId: actorKeyId, algorithm: "jubjub-schnorr",
    value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
      seed, mutationIntentDigestBytes(lostIntent),
    ))).toString("hex")}`,
  } };
  let acceptedStatus;
  await assert.rejects(registerApplicantApplication({
    apiBase: origin, pageOrigin: origin, session: cliSession, request: lostRequest,
    fetchImpl: async (...args) => {
      const accepted = await fetch(...args);
      acceptedStatus = accepted.status;
      throw new Error("response lost after server acceptance");
    },
  }), /outcome is unknown.*Do not resubmit/u);
  assert.equal(acceptedStatus, 201);
  const afterLostResponse = await runActorCli("api-applications", origin, { session: cliSession });
  assert.equal(afterLostResponse.code, 0, afterLostResponse.stderr);
  assert.equal(JSON.parse(afterLostResponse.stdout).entries.some(
    (entry) => entry.applicationId === lostPayload.applicationId,
  ), true);
  const reconciled = await runActorCli("api-reconcile", origin, { session: cliSession, request: lostRequest });
  assert.equal(reconciled.code, 0, reconciled.stderr);
  assert.equal(JSON.parse(reconciled.stdout).status, "observed");
  assert.equal(JSON.parse(reconciled.stdout).record.requestCommitment,
    computeSignedPendingApplicationCommitment(lostRequest));
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
    apiBase: origin, pageOrigin: origin, registryId,
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
    apiBase: origin, pageOrigin: origin, registryId,
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
    apiBase: origin, pageOrigin: origin, registryId,
    purpose: "applicant-session", clock: () => now,
    signer: {
      getIdentity: async () => ({ actorDid, actorKeyId }),
      signDigest: async ({ digest }) => ({ keyId: actorKeyId, algorithm: "jubjub-schnorr",
        value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(seed, digest))).toString("hex")}` }),
    },
  });
  const expiringList = await listApplicantApplications({ apiBase: origin, pageOrigin: origin,
    session: expiringSession, clock: () => now });
  assert.equal(expiringList.status, "available");
  assert.deepEqual(expiringList.entries.map((entry) => entry.applicationId).sort(),
    ["application:issuer:headless:v1", applicationId, lostPayload.applicationId].sort());
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
  process.stdout.write("[did-auth-headless] Ledger and off-chain DID challenge sessions; executable CLI signed registration, applicant list, replay and origin denial; a lost response remains unknown until exact signed-request reconciliation observes intake; private-list isolation, expiry, and revocation passed. No role grant or deployed finality was inferred.\n");
} finally {
  server.closeAllConnections();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  await rm(directory, { recursive: true, force: true });
}
