import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync, sign as signEd25519 } from "node:crypto";
import { createServer } from "node:net";
import { cp, mkdir, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createLongFormOffchainMidnightDIDString, CurveType, KeyType } from "@midnight-ntwrk/midnight-did-domain";

import { createOperatorWorkspace, writeWorkspaceToFile } from "../packages/trust-registry-cli/dist/index.js";
import { signInActorDid, signOutActorDid } from "@midnight-ntwrk/trust-registry-client/browser-authentication";
import { actorAuthenticationDigestBytes } from "../packages/trust-registry-domain/dist/index.js";

const directory = await mkdtemp(join(tmpdir(), "tr-fixture-offchain-cli-"));
const workspacePath = join(directory, "workspace.json");
const challengeStorePath = join(directory, "challenges.json");
const portalRoot = join(directory, "portals");
const reservePort = async () => {
  const listener = createServer();
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const address = listener.address();
  if (address === null || typeof address === "string") throw new Error("Expected loopback port");
  await new Promise((resolve) => listener.close(resolve));
  return address.port;
};
const port = await reservePort();
const origin = `http://127.0.0.1:${port}`;

async function startHost() {
  const child = spawn(process.execPath, ["packages/trust-registry-api/bin/trust-registry-api.mjs",
    "serve", "--workspace", workspacePath, "--port", String(port),
    "--fixture-offchain-auth-store", challengeStorePath,
    "--fixture-portal-root", portalRoot], {
    cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  let errorOutput = "";
  const exited = new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
  child.stderr.on("data", (chunk) => { errorOutput += chunk.toString(); });
  try {
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error(`API startup timed out: ${errorOutput}`)), 10_000);
      const done = (error) => { clearTimeout(timeout); error ? reject(error) : resolve(); };
      child.stdout.on("data", (chunk) => {
        output += chunk.toString();
        if (output.includes(`trust-registry-api listening on ${origin}\n`)
          && output.includes("Fixture off-chain DID sign-in enabled")) done();
      });
      child.once("exit", (code) => done(new Error(`API exited before startup (${code}): ${errorOutput}`)));
      child.once("error", done);
    });
  } catch (error) {
    if (child.exitCode === null) child.kill("SIGTERM");
    await exited;
    throw error;
  }
  return {
    async stop() {
      if (child.exitCode === null) child.kill("SIGTERM");
      const result = await exited;
      assert.equal(result.code, 0, `API exited unexpectedly: ${errorOutput}`);
    },
  };
}

async function expectStatus(response, status) {
  const body = await response.json();
  assert.equal(response.status, status, `HTTP ${response.status}: ${JSON.stringify(body)}`);
  return body;
}

async function post(path, body, requestOrigin = origin) {
  return fetch(`${origin}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: requestOrigin },
    body: JSON.stringify(body),
  });
}

let host;
try {
  await writeWorkspaceToFile(workspacePath, createOperatorWorkspace({ label: "fixture-offchain-cli" }));
  await mkdir(portalRoot);
  for (const role of ["admin", "applicant"]) {
    await cp(join("packages", `trust-registry-${role === "admin" ? "admin-console" : "applicant-portal"}`, "dist"),
      join(portalRoot, role), { recursive: true });
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const actorDid = createLongFormOffchainMidnightDIDString({
    version: 1, alsoKnownAs: [],
    verificationMethod: [{
      id: "./keys#auth",
      publicKeyJwk: { kty: KeyType.OKP, crv: CurveType.Ed25519, x: publicJwk.x },
      relationships: { authentication: true, assertionMethod: false, keyAgreement: false,
        capabilityInvocation: false, capabilityDelegation: false },
    }],
    service: [],
  });
  const actorKeyId = `${actorDid}/keys#auth`;
  host = await startHost();
  for (const role of ["admin", "applicant"]) {
    const portal = await fetch(`${origin}/${role}/`);
    assert.equal(portal.status, 200);
    assert.match(portal.headers.get("content-security-policy"), /connect-src 'self'/u);
    assert.match(await portal.text(), /Trust Registry/u);
  }
  const challengeRoute = "/v1/actor-authentication/challenges";
  const sessionRoute = "/v1/actor-authentication/sessions";
  const body = { actorDid, actorKeyId, purpose: "applicant-session" };
  await expectStatus(await post(challengeRoute, body, "https://other.example"), 403);
  const challenge = await expectStatus(await post(challengeRoute, body), 201);
  assert.equal(challenge.version, "tr-actor-authentication-offchain-v1");
  assert.equal(challenge.origin, origin);
  const signature = { keyId: actorKeyId, algorithm: "ed25519",
    value: `0x${signEd25519(null, actorAuthenticationDigestBytes(challenge), privateKey).toString("hex")}` };
  await expectStatus(await post(sessionRoute, { challenge, signature: {
    ...signature, value: `0x${"00".repeat(64)}` } }), 401);
  const session = await expectStatus(await post(sessionRoute, { challenge, signature }), 201);
  assert.equal(session.actorDid, actorDid);
  assert.equal(Object.hasOwn(session, "role"), false);
  assert.equal(Object.hasOwn(session, "vpEligible"), false);
  await expectStatus(await post(sessionRoute, { challenge, signature }), 401);
  const workspace = JSON.parse(await readFile(workspacePath, "utf8"));
  assert.match(workspace.workspaceInstanceId, /^[0-9a-f-]{36}$/u);
  const fixtureHash = (kind) => `0x${createHash("sha256")
    .update(JSON.stringify(["tr:fixture:actor-auth:v1", kind, workspace.workspaceInstanceId,
      challenge.registryId])).digest("hex")}`;
  const expectedGenesisHash = fixtureHash("genesis");
  const contractAddress = fixtureHash("contract");
  assert.equal(challenge.genesisHash, expectedGenesisHash);
  assert.equal(challenge.contractAddress, contractAddress);
  let signedChallenges = 0;
  const signer = {
    getIdentity: async () => ({ actorDid, actorKeyId }),
    signDigest: async ({ digest }) => {
      signedChallenges += 1;
      return { keyId: actorKeyId, algorithm: "ed25519",
        value: `0x${signEd25519(null, digest, privateKey).toString("hex")}` };
    },
  };
  const clientInput = { apiBase: origin, pageOrigin: origin, registryId: challenge.registryId,
    purpose: "applicant-session", signer };
  await assert.rejects(signInActorDid({ ...clientInput,
    deploymentIdentity: { expectedGenesisHash: `0x${"ff".repeat(32)}`, contractAddress },
  }), /does not match this actor and registry/u);
  assert.equal(signedChallenges, 0);
  const clientSession = await signInActorDid({
    ...clientInput,
    deploymentIdentity: { expectedGenesisHash, contractAddress },
  });
  assert.equal(clientSession.actorDid, actorDid);
  assert.equal(clientSession.purpose, "applicant-session");
  assert.equal(Object.hasOwn(clientSession, "role"), false);
  assert.equal(signedChallenges, 1);
  const privateList = "/v1/pending-applications";
  await expectStatus(await fetch(`${origin}${privateList}`), 403);
  await expectStatus(await fetch(`${origin}${privateList}`, {
    headers: { authorization: `Bearer ${clientSession.accessToken}` },
  }), 503);
  const maintainerSession = await signInActorDid({
    ...clientInput, purpose: "maintainer-session",
    deploymentIdentity: { expectedGenesisHash, contractAddress },
  });
  assert.equal(maintainerSession.purpose, "maintainer-session");
  assert.equal(Object.hasOwn(maintainerSession, "role"), false);
  await expectStatus(await fetch(`${origin}${privateList}`, {
    headers: { authorization: `Bearer ${maintainerSession.accessToken}` },
  }), 403);
  await signOutActorDid({ apiBase: origin, pageOrigin: origin, session: clientSession });
  await signOutActorDid({ apiBase: origin, pageOrigin: origin, session: maintainerSession });
  await expectStatus(await fetch(`${origin}/v1/actor-authentication/session`, {
    headers: { authorization: `Bearer ${clientSession.accessToken}` },
  }), 401);
  const ledgerDid = `did:midnight:undeployed:${"ab".repeat(32)}`;
  await expectStatus(await post(challengeRoute, { actorDid: ledgerDid,
    actorKeyId: `${ledgerDid}#auth-1`, purpose: "applicant-session" }), 400);
  const challengeStat = await stat(challengeStorePath);
  assert.equal(challengeStat.mode & 0o077, 0);

  await host.stop();
  host = undefined;
  host = await startHost();
  await expectStatus(await post(sessionRoute, { challenge, signature }), 401);
  await expectStatus(await fetch(`${origin}/v1/actor-authentication/session`, {
    headers: { authorization: `Bearer ${session.accessToken}` },
  }), 401);
  const newChallenge = await expectStatus(await post(challengeRoute, body), 201);
  assert.equal(newChallenge.genesisHash, challenge.genesisHash);
  assert.equal(newChallenge.contractAddress, challenge.contractAddress);
  process.stdout.write("[fixture-offchain-cli] Packaged same-origin portals, typed client, and loopback API accept off-chain DID sign-in only; invalid signature, origin, ledger DID, replay, cross-purpose private read, sign-out reuse, and restart session revival denied. Applicant private list remains unavailable without a registration adapter. No role, VP, or deployed binding inferred.\n");
} finally {
  if (host !== undefined) await host.stop();
  await rm(directory, { recursive: true, force: true });
}
