import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { request as httpRequest } from "node:http";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  encodeJubjubSignature,
  payloadToJubjubDigest,
  signJubjubDigest,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";

import { createOperatorWorkspace } from "../packages/trust-registry-cli/dist/index.js";
import { sha256Hex } from "../packages/trust-registry-domain/dist/index.js";
import {
  prepareAuditorApplication,
  signPreparedAuditorApplication,
} from "../packages/trust-registry-applicant-portal/dist/auditor-application.js";
import {
  prepareIssuerApplication,
  prepareVerifierApplication,
  signPreparedMembershipApplication,
} from "../packages/trust-registry-applicant-portal/dist/membership-application.js";
import {
  createApplicationVpIntakePorts,
  createApplicationVpScenarioFixture,
  createMidnightDid,
  VP_FIXTURE_TIME_MS,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  InMemoryApplicationChallengeStore,
  InMemoryPendingApplicationRegistrationPort,
  computeOperatorWorkspaceCommitment,
  createTrustRegistryApiServer,
} from "../packages/trust-registry-api/dist/index.js";
import { createStaticAssetHandler } from "./serve-static.mjs";

const command = process.argv[2] ?? "serve";
const NOW = new Date(VP_FIXTURE_TIME_MS).toISOString();
const subjectDid = createMidnightDid("vp-holder");
const evidenceVerifierDid = createMidnightDid("vp-evidence-verifier");
const applicationId = "application:auditor:local-demo:v1";
const scope = {
  version: "tr-scope-v1",
  role: "auditor",
  requestProfileId: "audit-profile:local-demo:v1",
  purpose: "compliance-review",
  credentialScopeCommitment: `0x${"11".repeat(32)}`,
  allowedAttributes: ["company-id"],
  allowedPredicates: ["is-licensed"],
  disclosureLevel: "restricted",
};
const issuerScope = {
  version: "tr-scope-v1", role: "issuer", credentialFamilyId: "family:degree:v1",
  schemaId: "schema:degree", schemaVersion: "1.0.0",
  credentialDefinitionId: "definition:degree:v1", statusMethod: "status:registry:v1",
};
const verifierScope = {
  version: "tr-scope-v1", role: "verifier", requestProfileId: "profile:age-gate:v1",
  purpose: "age-gate", credentialScopeCommitment: `0x${"aa".repeat(32)}`,
  allowedAttributes: ["attribute:age"], allowedPredicates: ["predicate:over-18"],
  disclosureLevel: "minimal",
};
const scopes = { auditor: scope, issuer: issuerScope, verifier: verifierScope };
export const applicationDraft = {
  applicationId,
  authorizationId: "auth:auditor:local-demo:v1",
  actorDid: subjectDid,
  actorKeyId: `${subjectDid}#auth-1`,
  requestProfileId: scope.requestProfileId,
  purpose: scope.purpose,
  credentialScopeCommitment: scope.credentialScopeCommitment,
  allowedAttributes: scope.allowedAttributes,
  allowedPredicates: scope.allowedPredicates,
  disclosureLevel: scope.disclosureLevel,
};
const issuerDraft = {
  applicationId: "application:issuer:local-demo:v1", authorizationId: "auth:issuer:local-demo:v1",
  actorDid: subjectDid, actorKeyId: `${subjectDid}#auth-1`,
  credentialFamilyId: issuerScope.credentialFamilyId, schemaId: issuerScope.schemaId,
  schemaVersion: issuerScope.schemaVersion, credentialDefinitionId: issuerScope.credentialDefinitionId,
  statusMethod: issuerScope.statusMethod, governedResourceType: "credentialFamily",
};
const verifierDraft = {
  applicationId: "application:verifier:local-demo:v1", authorizationId: "auth:verifier:local-demo:v1",
  actorDid: subjectDid, actorKeyId: `${subjectDid}#auth-1`,
  requestProfileId: verifierScope.requestProfileId, purpose: verifierScope.purpose,
  credentialScopeCommitment: verifierScope.credentialScopeCommitment,
  allowedAttributes: verifierScope.allowedAttributes, allowedPredicates: verifierScope.allowedPredicates,
  disclosureLevel: verifierScope.disclosureLevel,
};
const drafts = { auditor: applicationDraft, issuer: issuerDraft, verifier: verifierDraft };

function requestedRole(raw) {
  if (!Object.hasOwn(scopes, raw)) throw new Error("Demo role must be issuer, verifier, or auditor");
  return raw;
}

export function signDigest(digest) {
  if (typeof digest !== "string" || !/^0x[0-9a-f]{64}$/u.test(digest)) {
    throw new Error("Pass the canonical 0x-prefixed 32-byte digest after sign-digest");
  }
  return `0x${Buffer.from(encodeJubjubSignature(signJubjubDigest(
    23n, payloadToJubjubDigest(Buffer.from(digest.slice(2), "hex")),
  ))).toString("hex")}`;
}

function signedApplication(workspace, role = "auditor") {
  const context = {
    registryId: workspace.snapshot.registry.registryId,
    expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(workspace),
    expectedEpochId: workspace.snapshot.currentEpoch.epochId,
    evaluatedAt: NOW,
  };
  const nonce = `0x${"22".repeat(32)}`;
  const prepared = role === "issuer"
    ? prepareIssuerApplication(issuerDraft, context, nonce)
    : role === "verifier"
      ? prepareVerifierApplication(verifierDraft, context, nonce)
      : prepareAuditorApplication(applicationDraft, context, nonce);
  return role === "auditor"
    ? signPreparedAuditorApplication(prepared, signDigest(prepared.digest))
    : signPreparedMembershipApplication(prepared, signDigest(prepared.digest));
}

export async function startHost(port, staticDir = fileURLToPath(new URL("../packages/trust-registry-applicant-portal/dist", import.meta.url)), applicationScope = scope) {
  const fixture = await createApplicationVpScenarioFixture(undefined, { scope: applicationScope, subjectDid, evidenceVerifierDid });
  const workspace = createOperatorWorkspace({ label: "auditor-admission-demo" });
  const registration = new InMemoryPendingApplicationRegistrationPort({
    workspace, applications: [], consumedNonces: [],
  }, evidenceVerifierDid, fixture.input.resolver);
  const ports = await createApplicationVpIntakePorts({
    resolver: fixture.input.resolver,
    family: fixture.family,
    signer: fixture.signer,
  });
  const session = randomBytes(32);
  const cookieName = "tr-auditor-demo";
  const cookie = `${cookieName}=${session.toString("hex")}`;
  const receipts = new Map();
  const staticHandler = createStaticAssetHandler({
    distDir: resolve(staticDir),
    name: "auditor-admission-demo",
  });
  let server;
  const expectedHost = () => {
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("Demo server is not listening");
    return `127.0.0.1:${address.port.toString()}`;
  };
  const isLocalRequest = (request) => request.socket.remoteAddress === "127.0.0.1"
    && request.headers.host === expectedHost();
  const hasDemoSession = (request) => {
    const supplied = request.headers.cookie?.split(";").map((value) => value.trim())
      .find((value) => value.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
    const token = typeof supplied === "string" && /^[0-9a-f]{64}$/u.test(supplied)
      ? Buffer.from(supplied, "hex") : Buffer.alloc(32);
    return isLocalRequest(request) && timingSafeEqual(token, session)
      && (request.method !== "POST" || request.headers.origin === `http://${expectedHost()}`);
  };
  const authorizeRequest = async (id, request) => {
    const pending = registration.readPending(id);
    if (!hasDemoSession(request) || pending === null || pending.binding.subjectDid !== subjectDid) {
      throw new Error("Demo applicant session denied");
    }
  };
  server = createTrustRegistryApiServer({
    source: {
      mode: "workspace",
      loadSnapshot: async () => workspace.snapshot,
      loadWorkspace: async () => workspace,
      writeWorkspace: async () => { throw new Error("Demo governance mutations are disabled"); },
      withExclusiveWrite: async () => { throw new Error("Demo governance mutations are disabled"); },
    },
    clock: () => NOW,
    pendingApplicationRegistration: registration,
    authorizePendingApplicationRegistration: async (request) => {
      if (!hasDemoSession(request)) throw new Error("Demo applicant session denied");
    },
    applicationVp: {
      challengeStore: new InMemoryApplicationChallengeStore(),
      authorizeRequest,
      resolvePendingApplication: async (id) => {
        const pending = registration.readPending(id);
        return pending === null || pending.binding.subjectDid !== subjectDid ? null : {
          binding: pending.binding,
          authorizedVerifiers: [{
            did: fixture.signer.did,
            keyIds: [fixture.signer.keyId],
            algorithms: ["jubjub-schnorr"],
          }],
        };
      },
      ...ports,
      persistRedactedEvidence: async (id, evidence) => {
        if (receipts.has(id)) throw new Error("Demo application already has evidence");
        const receipt = {
          receiptId: sha256Hex(JSON.stringify([id, evidence.commitment])),
          evidenceCommitment: evidence.commitment,
          acceptedAt: NOW,
        };
        receipts.set(id, { evidence, receipt });
        return receipt;
      },
    },
    nonApiGetHandler: async (request, response) => {
      if (!isLocalRequest(request)) {
        response.statusCode = 403;
        response.end("forbidden\n");
        return;
      }
      if (request.url === "/" || request.url?.startsWith("/?")) {
        response.setHeader("set-cookie", `${cookie}; HttpOnly; SameSite=Strict; Path=/`);
        response.setHeader("cache-control", "no-store");
      }
      await staticHandler(request, response);
    },
  });
  await new Promise((resolveListen) => server.listen(port, "127.0.0.1", resolveListen));
  return { server, base: `http://${expectedHost()}`, cookie, application: signedApplication(workspace, applicationScope.role), receipts };
}

async function smoke() {
  const host = await startHost(0);
  try {
    const page = await fetch(host.base);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Trust Registry/u);
    assert.equal(page.headers.get("set-cookie")?.split(";")[0], host.cookie);
    const appAsset = await fetch(`${host.base}/index.js`);
    assert.equal(appAsset.status, 200);
    assert.match(appAsset.headers.get("content-type") ?? "", /javascript/u);
    assert.equal((await fetch(`${host.base}/v1/not-a-page`)).status, 404);
    const spoofedHostStatus = await new Promise((resolveStatus, rejectStatus) => {
      const request = httpRequest(host.base, { headers: { host: "untrusted.example" } }, (response) => {
        response.resume();
        response.on("end", () => resolveStatus(response.statusCode));
      });
      request.on("error", rejectStatus);
      request.end();
    });
    assert.equal(spoofedHostStatus, 403);
    const post = (path, body, authorized = true, origin = host.base) => fetch(`${host.base}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin,
        ...(authorized ? { cookie: host.cookie } : {}),
      },
      body: JSON.stringify(body),
    });
    const registrationPath = "/v1/pending-applications";
    assert.equal((await post(registrationPath, host.application, false)).status, 403);
    assert.equal((await post(registrationPath, host.application, true, "https://untrusted.example")).status, 403);
    const spoofedRegistrationStatus = await new Promise((resolveStatus, rejectStatus) => {
      const request = httpRequest(`${host.base}${registrationPath}`, {
        method: "POST",
        headers: { host: "untrusted.example", cookie: host.cookie, origin: host.base, "content-type": "application/json" },
      }, (response) => {
        response.resume();
        response.on("end", () => resolveStatus(response.statusCode));
      });
      request.on("error", rejectStatus);
      request.end(JSON.stringify(host.application));
    });
    assert.equal(spoofedRegistrationStatus, 403);
    const contextResponse = await fetch(`${host.base}/v1/registry/mutation-context`);
    assert.equal(contextResponse.status, 200);
    const context = await contextResponse.json();
    assert.equal(context.evaluatedAt, NOW);
    const prepared = prepareAuditorApplication(applicationDraft, context, host.application.intent.nonce);
    const formApplication = signPreparedAuditorApplication(prepared, signDigest(prepared.digest));
    assert.deepEqual(formApplication.intent, host.application.intent);
    assert.deepEqual(formApplication.scope, host.application.scope);
    assert.equal((await post(registrationPath, {
      ...host.application, authorizationId: "auth:auditor:substituted:v1",
    })).status, 400);
    const registered = await post(registrationPath, formApplication);
    assert.equal(registered.status, 201);
    assert.equal((await registered.json()).authorizationId, host.application.authorizationId);
    const path = `/v1/application-evidence/${applicationId}`;
    assert.equal((await post(`${path}/challenges`, {}, false)).status, 403);
    assert.equal((await post(`${path}/challenges`, {}, true, "https://untrusted.example")).status, 403);
    const challengeResponse = await post(`${path}/challenges`, {});
    assert.equal(challengeResponse.status, 201);
    const challenge = await challengeResponse.json();
    const wrong = await createApplicationVpScenarioFixture(challenge.nonce, {
      scope: { ...scope, purpose: "wrong-purpose" }, subjectDid, evidenceVerifierDid,
    });
    const valid = await createApplicationVpScenarioFixture(challenge.nonce, { scope, subjectDid, evidenceVerifierDid });
    const submission = (presentation) => ({
      nonce: challenge.nonce, challengeHash: challenge.challengeHash, presentation,
    });
    assert.equal((await post(`${path}/submissions`, submission(wrong.input.submission))).status, 403);
    const accepted = await post(`${path}/submissions`, submission(valid.input.submission));
    assert.equal(accepted.status, 202);
    const result = await accepted.json();
    assert.equal(result.evidence.commitment, result.receipt.evidenceCommitment);
    assert.equal(host.receipts.size, 1);
    assert.equal(JSON.stringify(result).includes("private-presentation-payload"), false);
    assert.equal(JSON.stringify(host.receipts.get(applicationId)).includes("private-presentation-payload"), false);
    assert.equal((await post(`${path}/submissions`, submission(valid.input.submission))).status, 409);
    process.stdout.write(JSON.stringify({
      demo: "auditor-admission",
      applicationId,
      subjectDid,
      evidenceCommitment: result.evidence.commitment,
      receiptId: result.receipt.receiptId,
      expectedRejections: ["unauthorized:403", "wrong-target:400", "wrong-scope:403", "replay:409"],
    }, null, 2) + "\n");
  } finally {
    await new Promise((resolveClose, reject) => host.server.close((error) => error ? reject(error) : resolveClose()));
  }
}

export async function presentationForNonce(nonce, applicationScope = scope) {
  if (nonce === undefined || !/^0x[0-9a-f]{64}$/u.test(nonce)) {
    throw new Error("Pass the canonical challenge nonce after vp");
  }
  const fixture = await createApplicationVpScenarioFixture(nonce, { scope: applicationScope, subjectDid, evidenceVerifierDid });
  return fixture.input.submission;
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  if (command === "application") {
    const role = requestedRole(process.argv[3] ?? "auditor");
    process.stdout.write(`${JSON.stringify(signedApplication(createOperatorWorkspace({ label: "auditor-admission-demo" }), role))}\n`);
  } else if (command === "sign-digest") {
    process.stdout.write(`${signDigest(process.argv[3])}\n`);
  } else if (command === "vp") {
    const role = requestedRole(process.argv[4] ?? "auditor");
    process.stdout.write(`${JSON.stringify(await presentationForNonce(process.argv[3], scopes[role]))}\n`);
  } else if (command === "smoke") {
    await smoke();
  } else if (command === "serve") {
    const rawPort = process.argv[3] ?? "4400";
    const port = Number(rawPort);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Demo port must be 1-65535");
    const role = requestedRole(process.argv[4] ?? "auditor");
    const host = await startHost(port, undefined, scopes[role]);
    process.stdout.write(`Fixture-only ${role} portal: ${host.base}\n`);
    process.stdout.write("Paste this DID-signed fixture application in the portal:\n");
    process.stdout.write(`${JSON.stringify(host.application)}\n`);
    process.stdout.write(`Or use the ${role} form with this fixture draft, prepare its digest, then run \`node scripts/demo-auditor-admission.mjs sign-digest <digest>\` and paste the signature:\n`);
    process.stdout.write(`${JSON.stringify(drafts[role])}\n`);
    process.stdout.write(`After issuing a challenge, run \`node scripts/demo-auditor-admission.mjs vp <nonce> ${role}\` and paste its VP JSON.\n`);
    process.stdout.write("Loopback/in-memory fixture only; not a public admission host or production status verifier.\n");
  } else {
    throw new Error("Usage: demo-auditor-admission.mjs [serve [port] [issuer|verifier|auditor]|application [role]|sign-digest <digest>|vp <nonce> [role]|smoke]");
  }
}
