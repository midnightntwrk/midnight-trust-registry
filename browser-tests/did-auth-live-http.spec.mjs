import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { generateKeyPairSync, sign as signEd25519 } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signJubjubPayloadFromSeed,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { createLongFormOffchainMidnightDIDString, CurveType, KeyType } from "@midnight-ntwrk/midnight-did-domain";

import { test, expect } from "./offline-browser-fixture.mjs";
import { createStaticAssetHandler } from "../scripts/serve-static.mjs";
import { createOperatorWorkspace } from "../packages/trust-registry-cli/dist/index.js";
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

test("both browser apps use real same-origin DID HTTP sessions without a role grant", async ({ page, allowedLocalOrigins }, testInfo) => {
  const directory = await mkdtemp(join(tmpdir(), "tr-browser-did-auth-"));
  const seed = new Uint8Array(32).fill(86);
  const actorDid = createMidnightDid("browser-did-authentication");
  const actorKeyId = `${actorDid}#auth-1`;
  const workspace = createOperatorWorkspace({ label: "browser-did-auth" });
  const options = { source: createInMemorySource(workspace.snapshot) };
  const sessions = createActorSessionService(Date.now);
  const api = createTrustRegistryApiServer(options);
  const staticHandlers = new Map([
    ["applicant", createStaticAssetHandler({
      distDir: resolve("packages/trust-registry-applicant-portal/dist"), name: "applicant-auth-browser",
    })],
    ["admin", createStaticAssetHandler({
      distDir: resolve("packages/trust-registry-admin-console/dist"), name: "admin-auth-browser",
    })],
  ]);
  const requests = [];
  const listedFor = [];
  let heldList;
  let notifyHeldListStarted;
  const revokedPurposes = [];
  const server = createServer((request, response) => {
    const pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (pathname === "/health" || pathname.startsWith("/v1/")) {
      requests.push(`${request.method} ${pathname}`);
      if (request.method === "DELETE" && pathname === "/v1/actor-authentication/session") {
        const identity = sessions.authenticate(request.headers.authorization);
        revokedPurposes.push({
          purpose: identity?.purpose,
          wrongPurposeAccepted: sessions.authenticate(request.headers.authorization,
            identity?.purpose === "applicant-session" ? "maintainer-session" : "applicant-session") !== null,
        });
      }
      api.emit("request", request, response);
      return;
    }
    const surface = pathname.startsWith("/applicant/") ? "applicant"
      : pathname.startsWith("/admin/") ? "admin" : undefined;
    if (surface === undefined) {
      response.writeHead(404).end();
      return;
    }
    request.url = (request.url ?? "/").replace(/^\/(?:applicant|admin)\//u, "/");
    void staticHandlers.get(surface)(request, response);
  });
  try {
    await new Promise((done) => server.listen(0, "127.0.0.1", done));
    const address = server.address();
    assert(address !== null && typeof address !== "string");
    const origin = `http://127.0.0.1:${address.port}`;
    allowedLocalOrigins.add(origin);
    const resolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(actorDid, {
        verificationMethodId: "auth-1",
        schnorrJubjubPublicKey: deriveJubjubPublicKeyFromSeed(seed),
      }),
    ]);
    options.actorAuthentication = {
      challenges: createActorAuthenticationService({
        context: {
          registryId: workspace.snapshot.registry.registryId,
          genesisHash: `0x${"11".repeat(32)}`,
          contractAddress: `0x${"22".repeat(32)}`,
          origin,
        },
        resolver,
        store: new FileActorAuthenticationChallengeStore(join(directory, "challenges.json"), Date.now),
        clock: Date.now,
      }),
      sessions,
    };
    options.pendingApplicationRegistration = {
      register: async () => { throw new Error("Not used in this browser journey"); },
      listForSubjectDid: async (subjectDid) => {
        listedFor.push(subjectDid);
        if (heldList !== undefined) {
          notifyHeldListStarted();
          await heldList;
        }
        return subjectDid === actorDid ? [{
          subjectDid: actorDid,
          summary: { applicationId: "application:issuer:mine:v1", authorizationId: "auth:issuer:mine:v1",
            role: "issuer", status: "pending", createdAt: "2026-11-14T00:00:00.000Z" },
        }] : [];
      },
    };
    await page.exposeFunction("signTrustRegistryDigest", (digest, useWrongKey) => ({
      keyId: actorKeyId,
      algorithm: "jubjub-schnorr",
      value: `0x${Buffer.from(encodeJubjubSignature(signJubjubPayloadFromSeed(
        useWrongKey ? new Uint8Array(32).fill(87) : seed, Uint8Array.from(digest),
      ))).toString("hex")}`,
    }));
    await page.addInitScript(({ actorDid, actorKeyId }) => {
      window.midnightTrustRegistryDidSigner = {
        getIdentity: async () => ({ actorDid, actorKeyId }),
        signDigest: async ({ digest }) => window.signTrustRegistryDigest(
          Array.from(digest), window.trDidSignerUseWrongKey === true,
        ),
      };
    }, { actorDid, actorKeyId });

    await page.goto(`${origin}/applicant/`);
    await expect(page.locator(".source-badge")).toHaveText("Practice workspace");
    await page.locator('.task-nav a[href="./registry-manual.html"]').click();
    await expect(page.locator("main h1")).toContainText("Registry Manual");
    await page.getByRole("link", { name: "Choose a role" }).click();
    await expect(page.locator("#governed-requests")).toBeVisible();
    await page.locator('.journey-cards a[href="#issuer-request"]').click();
    await expect(page.locator("#issuer-request")).toHaveAttribute("open", "");
    await expect(page.locator(".journey-prerequisite")).toContainText("sign in with your digital identity");
    assert.equal(requests.some((request) => request.startsWith("POST /v1/governed/")), false);
    await page.locator(".hero-sign-in").click();
    await page.evaluate(() => { window.trDidSignerUseWrongKey = true; });
    await page.getByRole("button", { name: "Sign in with digital identity" }).click();
    await expect(page.locator(".portal-profile-card [role='alert']")).toContainText("HTTP 401");
    await expect(page.locator(".application-readiness")).toContainText("Not signed in");
    await page.evaluate(() => { window.trDidSignerUseWrongKey = false; });
    await page.getByRole("button", { name: "Sign in with digital identity" }).click();
    await expect(page.locator(".portal-profile-card")).toContainText(`Signed in as ${actorDid}`);
    await expect(page.locator(".portal-profile-card [role='alert']")).toHaveCount(0);
    await expect(page.locator(".application-readiness")).toContainText("Requires governed approval");
    await expect(page.locator(".journey-prerequisite")).toContainText("Proof of eligibility and governed approval are still required");
    await expect(page.locator("#issuer-request")).toHaveAttribute("open", "");
    await expect(page.locator("body")).not.toContainText("trsa_");
    await page.getByRole("link", { name: "Back to issuer request" }).click();
    await expect(page.locator(".app-shell")).toHaveAttribute("data-settings-active", "false");
    await expect(page.locator("#issuer-request")).toBeVisible();
    await page.locator('.task-nav a[href="#my-applications"]').click();
    await page.getByRole("button", { name: "Load my applications" }).click();
    const applicationCard = page.locator("#my-applications .application-item");
    await expect(applicationCard).toContainText("Request registered");
    await expect(applicationCard.locator("time")).not.toContainText("2026-11-14T00:00:00.000Z");
    const applicationId = applicationCard.getByText("application:issuer:mine:v1");
    await expect(applicationId).toBeHidden();
    await applicationCard.getByText("Request identifiers").click();
    await expect(applicationId).toBeVisible();
    if (process.env.TR_UI_CAPTURE === "1") {
      await page.locator("#my-applications").screenshot({ path: testInfo.outputPath("applicant-my-applications.png") });
    }
    const viewport = page.viewportSize();
    await page.setViewportSize({ width: 320, height: 900 });
    await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
    const width = await page.evaluate(() => document.documentElement.scrollWidth);
    assert.ok(width <= 320, `expanded application identifiers overflow at 320px: ${width}`);
    await page.evaluate(() => { document.documentElement.style.removeProperty("font-size"); });
    if (viewport !== null) await page.setViewportSize(viewport);
    await page.getByRole("link", { name: "Continue private evidence" }).click();
    await expect(page.locator("#pending-evidence")).toHaveAttribute("open", "");
    await expect(page.locator("[data-application-binding-form] [name='applicationId']"))
      .toHaveValue("application:issuer:mine:v1");
    assert.deepEqual(listedFor, [actorDid]);
    assert.equal(requests.filter((request) => request === "GET /v1/pending-applications").length, 1);
    let releaseHeldList;
    heldList = new Promise((resolve) => { releaseHeldList = resolve; });
    const heldListStarted = new Promise((resolve) => { notifyHeldListStarted = resolve; });
    await page.getByRole("button", { name: "Refresh my applications" }).click();
    await heldListStarted;
    const staleResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/v1/pending-applications" && response.request().method() === "GET");
    await page.getByRole("button", { name: "Recheck", exact: true }).click();
    await expect(page.getByRole("button", { name: "Load my applications" })).toBeVisible();
    releaseHeldList();
    await staleResponse;
    await expect(page.locator("#my-applications .application-item")).toHaveCount(0);
    heldList = undefined;
    await page.getByRole("button", { name: "Load my applications" }).click();
    await expect(page.locator("#my-applications .application-item")).toHaveCount(1);
    options.pendingApplicationRegistration = undefined;
    await page.getByRole("button", { name: "Refresh my applications" }).click();
    await expect(page.locator("#my-applications [role='alert']"))
      .toContainText("Use Continue pending request with the ID from your receipt");
    await expect(page.locator("#my-applications .application-item")).toHaveCount(0);
    await expect(page.locator("#my-applications")).not.toContainText("No registered requests");
    const actorAuthentication = options.actorAuthentication;
    options.actorAuthentication = undefined;
    await page.getByRole("button", { name: "Load my applications" }).click();
    await expect(page.locator("#my-applications [role='alert']"))
      .toContainText("Sign out, then sign in again in Workspace settings");
    await expect(page.locator("#my-applications .application-item")).toHaveCount(0);
    options.actorAuthentication = actorAuthentication;
    await page.getByRole("link", { name: "Workspace settings" }).first().click();
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.locator(".portal-profile-card")).toContainText("A digital identity signer is connected");
    await expect(page.locator("#my-applications")).toContainText("Sign in with your digital identity");
    await expect(page.locator("#my-applications")).not.toContainText("application:issuer:mine:v1");

    await page.goto(`${origin}/admin/`);
    await page.locator('.task-nav a[href="./registry-manual.html"]').click();
    await expect(page.locator("main h1")).toContainText("Registry Manual");
    await page.getByRole("link", { name: "Open review inbox" }).click();
    await expect(page.locator("#review-board")).toBeVisible();
    assert.equal(requests.some((request) => request.startsWith("POST /v1/governed/")), false);
    await page.getByRole("link", { name: "Workspace settings" }).first().click();
    await page.getByRole("button", { name: "Sign in with digital identity" }).click();
    await expect(page.locator(".portal-profile-card")).toContainText(`Signed in as ${actorDid}`);
    await expect(page.locator(".portal-profile-card")).toContainText("Your maintainer authority is checked separately");
    await expect(page.locator("body")).not.toContainText("trsa_");
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.locator(".portal-profile-card")).toContainText("A digital identity signer is connected");
    assert.equal(requests.filter((request) => request === "POST /v1/actor-authentication/challenges").length, 3);
    assert.equal(requests.filter((request) => request === "POST /v1/actor-authentication/sessions").length, 3);
    assert.equal(requests.filter((request) => request === "DELETE /v1/actor-authentication/session").length, 2);
    assert.deepEqual(revokedPurposes, [
      { purpose: "applicant-session", wrongPurposeAccepted: false },
      { purpose: "maintainer-session", wrongPurposeAccepted: false },
    ]);
    assert.equal(requests.some((request) => request.startsWith("POST /v1/governed/")), false);
  } finally {
    server.closeAllConnections();
    await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
    await rm(directory, { recursive: true, force: true });
  }
});

test("off-chain DID signs in to both portals without gaining a registry role", async ({ page, allowedLocalOrigins }) => {
  const directory = await mkdtemp(join(tmpdir(), "tr-browser-offchain-auth-"));
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const actorDid = createLongFormOffchainMidnightDIDString({
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
  const actorKeyId = `${actorDid}/keys#auth`;
  const workspace = createOperatorWorkspace({ label: "browser-offchain-auth" });
  const options = { source: createInMemorySource(workspace.snapshot) };
  const api = createTrustRegistryApiServer(options);
  const staticHandlers = new Map([
    ["applicant", createStaticAssetHandler({
      distDir: resolve("packages/trust-registry-applicant-portal/dist"), name: "applicant-offchain-browser",
    })],
    ["admin", createStaticAssetHandler({
      distDir: resolve("packages/trust-registry-admin-console/dist"), name: "admin-offchain-browser",
    })],
  ]);
  const server = createServer((request, response) => {
    const pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (pathname === "/health" || pathname.startsWith("/v1/")) {
      api.emit("request", request, response);
      return;
    }
    const surface = pathname.startsWith("/applicant/") ? "applicant"
      : pathname.startsWith("/admin/") ? "admin" : undefined;
    if (surface === undefined) {
      response.writeHead(404).end();
      return;
    }
    request.url = (request.url ?? "/").replace(/^\/(?:applicant|admin)\//u, "/");
    void staticHandlers.get(surface)(request, response);
  });
  try {
    await new Promise((done) => server.listen(0, "127.0.0.1", done));
    const address = server.address();
    assert(address !== null && typeof address !== "string");
    const origin = `http://127.0.0.1:${address.port}`;
    allowedLocalOrigins.add(origin);
    options.actorAuthentication = {
      challenges: createActorAuthenticationService({
        context: {
          registryId: workspace.snapshot.registry.registryId,
          genesisHash: `0x${"11".repeat(32)}`,
          contractAddress: `0x${"22".repeat(32)}`,
          origin,
        },
        store: new FileActorAuthenticationChallengeStore(join(directory, "challenges.json"), Date.now),
        clock: Date.now,
      }),
      sessions: createActorSessionService(Date.now),
    };
    await page.exposeFunction("signTrustRegistryDigest", (digest) => ({
      keyId: actorKeyId,
      algorithm: "ed25519",
      value: `0x${signEd25519(null, Uint8Array.from(digest), privateKey).toString("hex")}`,
    }));
    await page.addInitScript(({ actorDid, actorKeyId }) => {
      window.midnightTrustRegistryDidSigner = {
        getIdentity: async () => ({ actorDid, actorKeyId }),
        signDigest: async ({ digest }) => window.signTrustRegistryDigest(Array.from(digest)),
      };
    }, { actorDid, actorKeyId });

    await page.goto(`${origin}/applicant/`);
    await page.locator(".hero-sign-in").click();
    await page.getByRole("button", { name: "Sign in with digital identity" }).click();
    await expect(page.locator(".portal-profile-status")).toContainText(actorDid);
    await expect(page.locator(".application-readiness")).toContainText("Requires governed approval");
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.locator(".portal-profile-card")).toContainText("A digital identity signer is connected");

    await page.goto(`${origin}/admin/`);
    await page.getByRole("link", { name: "Workspace settings" }).first().click();
    await page.getByRole("button", { name: "Sign in with digital identity" }).click();
    await expect(page.locator(".portal-profile-status")).toContainText(actorDid);
    await expect(page.locator(".portal-profile-card")).toContainText("maintainer authority is checked separately");
    await expect(page.locator("body")).not.toContainText("trsa_");
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.locator(".portal-profile-card")).toContainText("A digital identity signer is connected");
  } finally {
    server.closeAllConnections();
    await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
    await rm(directory, { recursive: true, force: true });
  }
});
