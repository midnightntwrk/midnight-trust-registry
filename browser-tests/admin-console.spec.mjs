import { createServer } from "node:http";
import { resolve } from "node:path";

import { expect, test } from "./offline-browser-fixture.mjs";

import { createStaticAssetHandler } from "../scripts/serve-static.mjs";

const counts = () => ({
  proposed: 0, authorized: 0, active: 0, suspended: 0,
  revoked: 0, superseded: 0, archived: 0,
});

const summary = (registry) => ({
  issuerCounts: counts(), verifierCounts: counts(), auditorCounts: counts(),
  recognitionCounts: counts(), currentEpochId: `epoch:${registry}:1`,
  registryLabel: `Registry ${registry.toUpperCase()}`, registryId: `registry:${registry}`,
  registryDid: `did:midnight:testnet:${registry}`, policyId: `policy:${registry}`, epochCount: 1,
});

test("a late governance receipt cannot replace another registry's board", async ({ page, allowedLocalOrigins }) => {
  const staticHandler = createStaticAssetHandler({
    distDir: resolve("packages/trust-registry-admin-console/dist"),
    name: "admin-console-browser-test",
  });
  let publishRequestStarted;
  const publishing = new Promise((resolveStarted) => { publishRequestStarted = resolveStarted; });
  let finishPublication;
  const publicationGate = new Promise((resolvePublication) => { finishPublication = resolvePublication; });
  const postPaths = [];
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (/^\/(a|b)\/health$/u.test(path)) {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ status: "ok", sourceMode: "workspace" }));
      return;
    }
    const match = /^\/(a|b)\/v1\/(.*)$/u.exec(path);
    if (match === null) {
      await staticHandler(request, response);
      return;
    }
    const [, registry, resource] = match;
    response.setHeader("content-type", "application/json");
    if (request.method === "POST") {
      postPaths.push(path);
      if (registry !== "a" || resource !== "epochs/publish") {
        response.statusCode = 500;
        response.end(JSON.stringify({ title: "unexpected mutation" }));
        return;
      }
      publishRequestStarted();
      await publicationGate;
      response.end(JSON.stringify({ recordKind: "epoch", epoch: { epochId: "epoch:a:2" } }));
      return;
    }
    response.end(JSON.stringify(resource === "registry/summary" ? summary(registry) : { entries: [] }));
  });
  await new Promise((resolveListening) => server.listen(0, "127.0.0.1", resolveListening));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected TCP address");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    allowedLocalOrigins.add(base);
    page.on("dialog", (dialog) => dialog.accept());
    await page.goto(`${base}/?apiBase=${encodeURIComponent(`${base}/a`)}`);
    const registryLabel = page.locator(".metrics .metric:first-child strong");
    await expect(registryLabel).toHaveText("Registry A");

    await page.locator(".advanced-workflows > summary").click();
    await page.locator("[data-signed-submit] [name='signedEnvelope']").fill("signed-for-registry-a");
    const completedPublication = page.waitForResponse((response) => response.url().endsWith("/a/v1/epochs/publish"));
    await page.locator("[data-epoch-label]").fill("first-registry-epoch");
    await page.locator("[data-epoch-form] button[type='submit']").click();
    await Promise.race([
      publishing,
      new Promise((_, reject) => setTimeout(() => reject(new Error("epoch publication request did not start")), 3000)),
    ]);

    await page.locator("[data-api-base-form] [name='apiBase']").fill(`${base}/b`);
    await page.locator("[data-api-base-form] button[type='submit']").click();
    await expect(registryLabel).toHaveText("Registry B");
    await expect(page.locator("[data-signed-submit] [name='signedEnvelope']")).toBeEmpty();
    await expect(page.locator("[data-epoch-label]")).toBeEmpty();
    finishPublication();
    await Promise.race([
      completedPublication,
      new Promise((_, reject) => setTimeout(() => reject(new Error("old publication response did not arrive")), 3000)),
    ]);
    await page.evaluate(() => new Promise((resolveFrame) => requestAnimationFrame(() => requestAnimationFrame(resolveFrame))));
    await expect(registryLabel).toHaveText("Registry B");
    await expect(page.locator("body")).not.toContainText("first-registry-epoch accepted");
    expect(postPaths).toEqual(["/a/v1/epochs/publish"]);
  } finally {
    finishPublication?.();
    await page.close();
    server.closeAllConnections();
    await new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  }
});

test("local-ledger board discards a lookup when its finalized checkpoint changes", async ({ page, allowedLocalOrigins }) => {
  const staticHandler = createStaticAssetHandler({
    distDir: resolve("packages/trust-registry-admin-console/dist"),
    name: "admin-console-local-browser-test",
  });
  const paths = [];
  let checkpoint = `0x${"b".repeat(64)}`;
  let lookupStarted;
  const lookupRequest = new Promise((resolveStarted) => { lookupStarted = resolveStarted; });
  let finishLookup;
  const lookupGate = new Promise((resolveLookup) => { finishLookup = resolveLookup; });
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (!path.startsWith("/health") && !path.startsWith("/v1/")) {
      await staticHandler(request, response);
      return;
    }
    paths.push(`${request.method} ${path}`);
    response.setHeader("content-type", "application/json");
    if (request.method !== "GET") {
      response.statusCode = 405;
      response.end(JSON.stringify({ title: "local mutations are unavailable" }));
    } else if (path === "/health") {
      response.end(JSON.stringify({
        status: "ok", sourceMode: "local-ledger", registryId: "registry:local",
        localPlanSha256: "a".repeat(64), finalizedBlockHash: checkpoint,
        generatedAt: "2026-10-27T00:00:00Z",
      }));
    } else if (path === "/v1/registry/summary") {
      response.end(JSON.stringify(summary("local")));
    } else if (path === "/v1/authorizations/auditor/auth%3Aauditor%3Acompliance") {
      lookupStarted();
      await lookupGate;
      response.end(JSON.stringify({ authorization: { registryId: "registry:local",
        authorizationId: "auth:auditor:compliance", role: "auditor",
        resourceId: "MUST_NOT_RENDER_STALE_RECORD" } }));
    } else {
      response.statusCode = 503;
      response.end(JSON.stringify({ title: "list unavailable" }));
    }
  });
  await new Promise((resolveListening) => server.listen(0, "127.0.0.1", resolveListening));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected TCP address");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    allowedLocalOrigins.add(base);
    await page.goto(`${base}/?apiBase=${encodeURIComponent(base)}`);
    await expect(page.locator("[data-current-lookup]")).toBeVisible();
    await expect(page.locator("[data-action]")).toHaveCount(0);
    await expect(page.locator("[data-epoch-form]")).toHaveCount(0);
    await expect(page.locator("[data-signed-context]")).toHaveCount(0);
    await page.locator("[data-current-target]").selectOption("auditor");
    await page.locator("[data-current-id]").fill("auth:auditor:compliance");
    await page.locator("[data-current-lookup] button[type='submit']").click();
    await Promise.race([
      lookupRequest,
      new Promise((_, reject) => setTimeout(() => reject(new Error("local lookup did not start")), 3000)),
    ]);
    checkpoint = `0x${"c".repeat(64)}`;
    finishLookup();
    await expect(page.locator("body")).toContainText("checkpoint changed");
    await expect(page.locator("body")).not.toContainText("MUST_NOT_RENDER_STALE_RECORD");
    expect(paths.filter((path) => path.includes("/v1/authorizations/"))).toEqual([
      "GET /v1/authorizations/auditor/auth%3Aauditor%3Acompliance",
    ]);
    expect(paths.filter((path) => path.startsWith("POST "))).toEqual([]);
  } finally {
    finishLookup?.();
    await page.close();
    server.closeAllConnections();
    await new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  }
});

test("fixture admin review advances an issuer through approval, activation, risk, and archive", async ({ page, allowedLocalOrigins }) => {
  const staticHandler = createStaticAssetHandler({
    distDir: resolve("packages/trust-registry-admin-console/dist"),
    name: "admin-console-review-journey",
  });
  const id = "auth:issuer:ui-review:v1";
  let status = "proposed";
  const posted = [];
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (path !== "/health" && !path.startsWith("/v1/")) {
      await staticHandler(request, response);
      return;
    }
    response.setHeader("content-type", "application/json");
    if (path === "/health") {
      response.end(JSON.stringify({ status: "ok", sourceMode: "workspace", registryId: "registry:ui-review" }));
      return;
    }
    const entry = { label: "UI review issuer", authorization: {
      authorizationId: id, registryId: "registry:ui-review", role: "issuer",
      subjectDid: "did:midnight:undeployed:ui-review", resourceType: "credential-family",
      resourceId: `tr:issuer-resource:v1:${"a".repeat(64)}`, policyId: "policy:ui-review",
      trustLevel: "approved", status, proposedAt: "2026-05-20T00:00:00Z",
      ...(status === "proposed" ? {} : { authorizedAt: "2026-05-20T00:01:00Z" }),
      ...(status === "active" ? { activeFrom: "2026-05-20T00:02:00Z" } : {}),
    }, evidence: { epoch: { epochId: "epoch:ui-review:1", stateRoot: "0xroot" } } };
    if (request.method === "POST") {
      const action = ["approve", "activate", "suspend", "revoke", "archive"]
        .find((candidate) => path.endsWith(`/${candidate}`)) ?? null;
      if (action === null || (action === "approve" && status !== "proposed")
        || (action === "activate" && status !== "authorized")
        || (action === "suspend" && status !== "active")
        || (action === "revoke" && status !== "suspended")
        || (action === "archive" && status !== "revoked")) {
        response.statusCode = 409;
        response.end(JSON.stringify({ title: "invalid review transition" }));
        return;
      }
      posted.push(path);
      status = { approve: "authorized", activate: "active", suspend: "suspended",
        revoke: "revoked", archive: "archived" }[action];
      entry.authorization.status = status;
      response.end(JSON.stringify({ recordKind: "authorization", operation: { operation: action }, entry }));
      return;
    }
    if (path === "/v1/registry/summary") {
      const current = counts();
      current[status] = 1;
      response.end(JSON.stringify({ ...summary("ui-review"), issuerCounts: current }));
      return;
    }
    response.end(JSON.stringify({ entries: path === "/v1/authorizations/issuer" ? [entry] : [] }));
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected TCP address");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    allowedLocalOrigins.add(base);
    page.on("dialog", (dialog) => dialog.accept());
    await page.goto(`${base}/?apiBase=${encodeURIComponent(base)}`);
    await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    await expect(page.locator(".card")).toContainText("UI review issuer");
    await page.locator("[data-review-query]").fill("missing record");
    await expect(page.getByText("No records match these filters.")).toBeVisible();
    await expect(page.locator(".card")).toHaveCount(0);
    await page.locator("[data-review-query]").fill("UI review issuer");
    await expect(page.locator(".card")).toHaveCount(1);
    await page.locator("[data-review-status]").selectOption("active");
    await expect(page.locator(".card")).toHaveCount(0);
    await page.locator("[data-review-status]").selectOption("all");
    await expect(page.locator(".card")).toHaveCount(1);
    expect(posted).toEqual([]);
    await page.locator('[data-action="approve"]').click();
    await expect(page.locator(".card .status-chip")).toHaveText("Authorized");
    await page.locator('[data-action="activate"]').click();
    await expect(page.locator(".card .status-chip")).toHaveText("Active");
    await page.locator('[data-action="suspend"]').click();
    await expect(page.locator(".card .status-chip")).toHaveText("Suspended");
    await page.locator('[data-action="revoke"]').click();
    await expect(page.locator(".card .status-chip")).toHaveText("Revoked");
    await page.locator('[data-action="archive"]').click();
    await expect(page.locator(".card .status-chip")).toHaveText("Archived");
    await expect(page.locator(".source-panel")).toContainText("not deployed ledger evidence");
    await page.locator(".advanced-workflows > summary").click();
    await expect(page.locator(".governance-task-grid a")).toHaveCount(4);
    expect(await page.locator(".governance-task-grid a").evaluateAll((links) => links.every((link) =>
      document.querySelector(link.getAttribute("href")) !== null))).toBe(true);
    expect(posted).toEqual([
      `/v1/applications/issuer/${encodeURIComponent(id)}/approve`,
      `/v1/applications/issuer/${encodeURIComponent(id)}/activate`,
      `/v1/applications/issuer/${encodeURIComponent(id)}/suspend`,
      `/v1/applications/issuer/${encodeURIComponent(id)}/revoke`,
      `/v1/applications/issuer/${encodeURIComponent(id)}/archive`,
    ]);
  } finally {
    await page.close();
    server.closeAllConnections();
    await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
  }
});

test("fixture governance publishes an epoch and submits an externally signed workspace intent", async ({ page, allowedLocalOrigins }) => {
  const staticHandler = createStaticAssetHandler({
    distDir: resolve("packages/trust-registry-admin-console/dist"),
    name: "admin-console-governance-journey",
  });
  const registryId = "registry:ui-governance";
  const workspaceCommitment = `0x${"a".repeat(64)}`;
  let epochId = "epoch:ui-governance:1";
  const posted = [];
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (path !== "/health" && !path.startsWith("/v1/")) {
      await staticHandler(request, response);
      return;
    }
    response.setHeader("content-type", "application/json");
    if (path === "/health") {
      response.end(JSON.stringify({ status: "ok", sourceMode: "workspace", registryId }));
      return;
    }
    if (request.method === "POST") {
      let body = "";
      for await (const chunk of request) body += chunk;
      posted.push({ path, body: JSON.parse(body) });
      if (path === "/v1/epochs/publish") {
        epochId = "epoch:ui-governance:2";
        response.end(JSON.stringify({ recordKind: "epoch", epoch: { epochId } }));
      } else if (path === "/v1/mutations") {
        response.end(JSON.stringify({ recordKind: "authorization", operation: { operation: "approve" } }));
      } else {
        response.statusCode = 404;
        response.end(JSON.stringify({ title: "unexpected mutation" }));
      }
      return;
    }
    if (path === "/v1/registry/summary") {
      response.end(JSON.stringify({ ...summary("ui-governance"), registryId, currentEpochId: epochId }));
      return;
    }
    if (path === "/v1/registry/mutation-context") {
      response.end(JSON.stringify({ registryId, expectedEpochId: epochId,
        expectedWorkspaceCommitment: workspaceCommitment }));
      return;
    }
    response.end(JSON.stringify({ entries: [] }));
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected TCP address");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    allowedLocalOrigins.add(base);
    const confirmations = [];
    page.on("dialog", async (dialog) => {
      confirmations.push(dialog.message());
      await dialog.accept();
    });
    await page.goto(`${base}/?apiBase=${encodeURIComponent(base)}`);
    await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    await page.locator(".advanced-workflows > summary").click();
    await page.locator("[data-epoch-label]").fill("reviewed fixture epoch");
    await page.locator("[data-epoch-form] button[type='submit']").click();
    await expect(page.locator("[data-epoch-label]")).toBeEmpty();
    await expect(page.locator(".workspace-settings")).toContainText("epoch:ui-governance:2");
    expect(confirmations[0]).toContain("reviewed fixture epoch");
    expect(posted[0]).toEqual({ path: "/v1/epochs/publish", body: { label: "reviewed fixture epoch" } });

    await page.locator("[data-signed-context]").click();
    await expect(page.locator("#task-signed-intent")).toContainText(workspaceCommitment);
    const envelope = {
      intent: { registryId, expectedEpochId: epochId,
        expectedWorkspaceCommitment: workspaceCommitment, actorRole: "maintainer",
        targetId: "auth:issuer:ui-governance:v1" },
      signature: { algorithm: "external-fixture-signature" },
      operation: { operation: "approve", target: "issuer", id: "auth:issuer:ui-governance:v1" },
    };
    await page.locator("[data-signed-submit] [name='signedEnvelope']").fill(JSON.stringify(envelope));
    await page.locator("[data-signed-submit] button[type='submit']").click();
    await expect(page.locator(".alert.success")).toContainText("Signed approve accepted");
    expect(confirmations[1]).toContain(envelope.intent.targetId);
    expect(posted[1]).toEqual({ path: "/v1/mutations", body: envelope });
    await expect(page.locator(".source-panel")).toContainText("not deployed ledger evidence");
    await expect(page.locator("[data-signed-submit] button[type='submit']")).toBeDisabled();
  } finally {
    await page.close();
    server.closeAllConnections();
    await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
  }
});
