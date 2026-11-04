import { createServer } from "node:http";
import { resolve } from "node:path";

import { expect, test } from "./offline-browser-fixture.mjs";
import { createStaticAssetHandler } from "../scripts/serve-static.mjs";

const id = "auth:issuer:exact-ui:v1";
const did = "did:midnight:undeployed:exact-ui";
const resourceId = `tr:issuer-resource:v1:${"a".repeat(64)}`;
const registryId = "registry:local-ui";
const entry = { label: "Exact UI issuer", authorization: {
  authorizationId: id, registryId, role: "issuer", subjectDid: did,
  resourceType: "credential-family", resourceId, policyId: "policy:local-ui",
  trustLevel: "approved", status: "active", proposedAt: "2026-05-20T00:00:00Z",
  activeFrom: "2026-05-20T00:01:00Z",
}, evidence: { epoch: { epochId: "epoch:local-ui:1", stateRoot: "0xroot" } } };
const counts = { proposed: 0, authorized: 0, active: 1, suspended: 0,
  revoked: 0, superseded: 0, archived: 0 };
const emptyCounts = { ...counts, active: 0 };
const summary = { registryLabel: "Local UI registry", registryId,
  registryDid: "did:midnight:undeployed:local-ui", policyId: "policy:local-ui",
  currentEpochId: "epoch:local-ui:1", epochCount: 1,
  issuerCounts: counts, verifierCounts: emptyCounts,
  auditorCounts: emptyCounts, recognitionCounts: emptyCounts };

async function serveLocalApp(app) {
  const staticHandler = createStaticAssetHandler({
    distDir: resolve(`packages/trust-registry-${app}/dist`), name: `local-lookup-${app}`,
  });
  const requests = [];
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (path !== "/health" && !path.startsWith("/v1/")) {
      await staticHandler(request, response);
      return;
    }
    requests.push(`${request.method} ${path}`);
    response.setHeader("content-type", "application/json");
    if (path === "/health") response.end(JSON.stringify({ status: "ok", sourceMode: "local-ledger",
      registryId, localPlanSha256: "b".repeat(64), finalizedBlockHash: `0x${"c".repeat(64)}`,
      generatedAt: "2026-10-27T00:00:00Z" }));
    else if (path === "/v1/registry/summary") response.end(JSON.stringify(summary));
    else if (path === `/v1/authorizations/issuer/${encodeURIComponent(id)}`
      || path === "/v1/authorizations/resolve") response.end(JSON.stringify(entry));
    else {
      response.statusCode = 503;
      response.end(JSON.stringify({ title: "Broad lists unavailable" }));
    }
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected TCP address");
  return { base: `http://127.0.0.1:${address.port}`, requests,
    close: async () => {
      server.closeAllConnections();
      await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
    } };
}

test("admin exact lookup presents a local API claim without fixture controls", async ({ page, allowedLocalOrigins }) => {
  const host = await serveLocalApp("admin-console");
  try {
    allowedLocalOrigins.add(host.base);
    await page.goto(`${host.base}/?apiBase=${encodeURIComponent(host.base)}`);
    await expect(page.locator(".source-badge")).toHaveText("API claim");
    await page.locator(".workspace-settings > summary").click();
    await expect(page.locator(".workspace-settings")).toContainText("Node-reported checkpoint hash");
    await expect(page.locator(".workspace-settings")).toContainText(`0x${"c".repeat(64)}`);
    await expect(page.locator(".workspace-settings")).toContainText("not independently authenticated finality");
    await expect(page.locator("[data-action]")).toHaveCount(0);
    await page.locator("[data-current-id]").fill(id);
    await page.locator("[data-current-lookup] button[type='submit']").click();
    await expect(page.locator(".card")).toContainText("Exact UI issuer");
    await expect(page.locator(".source-panel")).toContainText("not independently verified finality");
    expect(host.requests.some((value) => value.startsWith("POST "))).toBe(false);
    expect(host.requests.some((value) => value === "GET /v1/authorizations/issuer")).toBe(false);
  } finally {
    await page.close();
    await host.close();
  }
});

test("applicant exact scope lookup keeps returned trust unverified", async ({ page, allowedLocalOrigins }) => {
  const host = await serveLocalApp("applicant-portal");
  try {
    allowedLocalOrigins.add(host.base);
    await page.goto(`${host.base}/?apiBase=${encodeURIComponent(host.base)}`);
    await expect(page.locator(".source-badge")).toHaveText("API claim");
    await page.locator(".workspace-settings > summary").click();
    await expect(page.locator(".workspace-settings")).toContainText("Node-reported checkpoint time");
    await expect(page.locator(".workspace-settings")).toContainText("2026-10-27T00:00:00Z");
    await expect(page.locator("[data-current-authorization]")).toBeVisible();
    await page.locator("[data-current-authorization] [name='subjectDid']").fill(did);
    await page.locator("[data-current-authorization] [name='resourceId']").fill(resourceId);
    await page.locator("[data-current-authorization] button[type='submit']").click();
    await expect(page.locator("[data-current-authorization-result]")).toContainText("Unverified current API claim");
    await expect(page.locator("[data-current-authorization-result]")).toContainText("active");
    expect(host.requests).toContain("POST /v1/authorizations/resolve");
    expect(host.requests.some((value) => value === "GET /v1/authorizations/issuer")).toBe(false);
  } finally {
    await page.close();
    await host.close();
  }
});
