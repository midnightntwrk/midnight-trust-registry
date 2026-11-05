import { createServer } from "node:http";
import { resolve } from "node:path";

import { expectNoWcagViolations } from "./accessibility-audit.mjs";
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
const recognition = { label: "External authority", recognition: {
  registryId, recognizedAuthorityDid: "did:web:authority.example",
  recognizedRegistryId: "external:registry", status: "active",
  scope: { resourceType: "schema", resourceId: "degree",
    context: { purpose: "assurance" } },
} };
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
  let sourceMode = "local-ledger";
  let heldHealth;
  let denyCurrentReads = false;
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (path !== "/health" && !path.startsWith("/v1/")) {
      await staticHandler(request, response);
      return;
    }
    requests.push(`${request.method} ${path}`);
    response.setHeader("content-type", "application/json");
    if (path === "/health") {
      if (heldHealth !== undefined) {
        const pending = heldHealth;
        heldHealth = undefined;
        await pending;
      }
      response.end(JSON.stringify({ status: "ok", sourceMode,
        registryId, localPlanSha256: "b".repeat(64), finalizedBlockHash: `0x${"c".repeat(64)}`,
        generatedAt: "2026-10-27T00:00:00Z" }));
    }
    else if (path === "/v1/registry/summary") response.end(JSON.stringify(sourceMode === "local-ledger"
      ? summary : { ...summary, issuerCounts: emptyCounts }));
    else if (denyCurrentReads && (path === `/v1/authorizations/issuer/${encodeURIComponent(id)}`
      || path === "/v1/authorizations/resolve")) {
      response.statusCode = 403;
      response.end(JSON.stringify({ title: "Current authorization denied", detail: "The source refused this exact lookup." }));
    }
    else if (path === `/v1/authorizations/issuer/${encodeURIComponent(id)}`
      || path === "/v1/authorizations/resolve") response.end(JSON.stringify(entry));
    else if (path === "/v1/recognitions/resolve") response.end(JSON.stringify(recognition));
    else if (sourceMode === "workspace") response.end(JSON.stringify({ entries: [] }));
    else {
      response.statusCode = 503;
      response.end(JSON.stringify({ title: "Broad lists unavailable" }));
    }
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected TCP address");
  return { base: `http://127.0.0.1:${address.port}`, requests,
    setSourceMode: (mode) => { sourceMode = mode; },
    setCurrentReadsDenied: (denied) => { denyCurrentReads = denied; },
    holdNextHealth: () => {
      let release;
      heldHealth = new Promise((resolve) => { release = resolve; });
      return () => release();
    },
    close: async () => {
      server.closeAllConnections();
      await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
    } };
}

async function reviewLocalLayouts(page, testInfo, app) {
  for (const width of [1440, 768, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await expect(page.locator(".source-badge")).toHaveText("API claim");
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width + 1);
    if (app === "applicant") {
      const layout = await page.locator(".current-lookup-panel:not([hidden])").evaluate((panel) => {
        const input = panel.querySelector(".lookup-input").getBoundingClientRect();
        const result = panel.querySelector(".lookup-result").getBoundingClientRect();
        return { inputRight: input.right, inputBottom: input.bottom, resultLeft: result.left, resultTop: result.top };
      });
      if (width > 980) expect(layout.resultLeft).toBeGreaterThanOrEqual(layout.inputRight);
      else expect(layout.resultTop).toBeGreaterThanOrEqual(layout.inputBottom);
      await expect(page.locator(".current-lookup-panel:not([hidden]) .lookup-result"))
        .toContainText("not independently authenticated finality");
    }
    if (width === 390) await expectNoWcagViolations(page, `${app} exact lookup`);
    if (process.env.TR_UI_CAPTURE === "1") {
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: testInfo.outputPath(`${app}-local-lookup-${width}.png`), fullPage: true });
      if (app === "applicant") {
        await page.locator(".current-lookup-panel:not([hidden])").screenshot({
          path: testInfo.outputPath(`${app}-selected-lookup-${width}.png`),
        });
      }
    }
    if (width <= 760) {
      await page.locator(".mobile-task-menu > summary").click();
      await page.locator(".mobile-task-menu nav a").filter({ hasText: "Workspace settings" }).click();
    } else {
      await page.locator(".task-nav a").filter({ hasText: "Workspace settings" }).click();
    }
    await expect(page.locator(".settings-view")).toBeVisible();
    await expect(page.locator(".settings-view")).toContainText(app === "admin"
      ? "not independently authenticated finality" : "do not establish finalized ledger state");
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width + 1);
    if (width === 390) await expectNoWcagViolations(page, `${app} local settings`);
    if (process.env.TR_UI_CAPTURE === "1") {
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: testInfo.outputPath(`${app}-local-settings-${width}.png`), fullPage: true });
    }
    await page.locator(".settings-back").click();
    if (app === "applicant") {
      await expect(page.locator("#current-recognition-lookup")).toBeVisible();
      await expect(page.locator("#current-authorization-lookup")).toBeHidden();
    }
  }
}

test("admin exact lookup presents a local API claim without fixture controls", async ({ page, allowedLocalOrigins }, testInfo) => {
  const host = await serveLocalApp("admin-console");
  try {
    allowedLocalOrigins.add(host.base);
    await page.goto(`${host.base}/?apiBase=${encodeURIComponent(host.base)}`);
    await expect(page.locator(".source-badge")).toHaveText("API claim");
    await expect(page.getByRole("heading", { name: "Inspect current records" })).toBeVisible();
    await expect(page.locator(".hero > .metrics .metric")).toHaveCount(0);
    await expect(page.locator(".hero > .metrics")).toContainText("Local UI registry");
    await expect(page.locator(".hero-copy a")).toHaveAttribute("href", "#exact-lookup");
    await page.locator(".task-nav a").filter({ hasText: "Workspace settings" }).click();
    await expect(page.locator(".settings-view")).toContainText("Node-reported checkpoint hash");
    await expect(page.locator(".settings-view")).toContainText(`0x${"c".repeat(64)}`);
    await expect(page.locator(".settings-view")).toContainText("not independently authenticated finality");
    await page.locator(".settings-back").click();
    await expect(page.locator("[data-action]")).toHaveCount(0);
    const lookupButton = page.locator("[data-current-lookup] button[type='submit']");
    await lookupButton.click();
    await expect(page.locator("#exact-lookup").getByRole("alert"))
      .toContainText("Enter the exact current authorization or recognition ID.");
    await expect(lookupButton).toBeFocused();
    await page.locator("[data-current-id]").fill(id);
    await expect(page.locator("#exact-lookup").getByRole("alert")).toHaveCount(0);
    await lookupButton.click();
    await expect(page.locator(".card")).toContainText("Exact UI issuer");
    await expect(page.locator(".hero > .metrics .metric")).toHaveCount(0);
    await expect(lookupButton).toBeFocused();
    await expect(page.locator(".source-panel")).toContainText("not independently verified finality");
    await reviewLocalLayouts(page, testInfo, "admin");
    expect(host.requests.some((value) => value.startsWith("POST "))).toBe(false);
    expect(host.requests.some((value) => value === "GET /v1/authorizations/issuer")).toBe(false);
  } finally {
    await page.close();
    await host.close();
  }
});

test("applicant exact scope lookup keeps returned trust unverified", async ({ page, allowedLocalOrigins }, testInfo) => {
  const host = await serveLocalApp("applicant-portal");
  try {
    allowedLocalOrigins.add(host.base);
    await page.goto(`${host.base}/?apiBase=${encodeURIComponent(host.base)}`);
    await expect(page.locator(".source-badge")).toHaveText("API claim");
    await expect(page.locator(".hero-overview")).toContainText("Registry context");
    await expect(page.locator(".hero-overview")).toContainText("API-reported epoch");
    await expect(page.locator(".hero-overview .metric")).toHaveCount(2);
    await expect(page.locator(".hero-overview")).not.toContainText("Active issuers");
    await expect(page.locator(".task-nav a").first()).toHaveAttribute("href", "#current-authorization-lookup");
    await expect(page.locator(".hero-actions a").first()).toHaveAttribute("href", "#current-authorization-lookup");
    await expect(page.locator(".source-panel")).toContainText("Broad lists are not offered in this mode");
    await expect(page.locator(".alert.error")).toHaveCount(0);
    expect(await page.locator("#current-authorization-lookup").evaluate((element) =>
      element.compareDocumentPosition(document.querySelector("#governed-requests"))))
      .toBe(4);
    await expect(page.locator("#trust-records")).toHaveCount(0);
    await expect(page.locator("#demo-application")).toHaveCount(0);
    await expect(page.locator("#current-recognition-lookup")).toBeHidden();
    await expect(page.locator(".lookup-switch a[aria-current='location']")).toHaveText("Authorization");
    await expect(page.locator("#current-authorization-lookup .lookup-empty")).toContainText("No record loaded yet");
    await page.locator(".task-nav a").filter({ hasText: "Workspace settings" }).click();
    await expect(page.locator(".settings-view")).toContainText("Node-reported checkpoint time");
    await expect(page.locator(".settings-view")).toContainText("2026-10-27T00:00:00Z");
    await page.locator(".settings-back").click();
    await expect(page.locator("[data-current-authorization]")).toBeVisible();
    await page.locator("[data-current-authorization] [name='subjectDid']").fill(did);
    await page.locator("[data-current-authorization] [name='resourceId']").fill(resourceId);
    const authorizationButton = page.locator("[data-current-authorization] button[type='submit']");
    await authorizationButton.click();
    await expect(page.locator("[data-current-authorization-result]")).toContainText("Unverified current API claim");
    await expect(page.locator("[data-current-authorization-result]")).toContainText("active");
    await expect(page.locator("[data-current-authorization-result]")).toHaveAttribute("role", "status");
    await expect(authorizationButton).toBeFocused();
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"], { origin: host.base });
    await page.locator("[data-current-authorization-result] details > summary").click();
    await page.locator("[data-current-authorization-result] [data-copy-current-claim]").click();
    await expect(page.locator("[data-current-authorization-result] [data-copy-claim-feedback]"))
      .toContainText("Copied current API claim. Verify before relying on it.");
    const copiedAuthorization = await page.evaluate(() => navigator.clipboard.readText());
    expect(JSON.parse(copiedAuthorization).authorization.subjectDid).toBe(did);
    expect(JSON.parse(copiedAuthorization).authorization.resourceId).toBe(resourceId);
    await page.locator(".lookup-switch a[href='#current-recognition-lookup']").click();
    await expect(page.locator("#current-recognition-lookup")).toBeVisible();
    await expect(page.locator("#current-authorization-lookup")).toBeHidden();
    await expect(page.locator(".lookup-switch a[aria-current='location']")).toHaveText("External recognition");
    const form = page.locator("[data-current-recognition]");
    await form.locator("[name='recognizedAuthorityDid']").fill("did:web:authority.example");
    await form.locator("[name='recognizedRegistryId']").fill("external:registry");
    await form.locator("[name='scopeResourceType']").fill("schema");
    await form.locator("[name='scopeResourceId']").fill("degree");
    const recognitionButton = form.locator("button[type='submit']");
    await form.locator("[name='scopeContext']").fill('{"purpose":1}');
    await recognitionButton.click();
    await expect(page.getByRole("alert")).toContainText("Recognition scope context must be a JSON object of string values.");
    await expect(page.locator("#current-recognition-lookup .lookup-result")).toContainText("not independently authenticated finality");
    await expect(recognitionButton).toBeFocused();
    expect(host.requests).not.toContain("POST /v1/recognitions/resolve");
    await form.locator("[name='scopeContext']").fill('{"purpose":"assurance"}');
    await recognitionButton.click();
    await expect(page.locator("[data-current-recognition-result]"))
      .toContainText("Unverified current API claim: active");
    await expect(page.locator("[data-current-recognition-result]")).toHaveAttribute("role", "status");
    await expect(recognitionButton).toBeFocused();
    await page.locator("[data-current-recognition-result] details > summary").click();
    await page.locator("[data-current-recognition-result] [data-copy-current-claim]").click();
    await expect(page.locator("[data-current-recognition-result] [data-copy-claim-feedback]"))
      .toContainText("Copied current API claim. Verify before relying on it.");
    const copiedRecognition = await page.evaluate(() => navigator.clipboard.readText());
    expect(JSON.parse(copiedRecognition).recognition.recognizedRegistryId).toBe("external:registry");
    expect(JSON.parse(copiedRecognition).recognition.scope.resourceId).toBe("degree");
    await page.evaluate(() => {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText: async () => { throw new Error("Permission denied"); } },
      });
    });
    await page.locator("[data-current-recognition-result] [data-copy-current-claim]").click();
    await expect(page.locator("[data-current-recognition-result] [data-copy-claim-feedback]"))
      .toContainText("Copy unavailable. Select the JSON below to copy it manually.");
    const lookupRequests = host.requests.filter((value) => value.startsWith("POST /v1/")).length;
    await page.locator(".lookup-switch a[href='#current-authorization-lookup']").click();
    await expect(page.locator("[data-current-authorization-result]")).toContainText("Unverified current API claim");
    await page.locator(".lookup-switch a[href='#current-recognition-lookup']").click();
    await expect(page.locator("[data-current-recognition-result]")).toContainText("Unverified current API claim");
    expect(host.requests.filter((value) => value.startsWith("POST /v1/")).length).toBe(lookupRequests);
    await reviewLocalLayouts(page, testInfo, "applicant");
    await form.locator("[name='scopeResourceId']").fill("substituted-degree");
    await form.locator("button[type='submit']").click();
    await expect(page.locator("[data-current-recognition-result]")).toHaveCount(0);
    await expect(page.locator("#current-recognition-lookup .lookup-result")).toContainText("does not match the requested scope");
    expect(host.requests).toContain("POST /v1/authorizations/resolve");
    expect(host.requests).toContain("POST /v1/recognitions/resolve");
    expect(host.requests.some((value) => value === "GET /v1/authorizations/issuer")).toBe(false);
  } finally {
    await page.close();
    await host.close();
  }
});

test("applicant recognition deep link selects only the external lookup", async ({ page, allowedLocalOrigins }) => {
  const host = await serveLocalApp("applicant-portal");
  try {
    allowedLocalOrigins.add(host.base);
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(`${host.base}/?apiBase=${encodeURIComponent(host.base)}#current-recognition-lookup`);
    await expect(page.locator(".source-badge")).toHaveText("API claim");
    await expect(page.locator("#current-recognition-lookup")).toBeVisible();
    await expect(page.locator("#current-authorization-lookup")).toBeHidden();
    await expect(page.locator(".lookup-switch a[aria-current='location']")).toHaveText("External recognition");
    await expect(page.locator(".lookup-switch a")).toHaveCount(2);
    await expect(page.locator("#current-recognition-lookup .lookup-empty")).toContainText("No record loaded yet");
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
    await page.locator(".lookup-switch a[href='#current-authorization-lookup']").click();
    await expect(page.locator("#current-authorization-lookup")).toBeVisible();
    await expect(page.locator("#current-authorization-lookup .lookup-empty")).toContainText("No record loaded yet");
    const pickerTop = await page.locator(".lookup-picker").evaluate((element) => element.getBoundingClientRect().top);
    expect(pickerTop).toBeGreaterThanOrEqual(-1);
    expect(pickerTop).toBeLessThan(844);
  } finally {
    await page.close();
    await host.close();
  }
});

for (const app of ["admin-console", "applicant-portal"]) {
  test(`${app} keeps exact lookup readable at 320px and 200% text`, async ({ page, allowedLocalOrigins }, testInfo) => {
    const host = await serveLocalApp(app);
    try {
      allowedLocalOrigins.add(host.base);
      await page.setViewportSize({ width: 320, height: 700 });
      await page.goto(`${host.base}/?apiBase=${encodeURIComponent(host.base)}`);
      await expect(page.locator(".source-badge")).toHaveText("API claim");
      await page.addStyleTag({ content: "html { font-size: 200%; }" });
      const checkWidth = async () => {
        const layout = await page.evaluate(() => ({
          page: document.documentElement.scrollWidth,
          overflowing: [...document.querySelectorAll("body *")]
            .filter((element) => !element.matches("input, textarea, select, .lookup-result pre")
              && element.scrollWidth > element.clientWidth + 1)
            .slice(0, 8).map((element) => `${element.tagName}.${element.className}:${element.scrollWidth}/${element.clientWidth}`),
        }));
        expect(layout.page, JSON.stringify(layout)).toBeLessThanOrEqual(320);
        expect(layout.overflowing).toEqual([]);
      };
      await checkWidth();
      if (app === "admin-console") {
        await page.locator("[data-current-id]").fill(id);
        await page.locator("[data-current-lookup] button[type='submit']").click();
        await expect(page.locator(".card")).toContainText("Exact UI issuer");
        await page.locator(".technical-details > summary").click();
      } else {
        await expect(page.locator(".lookup-picker")).toBeVisible();
        await expect(page.locator(".current-lookup-panel:not([hidden]) .lookup-empty"))
          .toContainText("No record loaded yet");
        const switchWidth = await page.locator(".lookup-switch a").first()
          .evaluate((element) => element.getBoundingClientRect().width);
        expect(switchWidth).toBeGreaterThanOrEqual(200);
        await page.locator(".lookup-switch a[href='#current-recognition-lookup']").click();
        await expect(page.locator("#current-recognition-lookup")).toBeVisible();
        const form = page.locator("[data-current-recognition]");
        await form.locator("[name='recognizedAuthorityDid']").fill("did:web:authority.example");
        await form.locator("[name='recognizedRegistryId']").fill("external:registry");
        await form.locator("[name='scopeResourceType']").fill("schema");
        await form.locator("[name='scopeResourceId']").fill("degree");
        await form.locator("[name='scopeContext']").fill('{"purpose":"assurance"}');
        await form.locator("button[type='submit']").click();
        await expect(page.locator("[data-current-recognition-result]"))
          .toContainText("Unverified current API claim");
        await page.locator("[data-current-recognition-result] details > summary").click();
        const rawJson = page.locator("[data-current-recognition-result] pre");
        await expect(rawJson).toHaveAttribute("tabindex", "0");
        await rawJson.focus();
        await expect(rawJson).toBeFocused();
        const technical = await rawJson.evaluate((element) => ({
          height: element.getBoundingClientRect().height,
          scrollable: element.scrollWidth > element.clientWidth,
        }));
        expect(technical.height).toBeLessThanOrEqual(750);
        expect(technical.scrollable).toBe(true);
        if (process.env.TR_UI_CAPTURE === "1") {
          await page.locator("#current-recognition-lookup .lookup-result").screenshot({ path: testInfo.outputPath("applicant-portal-local-zoom-result-320.png") });
        }
      }
      await checkWidth();
      if (process.env.TR_UI_CAPTURE === "1") {
        await page.screenshot({ path: testInfo.outputPath(`${app}-local-zoom-320.png`), fullPage: true });
      }
    } finally {
      await page.close();
      await host.close();
    }
  });

  test(`${app} discards a local API claim while its source is rechecked and changes mode`, async ({ page, allowedLocalOrigins }) => {
    const host = await serveLocalApp(app);
    let releaseHealth = () => {};
    try {
      allowedLocalOrigins.add(host.base);
      await page.goto(`${host.base}/?apiBase=${encodeURIComponent(host.base)}`);
      await expect(page.locator(".source-badge")).toHaveText("API claim");
      if (app === "admin-console") {
        await page.locator("[data-current-id]").fill(id);
        await page.locator("[data-current-lookup] button[type='submit']").click();
        await expect(page.locator(".card")).toContainText("Exact UI issuer");
      } else {
        const form = page.locator("[data-current-authorization]");
        await form.locator("[name='subjectDid']").fill(did);
        await form.locator("[name='resourceId']").fill(resourceId);
        await form.locator("button[type='submit']").click();
        await expect(page.locator("[data-current-authorization-result]"))
          .toContainText("Unverified current API claim");
      }

      releaseHealth = host.holdNextHealth();
      host.setSourceMode("workspace");
      const refresh = page.locator("[data-refresh]");
      await refresh.click();
      await expect(page.locator(".source-panel")).toHaveAttribute("data-source-state", "loading");
      await expect(page.locator(".source-badge")).toHaveText("Checking");
      await expect(refresh).toBeDisabled();
      await expect(page.getByText("Unverified current API claim", { exact: false })).toHaveCount(0);
      releaseHealth();
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await expect(refresh).toBeFocused();
      await expect(page.locator("#exact-lookup, #current-authorization-lookup")).toHaveCount(0);
      await expect(page.getByText("Unverified current API claim", { exact: false })).toHaveCount(0);

      host.setSourceMode("local-ledger");
      await refresh.click();
      await expect(page.locator(".source-badge")).toHaveText("API claim");
      await expect(page.getByText("Unverified current API claim", { exact: false })).toHaveCount(0);

      if (app === "admin-console") {
        await page.locator("[data-current-id]").fill(id);
        const submit = page.locator("[data-current-lookup] button[type='submit']");
        await submit.click();
        await expect(page.locator(".card")).toContainText("Exact UI issuer");
        host.setCurrentReadsDenied(true);
        await submit.click();
        await expect(page.locator("#exact-lookup").getByRole("alert")).toContainText("Current authorization denied");
        await expect(page.locator(".card")).toHaveCount(0);
      } else {
        const form = page.locator("[data-current-authorization]");
        await form.locator("[name='subjectDid']").fill(did);
        await form.locator("[name='resourceId']").fill(resourceId);
        const submit = form.locator("button[type='submit']");
        await submit.click();
        await expect(page.locator("[data-current-authorization-result]"))
          .toContainText("Unverified current API claim");
        host.setCurrentReadsDenied(true);
        await submit.click();
        await expect(page.getByRole("alert")).toContainText("Current authorization denied");
        await expect(page.locator("[data-current-authorization-result]")).toHaveCount(0);
      }
      await expect(page.locator(".source-badge")).toHaveText("API claim");
    } finally {
      releaseHealth();
      await page.close();
      await host.close();
    }
  });
}
