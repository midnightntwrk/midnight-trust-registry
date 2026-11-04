import { createServer } from "node:http";
import { resolve } from "node:path";

import { expectNoWcagViolations } from "./accessibility-audit.mjs";
import { expect, test } from "./offline-browser-fixture.mjs";
import { createStaticAssetHandler } from "../scripts/serve-static.mjs";

const longResource = `tr:issuer-resource:v1:${"a".repeat(64)}`;
const longDid = `did:midnight:undeployed:${"b".repeat(80)}`;
const counts = { proposed: 0, authorized: 0, active: 1, suspended: 0,
  revoked: 0, superseded: 0, archived: 0 };
const emptyCounts = { ...counts, active: 0 };
const summary = {
  registryLabel: "Midnight Trust Registry",
  registryId: "registry:midnight:local",
  registryDid: "did:midnight:undeployed:registry",
  policyId: "policy:midnight:v1",
  currentEpochId: `epoch:registry:midnight:local:trusted:${"c".repeat(48)}:4`,
  epochCount: 4,
  issuerCounts: counts, verifierCounts: emptyCounts,
  auditorCounts: emptyCounts, recognitionCounts: emptyCounts,
};
const issuer = {
  label: "Local demo issuer",
  authorization: {
    authorizationId: "auth:issuer:local-demo-issuer:v1",
    registryId: summary.registryId,
    role: "issuer",
    subjectDid: longDid,
    resourceType: "credential-family",
    resourceId: longResource,
    policyId: summary.policyId,
    trustLevel: "approved",
    status: "active",
    proposedAt: "2026-05-20T00:00:00.000Z",
    activeFrom: "2026-05-20T00:04:00.000Z",
  },
  evidence: { epoch: { epochId: summary.currentEpochId, stateRoot: "0xroot" } },
};

async function serveApp(app) {
  let healthAvailable = true;
  let auditorAvailable = true;
  const requests = [];
  const packagedPath = app === "admin-console" ? "/admin/" : "/applicant/";
  const staticHandler = createStaticAssetHandler({
    distDir: resolve(`packages/trust-registry-${app}/dist`),
    name: `ui-layout-${app}`,
  });
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (path !== "/health" && !path.startsWith("/v1/")) {
      if (path.startsWith(packagedPath)) request.url = (request.url ?? "/").replace(packagedPath, "/");
      await staticHandler(request, response);
      return;
    }
    requests.push(`${request.method} ${path}`);
    response.setHeader("content-type", "application/json");
    if (path === "/health") {
      if (!healthAvailable) response.statusCode = 503;
      response.end(JSON.stringify(healthAvailable
        ? { status: "ok", sourceMode: "workspace" }
        : { title: "Registry unavailable", detail: "Fixture host is offline" }));
    }
    else if (path === "/v1/registry/summary") response.end(JSON.stringify(summary));
    else if (path === "/v1/authorizations/auditor" && !auditorAvailable) {
      response.statusCode = 503;
      response.end(JSON.stringify({ title: "Auditor list unavailable" }));
    }
    else response.end(JSON.stringify({ entries: path === "/v1/authorizations/issuer" ? [issuer] : [] }));
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected TCP address");
  return {
    base: `http://127.0.0.1:${address.port}`,
    packagedPath,
    requests,
    setHealthAvailable: (available) => { healthAvailable = available; },
    setAuditorAvailable: (available) => { auditorAvailable = available; },
    close: async () => {
      server.closeAllConnections();
      await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
    },
  };
}

test("applicant portal treats a failed list as unavailable, then recovers on recheck", async ({ page, allowedLocalOrigins }) => {
  const server = await serveApp("applicant-portal");
  try {
    server.setAuditorAvailable(false);
    allowedLocalOrigins.add(server.base);
    await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
    await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    await expect(page.locator(".source-panel")).toContainText("1 list(s) unavailable; counts shown as n/a");
    const auditorLane = page.locator(".lane").filter({ has: page.getByRole("heading", { name: "Active auditors" }) });
    await expect(auditorLane).toContainText("unavailable");
    await expect(auditorLane).toContainText("Do not infer trust from this lane");
    await expect(auditorLane).not.toContainText("0 active");
    await expect(page.locator("#trust-records")).toContainText("Local demo issuer");

    server.setAuditorAvailable(true);
    await page.locator("[data-refresh]").click();
    await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    await expect(page.locator(".source-panel")).not.toContainText("list(s) unavailable");
    await expect(page.locator(".lane").filter({ has: page.getByRole("heading", { name: "Active auditors" }) })).toHaveCount(0);
  } finally {
    await page.close();
    await server.close();
  }
});

for (const app of ["admin-console", "applicant-portal"]) {
  test(`${app} serves the shared Midnight browser icon`, async ({ page, allowedLocalOrigins }) => {
    const server = await serveApp(app);
    try {
      allowedLocalOrigins.add(server.base);
      await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
      const icon = page.locator('link[rel="icon"]');
      await expect(icon).toHaveAttribute("type", "image/svg+xml");
      const response = await page.request.get(new URL(await icon.getAttribute("href"), server.base).href);
      expect(response.ok()).toBe(true);
      expect(response.headers()["content-type"]).toContain("image/svg+xml");
      expect(await response.text()).toContain('viewBox="0 0 32 32"');
    } finally {
      await page.close();
      await server.close();
    }
  });

  test(`${app} switches editable development endpoints without widening private access`, async ({ page, allowedLocalOrigins }) => {
    const first = await serveApp(app);
    const second = await serveApp(app);
    try {
      allowedLocalOrigins.add(first.base);
      allowedLocalOrigins.add(second.base);
      await page.goto(`${first.base}/?apiBase=${encodeURIComponent(first.base)}`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      const firstReads = first.requests.length;
      await page.locator(".task-nav a").filter({ hasText: "Workspace settings" }).click();
      const form = page.locator("[data-api-base-form]");
      await expect(page.locator(".settings-view")).toBeVisible();
      await expect(page.locator(".hero")).toBeHidden();
      await expect(form.locator("[name='apiBase']")).toBeEnabled();
      await form.locator("[name='apiBase']").fill(second.base);
      await form.locator("button[type='submit']").click();
      await expect(form.locator("[name='apiBase']")).toHaveValue(second.base);
      await expect(page.locator(".settings-view")).toBeVisible();
      await page.locator("[data-settings-refresh]").click();
      await expect(page.locator(".settings-view")).toBeVisible();
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await expect(page.locator(".settings-view")).toContainText(`${second.base} (local development setting)`);
      expect(second.requests).toContain("GET /health");
      expect(second.requests).toContain("GET /v1/registry/summary");
      expect(first.requests).toHaveLength(firstReads);
      if (app === "applicant-portal") {
        await page.locator(".settings-back").click();
        await page.locator(".advanced-tools > summary").click();
        await page.locator('[data-workflow="Recover external recognition"] > summary').click();
        await expect(page.locator("[data-recognition-challenge]")).toBeDisabled();
        await expect(page.locator(".journey-prerequisite")).toContainText("cannot submit governed evidence");
      }
    } finally {
      await page.close();
      await first.close();
      await second.close();
    }
  });

  test(`${app} keeps critical Midnight text pairs above normal-text contrast`, async ({ page, allowedLocalOrigins }) => {
    const server = await serveApp(app);
    try {
      allowedLocalOrigins.add(server.base);
      await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      const ratios = await page.evaluate(() => {
        const rgb = (value) => {
          const channels = value.match(/^rgba?\((\d+),\s*(\d+),\s*(\d+)/u);
          if (channels === null) throw new Error(`Expected a solid RGB color, got ${value}`);
          return channels.slice(1).map(Number);
        };
        const luminance = (value) => {
          const linear = rgb(value).map((channel) => {
            const normalized = channel / 255;
            return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
        };
        const samples = [
          ["brand", ".brand-name", ".brand-bar"],
          ["product title", ".brand-product-title", ".brand-bar"],
          ["product context", ".brand-product-context", ".brand-bar"],
          ["navigation", ".app-shell > .task-nav a", ".app-shell > .task-nav"],
          ["source", ".source-badge", ".source-badge"],
          ["primary action", ".button:not(.secondary):not(:disabled)", ".button:not(.secondary):not(:disabled)"],
          ["secondary action", ".button.secondary:not(:disabled)", ".button.secondary:not(:disabled)"],
        ];
        return samples.map(([name, textSelector, surfaceSelector]) => {
          const text = document.querySelector(textSelector);
          const surface = document.querySelector(surfaceSelector);
          if (text === null || surface === null) throw new Error(`Missing ${name} contrast sample`);
          const foreground = getComputedStyle(text).color;
          const background = getComputedStyle(surface).backgroundColor;
          const lighter = Math.max(luminance(foreground), luminance(background));
          const darker = Math.min(luminance(foreground), luminance(background));
          return { name, foreground, background, ratio: (lighter + 0.05) / (darker + 0.05) };
        });
      });
      for (const sample of ratios) {
        expect(sample.ratio, JSON.stringify(sample)).toBeGreaterThanOrEqual(4.5);
      }
    } finally {
      await page.close();
      await server.close();
    }
  });

  test(`${app} opens named workspace settings by keyboard on mobile`, async ({ page, allowedLocalOrigins }) => {
    const server = await serveApp(app);
    try {
      allowedLocalOrigins.add(server.base);
      await page.setViewportSize({ width: 390, height: 900 });
      await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");

      const menu = page.locator(".mobile-task-menu > summary");
      await page.keyboard.press("Tab");
      await expect(menu).toBeFocused();
      await page.keyboard.press("Enter");
      const settingsLink = page.locator(".mobile-task-menu nav").getByRole("link", { name: "Workspace settings" });
      await expect(settingsLink).toBeVisible();
      await settingsLink.focus();
      await page.keyboard.press("Enter");

      await expect(page.getByRole("heading", { name: "Workspace settings" })).toBeVisible();
      await expect(page.getByRole("textbox", { name: "API base URL" })).toBeVisible();
      await expect(page.locator(".hero")).toBeHidden();
      const recheck = page.getByRole("button", { name: "Recheck connection" });
      await recheck.focus();
      await page.keyboard.press("Enter");
      await expect(recheck).toBeFocused();
      await expect(page.locator(".settings-view")).toBeVisible();

      await page.locator(".settings-back").click();
      await expect(page.locator(".settings-view")).toBeHidden();
      await expect(page.locator(".hero")).toBeVisible();
    } finally {
      await page.close();
      await server.close();
    }
  });

  test(`${app} locks the packaged endpoint to its same-origin host`, async ({ page, allowedLocalOrigins }) => {
    const server = await serveApp(app);
    try {
      allowedLocalOrigins.add(server.base);
      await page.goto(`${server.base}${server.packagedPath}?apiBase=https://outside.example`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await expect(page.locator("[data-api-base-form] [name='apiBase']")).toHaveValue(server.base);
      await expect(page.locator("[data-api-base-form] [name='apiBase']")).toBeDisabled();
      await expect(page.locator("[data-api-base-form] button[type='submit']")).toBeDisabled();
      await page.locator(".task-nav a").filter({ hasText: "Workspace settings" }).click();
      await expect(page.locator(".settings-view")).toContainText("managed by this host");
      await expect(page.locator(".settings-view")).not.toContainText("outside.example");
      if (app === "applicant-portal") {
        await expect(page.locator(".settings-view"))
          .toContainText("Private actions require the authenticated same-origin host");
      }
    } finally {
      await page.close();
      await server.close();
    }
  });

  test(`${app} distinguishes unavailable data from a live fixture`, async ({ page, allowedLocalOrigins }) => {
    const server = await serveApp(app);
    try {
      allowedLocalOrigins.add(server.base);
      await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      server.setHealthAvailable(false);
      await page.locator("[data-refresh]").click();
      await expect(page.locator(".source-badge")).toHaveText("Unavailable");
      await expect(page.locator(".source-panel")).toContainText("No trust decision is available");
      await expect(page.getByRole("heading", { name: app === "admin-console"
        ? "Connect to review records" : "Find your place in the registry" })).toBeVisible();
      if (app === "applicant-portal") {
        await expect(page.locator(".hero-actions a").first()).toHaveAttribute("href", "#connection-details");
        await expect(page.locator('a[href="#demo-application"]')).toHaveCount(0);
        await expect(page.locator("#demo-application")).toHaveCount(0);
        await expect(page.locator("#trust-records")).toHaveCount(0);
        await expect(page.locator(".hero-actions a")).toHaveCount(1);
        await expect(page.locator(".journey-prerequisite")).toContainText("Connect to a registry source");
      }
      await expect(page.locator(".source-time")).toHaveCount(0);
      server.setHealthAvailable(true);
      await page.locator("[data-refresh]").click();
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    } finally {
      await page.close();
      await server.close();
    }
  });
}

for (const [app, title] of [
  ["admin-console", "Registry review workspace"],
  ["applicant-portal", "Find your place in the registry"],
]) {
  test(`${app} has no automated WCAG A/AA violations in workspace, workflow, and settings views`, async ({ page, allowedLocalOrigins }) => {
    const server = await serveApp(app);
    try {
      allowedLocalOrigins.add(server.base);
      for (const width of [1440, 390]) {
        await page.setViewportSize({ width, height: 900 });
        await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
        await expect(page.locator(".source-badge")).toHaveText("Local fixture");
        for (const view of ["workspace", "workflow", "settings"]) {
          if (view === "workflow") {
            if (app === "admin-console") {
              await page.locator("#advanced-governance > summary").click();
              await expect(page.locator("#advanced-governance")).toHaveAttribute("open", "");
            } else {
              await page.locator('[data-open-workflow="issuer-request"]').click();
              await expect(page.locator("#issuer-request")).toBeVisible();
            }
          } else if (view === "settings") {
            if (width <= 760) {
              await page.locator(".mobile-task-menu > summary").click();
              await page.locator(".mobile-task-menu nav a").filter({ hasText: "Workspace settings" }).click();
            } else {
              await page.locator(".task-nav a").filter({ hasText: "Workspace settings" }).click();
            }
            await expect(page.locator(".settings-view")).toBeVisible();
          }
          await expectNoWcagViolations(page, `${app} ${view} at ${width}px`);
        }
      }
    } finally {
      await page.close();
      await server.close();
    }
  });

  test(`${app} keeps long registry data within desktop and mobile viewports`, async ({ page, allowedLocalOrigins }, testInfo) => {
    const server = await serveApp(app);
    try {
      allowedLocalOrigins.add(server.base);
      for (const width of [1440, 768, 390, 320]) {
        await page.setViewportSize({ width, height: 900 });
        await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
        await expect(page.getByRole("heading", { name: title })).toBeVisible();
        await expect.poll(() => page.locator(".brand-logo").evaluate((image) => image.naturalWidth)).toBeGreaterThan(0);
        await expect(page.locator(".brand-product-title")).toHaveText("Trust Registry");
        await expect(page.locator(".brand-product-context")).toHaveText(app === "admin-console" ? "Admin console" : "Applicant portal");
        const brandLockup = await page.evaluate(() => {
          const logo = document.querySelector(".brand-logo").getBoundingClientRect();
          const title = document.querySelector(".brand-product-title");
          const context = document.querySelector(".brand-product-context");
          const titleBox = title.getBoundingClientRect();
          const contextBox = context.getBoundingClientRect();
          return { logoRight: logo.right, titleLeft: titleBox.left, contextLeft: contextBox.left,
            titleSize: parseFloat(getComputedStyle(title).fontSize), contextSize: parseFloat(getComputedStyle(context).fontSize) };
        });
        expect(brandLockup.titleLeft).toBeGreaterThan(brandLockup.logoRight);
        expect(Math.abs(brandLockup.titleLeft - brandLockup.contextLeft)).toBeLessThan(2);
        expect(brandLockup.titleSize).toBeGreaterThan(brandLockup.contextSize);
        if (width > 760) expect(brandLockup.titleSize).toBeGreaterThanOrEqual(24);
        expect(brandLockup.contextLeft - brandLockup.logoRight).toBeLessThan(48);
        if (app === "applicant-portal") await expect(page.locator(".hero-intro > .eyebrow")).toHaveText("Applicant workspace");
        await expect(page.locator(".metrics")).toContainText("Midnight Trust Registry");
        await expect(page.locator(".source-badge")).toHaveText("Local fixture");
        await expect(page.locator(".source-panel")).toContainText("not deployed ledger evidence");
        const initialLayout = await page.evaluate(() => {
          const top = (selector) => document.querySelector(selector).getBoundingClientRect().top;
          return { brand: top(".brand-bar"), nav: top(innerWidth <= 760 ? ".mobile-task-menu" : ".task-nav"),
            hero: top(".hero"), scrollY: window.scrollY };
        });
        expect(initialLayout.scrollY).toBe(0);
        if (width <= 760) {
          expect(initialLayout.nav).toBeGreaterThanOrEqual(initialLayout.brand);
          expect(initialLayout.nav).toBeLessThan(initialLayout.hero);
          expect(initialLayout.nav).toBeLessThan(900);
        } else {
          expect(initialLayout.nav).toBeGreaterThan(initialLayout.brand);
          expect(Math.abs(initialLayout.nav - initialLayout.hero)).toBeLessThan(2);
        }
        if (app === "admin-console" && width === 1440) {
          const heroLayout = await page.evaluate(() => {
            const intro = document.querySelector(".hero > .hero-copy").getBoundingClientRect();
            const metrics = document.querySelector(".hero > .metrics").getBoundingClientRect();
            const cards = [...document.querySelectorAll(".hero > .metrics .metric")];
            return { introTop: intro.top, metricsTop: metrics.top, introRight: intro.right,
              metricsLeft: metrics.left, cardWidths: cards.map((card) => card.getBoundingClientRect().width) };
          });
          expect(Math.abs(heroLayout.introTop - heroLayout.metricsTop)).toBeLessThan(2);
          expect(heroLayout.introRight).toBeLessThan(heroLayout.metricsLeft);
          expect(heroLayout.cardWidths).toHaveLength(3);
          expect(Math.min(...heroLayout.cardWidths)).toBeGreaterThan(150);
        }
        if (app === "applicant-portal") {
          await expect(page.locator(".hero-actions a").first()).toHaveAttribute("href", "#governed-requests");
          const contentOrder = await page.evaluate(() => ({
            rolesTop: document.querySelector(".journey-picker").getBoundingClientRect().top,
            recordsTop: document.querySelector("#trust-records").getBoundingClientRect().top,
            firstContentId: document.querySelector(".content").firstElementChild.id,
          }));
          expect(contentOrder.firstContentId).toBe("governed-requests");
          expect(contentOrder.rolesTop).toBeLessThan(contentOrder.recordsTop);
          await expect(page.locator(".task-nav a").first()).toHaveAttribute("href", "#governed-requests");
          await expect(page.locator("#trust-records .lane")).toHaveCount(1);
        }
        if (app === "admin-console" && width === 390) {
          const mobileOrder = await page.evaluate(() => ({
            metricsBottom: document.querySelector(".hero > .metrics").getBoundingClientRect().bottom,
            sourceTop: document.querySelector(".hero > .source-panel").getBoundingClientRect().top,
          }));
          expect(mobileOrder.metricsBottom).toBeLessThan(mobileOrder.sourceTop);
        }
        if (process.env.TR_UI_CAPTURE === "1") {
          await page.screenshot({ path: testInfo.outputPath(`${app}-${width}.png`), fullPage: true });
        }
        const refresh = page.locator("[data-refresh]");
        await refresh.focus();
        await refresh.click();
        await expect(page.locator(".source-badge")).toHaveText("Local fixture");
        await expect(refresh).toBeFocused();
        if (width <= 760) await page.locator(".mobile-task-menu > summary").click();
        const settingsLink = width <= 760 ? page.locator(".mobile-task-menu nav a").filter({ hasText: "Workspace settings" })
          : page.locator(".task-nav a").filter({ hasText: "Workspace settings" });
        await settingsLink.click();
        await expect(page.locator(".settings-view")).toBeVisible();
        await expect(page.locator(".hero")).toBeHidden();
        await expect(page.locator(".settings-view")).toContainText("Network profile, genesis, contract");
        await expect(page.locator(".settings-view")).toContainText("Not exposed by this API response");
        await expect(page.locator(".settings-view")).not.toHaveCSS("overflow-x", "scroll");
        if (process.env.TR_UI_CAPTURE === "1") {
          await page.screenshot({ path: testInfo.outputPath(`${app}-settings-${width}.png`), fullPage: true });
        }
        await page.locator(".settings-back").click();
        await expect(page.locator(".settings-view")).toBeHidden();
        await expect(page.locator(".hero")).toBeVisible();
        const links = width <= 760 ? page.locator(".mobile-task-menu nav a") : page.locator(".task-nav a");
        expect(await page.evaluate(() => {
          const ids = [...document.querySelectorAll("[id]")].map((element) => element.id);
          return new Set(ids).size === ids.length;
        })).toBe(true);
        expect(await links.evaluateAll((elements) => elements.every((link) =>
          document.querySelector(link.getAttribute("href")) !== null))).toBe(true);
        if (width === 390) {
          await expect(links.first()).toBeHidden();
          await page.locator(".mobile-task-menu > summary").focus();
          await page.keyboard.press("Enter");
          await expect(links.first()).toBeVisible();
          expect(await links.evaluateAll((elements) => elements.every((link) =>
            link.getBoundingClientRect().height >= 44))).toBe(true);
          await links.first().click();
          await expect(page.locator(".mobile-task-menu")).not.toHaveAttribute("open", "");
        }
        if (app === "admin-console") {
          await expect(page.locator(".card")).toHaveCount(1);
          await expect(page.locator(".column")).toHaveCount(1);
          await page.locator(".card").click();
          await expect(page.locator(".record-meaning")).toContainText("not deployed ledger evidence");
          await expect(page.locator(".decision-summary time")).toContainText("20 May 2026");
          await expect(page.locator(".decision-summary time")).toHaveAttribute("datetime", "2026-05-20T00:04:00.000Z");
          await expect(page.locator(".governed-actions")).not.toHaveAttribute("open", "");
          await page.locator(".governed-actions > summary").click();
          await expect(page.locator('[data-governed-prepare="suspend"]')).toBeVisible();
          await expect(page.locator(".detail-panel")).toContainText(longDid);
          await page.locator(".technical-details > summary").click();
        } else {
          await expect(page.locator(".journey-steps li")).toHaveCount(4);
          await page.locator(".record-identifiers > summary").click();
          const recordSearch = page.locator("[data-record-search]");
          await recordSearch.fill("not-a-registry-entry");
          await expect(page.locator("[data-record-no-match]")).toBeVisible();
          await expect(page.locator("#trust-records .lane")).toBeHidden();
          await recordSearch.fill(longDid.slice(-20));
          await expect(page.locator("#trust-records .lane")).toBeVisible();
          await expect(page.locator("[data-record-count]")).toHaveText("1 of 1 active records shown");
          await recordSearch.fill("issuer");
          await expect(page.locator("[data-record-count]")).toHaveText("1 of 1 active records shown");
          if (width === 390) {
            await page.emulateMedia({ reducedMotion: "reduce" });
            await page.locator('[data-open-workflow="issuer-request"]').focus();
            await page.keyboard.press("Enter");
            await expect(page.locator("#issuer-request")).toHaveAttribute("open", "");
            await expect(page.locator("#issuer-request .request-step")).toHaveCount(3);
          }
        }
        const geometry = await page.evaluate(() => ({
          viewport: window.innerWidth,
          page: document.documentElement.scrollWidth,
          overflowing: [...document.querySelectorAll("body *")]
            .filter((element) => element.scrollWidth > element.clientWidth + 1)
            .slice(0, 12).map((element) => `${element.tagName}.${element.className}:${element.scrollWidth}/${element.clientWidth} ${element.outerHTML.slice(0, 140)}`),
        }));
        expect(geometry.page, JSON.stringify(geometry)).toBeLessThanOrEqual(geometry.viewport + 1);
        expect(geometry.overflowing).toEqual([]);
        if (width === 390) {
          await page.addStyleTag({ content: "html { font-size: 200%; }" });
          const zoomGeometry = await page.evaluate(() => ({
            page: document.documentElement.scrollWidth,
            overflowing: [...document.querySelectorAll("body *")]
              .filter((element) => element.scrollWidth > element.clientWidth + 1)
              .slice(0, 12).map((element) => `${element.tagName}.${element.className}:${element.scrollWidth}/${element.clientWidth}`),
          }));
          expect(zoomGeometry.page, JSON.stringify(zoomGeometry)).toBeLessThanOrEqual(390);
        }
      }
    } finally {
      await page.close();
      await server.close();
    }
  });
}

test("loopback demo application choices stay usable at mobile zoom", async ({ page, allowedLocalOrigins }, testInfo) => {
  const server = await serveApp("applicant-portal");
  try {
    allowedLocalOrigins.add(server.base);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(`${server.base}/?demo=1&apiBase=${encodeURIComponent(server.base)}`);
    if (process.env.TR_UI_CAPTURE === "1") {
      await page.screenshot({ path: testInfo.outputPath("demo-choices-1440.png"), fullPage: true });
    }
    await page.setViewportSize({ width: 390, height: 900 });
    const choices = page.locator("#demo-application input[name='target']");
    await expect(choices).toHaveCount(3);
    await expect(choices.first()).toBeChecked();
    await choices.nth(2).check();
    await expect(choices.nth(2)).toBeChecked();
    if (process.env.TR_UI_CAPTURE === "1") {
      await page.screenshot({ path: testInfo.outputPath("demo-choices-390.png"), fullPage: true });
    }
    await page.addStyleTag({ content: "html { font-size: 200%; }" });
    const width = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(width).toBeLessThanOrEqual(390);
  } finally {
    await server.close();
  }
});
