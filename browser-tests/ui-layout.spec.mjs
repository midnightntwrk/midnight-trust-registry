import { createServer } from "node:http";
import { resolve } from "node:path";

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
    close: async () => {
      server.closeAllConnections();
      await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
    },
  };
}

for (const app of ["admin-console", "applicant-portal"]) {
  test(`${app} switches editable development endpoints without widening private access`, async ({ page, allowedLocalOrigins }) => {
    const first = await serveApp(app);
    const second = await serveApp(app);
    try {
      allowedLocalOrigins.add(first.base);
      allowedLocalOrigins.add(second.base);
      await page.goto(`${first.base}/?apiBase=${encodeURIComponent(first.base)}`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      const firstReads = first.requests.length;
      const form = page.locator("[data-api-base-form]");
      await expect(form.locator("[name='apiBase']")).toBeEnabled();
      await form.locator("[name='apiBase']").fill(second.base);
      await form.locator("button[type='submit']").click();
      await expect(form.locator("[name='apiBase']")).toHaveValue(second.base);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await page.locator(".workspace-settings > summary").click();
      await expect(page.locator(".workspace-settings")).toContainText(`${second.base} (local development setting)`);
      expect(second.requests).toContain("GET /health");
      expect(second.requests).toContain("GET /v1/registry/summary");
      expect(first.requests).toHaveLength(firstReads);
      if (app === "applicant-portal") {
        await page.locator('[data-workflow="Recover external recognition"] > summary').click();
        await expect(page.locator("[data-recognition-challenge]")).toBeDisabled();
        await expect(page.locator(".journey-prerequisite")).toContainText("cannot submit them");
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

  test(`${app} locks the packaged endpoint to its same-origin host`, async ({ page, allowedLocalOrigins }) => {
    const server = await serveApp(app);
    try {
      allowedLocalOrigins.add(server.base);
      await page.goto(`${server.base}${server.packagedPath}?apiBase=https://outside.example`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await expect(page.locator("[data-api-base-form] [name='apiBase']")).toHaveValue(server.base);
      await expect(page.locator("[data-api-base-form] [name='apiBase']")).toBeDisabled();
      await expect(page.locator("[data-api-base-form] button[type='submit']")).toBeDisabled();
      await page.locator(".workspace-settings > summary").click();
      await expect(page.locator(".workspace-settings")).toContainText("managed by this host");
      await expect(page.locator(".workspace-settings")).not.toContainText("outside.example");
      if (app === "applicant-portal") {
        await expect(page.locator(".workspace-settings"))
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
  ["admin-console", "Review trust records"],
  ["applicant-portal", "Join the trust registry"],
]) {
  test(`${app} keeps long registry data within desktop and mobile viewports`, async ({ page, allowedLocalOrigins }, testInfo) => {
    const server = await serveApp(app);
    try {
      allowedLocalOrigins.add(server.base);
      for (const width of [1440, 768, 390]) {
        await page.setViewportSize({ width, height: 900 });
        await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
        await expect(page.getByRole("heading", { name: title })).toBeVisible();
        await expect.poll(() => page.locator(".brand-logo").evaluate((image) => image.naturalWidth)).toBeGreaterThan(0);
        await expect(page.locator(".metrics")).toContainText("Midnight Trust Registry");
        await expect(page.locator(".source-badge")).toHaveText("Local fixture");
        await expect(page.locator(".source-panel")).toContainText("not deployed ledger evidence");
        const refresh = page.locator("[data-refresh]");
        await refresh.focus();
        await refresh.click();
        await expect(page.locator(".source-badge")).toHaveText("Local fixture");
        await expect(refresh).toBeFocused();
        await page.locator(".workspace-settings > summary").click();
        await expect(page.locator(".workspace-settings")).toHaveAttribute("open", "");
        await expect(page.locator(".workspace-settings")).toContainText("Network profile, genesis, contract");
        await expect(page.locator(".workspace-settings")).toContainText("Not exposed by this API response");
        expect(await page.locator(".task-nav a").evaluateAll((links) => links.every((link) =>
          document.querySelector(link.getAttribute("href")) !== null))).toBe(true);
        if (width === 390) {
          expect(await page.locator(".task-nav a").evaluateAll((links) => links.every((link) =>
            link.getBoundingClientRect().height >= 44))).toBe(true);
        }
        if (app === "admin-console") {
          await expect(page.locator(".card")).toHaveCount(1);
          await page.locator(".card").click();
          await expect(page.locator(".detail-panel")).toContainText(longDid);
          await page.locator(".technical-details > summary").click();
        } else {
          await page.locator(".record-identifiers > summary").click();
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
        if (process.env.TR_UI_CAPTURE === "1" && width !== 768) {
          await page.screenshot({ path: testInfo.outputPath(`${app}-${width}.png`), fullPage: true });
        }
      }
    } finally {
      await page.close();
      await server.close();
    }
  });
}
