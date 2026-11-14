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

async function serveApp(app, { secondIssuer = false, noIssuers = false } = {}) {
  let healthAvailable = true;
  let auditorAvailable = true;
  let sourceMode = "workspace";
  let healthGate;
  const requests = [];
  const servedSummary = noIssuers ? { ...summary, issuerCounts: emptyCounts }
    : secondIssuer ? { ...summary, issuerCounts: { ...counts, active: 2 } } : summary;
  const servedIssuers = noIssuers ? [] : secondIssuer ? [issuer, { ...issuer, label: "Second demo issuer", authorization: {
    ...issuer.authorization, authorizationId: "auth:issuer:second-demo-issuer:v1" } }] : [issuer];
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
      if (healthGate !== undefined) await healthGate;
      if (!healthAvailable) response.statusCode = 503;
      response.end(JSON.stringify(healthAvailable
        ? { status: "ok", sourceMode }
        : { title: "Registry unavailable", detail: "Fixture host is offline" }));
    }
    else if (path === "/v1/registry/summary") response.end(JSON.stringify(servedSummary));
    else if (path === "/v1/authorizations/auditor" && !auditorAvailable) {
      response.statusCode = 503;
      response.end(JSON.stringify({ title: "Auditor list unavailable" }));
    }
    else response.end(JSON.stringify({ entries: path === "/v1/authorizations/issuer" ? servedIssuers : [] }));
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
    setSourceMode: (mode) => { sourceMode = mode; },
    pauseHealth: () => {
      let release;
      healthGate = new Promise((resolveGate) => { release = resolveGate; });
      return () => { healthGate = undefined; release(); };
    },
    close: async () => {
      server.closeAllConnections();
      await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
    },
  };
}

test("applicant portal treats a failed list as unavailable, then recovers on recheck", async ({ page, allowedLocalOrigins }, testInfo) => {
  const server = await serveApp("applicant-portal");
  try {
    server.setAuditorAvailable(false);
    allowedLocalOrigins.add(server.base);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
    await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    await expect(page.locator(".source-panel")).toContainText("1 list(s) unavailable; counts shown as n/a");
    const auditorLane = page.locator(".lane").filter({ has: page.getByRole("heading", { name: "Active auditors" }) });
    await expect(auditorLane).toContainText("unavailable");
    await expect(auditorLane).toContainText("Do not infer trust from this lane");
    await expect(auditorLane).not.toContainText("0 active");
    await expect(page.locator("#trust-records")).toContainText("Local demo issuer");
    await expectNoWcagViolations(page, "applicant partial list failure at 1440px");
    if (process.env.TR_UI_CAPTURE === "1") {
      await page.screenshot({ path: testInfo.outputPath("applicant-partial-list-1440.png"), fullPage: true });
    }

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

test("admin clears stale review records when one list fails, then recovers", async ({ page, allowedLocalOrigins }, testInfo) => {
  const server = await serveApp("admin-console");
  try {
    allowedLocalOrigins.add(server.base);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
    await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    await expect(page.locator(".card")).toHaveCount(1);

    server.setAuditorAvailable(false);
    await page.locator("[data-refresh]").click();
    await expect(page.locator(".source-badge")).toHaveText("Unavailable");
    await expect(page.locator("[data-refresh]")).toBeFocused();
    await expect(page.locator(".source-panel")).toContainText("No trust decision is available");
    await expect(page.getByRole("alert")).toContainText("Auditor list unavailable");
    await expect(page.locator(".card, [data-governed-prepare]")).toHaveCount(0);
    await expect(page.locator("#review-board .board"))
      .toContainText("Review records are unavailable until the connection succeeds");
    await expect(page.locator("#review-board .board")).not.toContainText("No records yet");
    await expect(page.locator("#selected-record-detail"))
      .toContainText("Recheck the connection before reviewing a record");
    await expect(page.locator("#selected-record-detail")).not.toContainText("Local demo issuer");
    await expectNoWcagViolations(page, "admin partial list failure at 1440px");
    if (process.env.TR_UI_CAPTURE === "1") {
      await page.screenshot({ path: testInfo.outputPath("admin-partial-list-1440.png"), fullPage: true });
    }

    server.setAuditorAvailable(true);
    await page.locator("[data-refresh]").click();
    await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    await expect(page.locator(".card")).toHaveCount(1);
    await expect(page.locator(".card")).toContainText("Local demo issuer");
    expect(server.requests.some((request) => request.startsWith("POST "))).toBe(false);
  } finally {
    await page.close();
    await server.close();
  }
});

test("admin describes a healthy empty fixture as empty rather than unavailable", async ({ page, allowedLocalOrigins }) => {
  const server = await serveApp("admin-console", { noIssuers: true });
  try {
    allowedLocalOrigins.add(server.base);
    await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
    await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    await expect(page.locator("#review-board .board")).toContainText("No records yet");
    await expect(page.locator("#review-board .board")).not.toContainText("unavailable");
    await expect(page.locator("#selected-record-detail"))
      .toContainText("Select a record to review its detail");
    await expectNoWcagViolations(page, "admin healthy empty fixture");
  } finally {
    await page.close();
    await server.close();
  }
});

test("applicant keeps an empty fixture distinct from an unavailable source", async ({ page, allowedLocalOrigins }) => {
  const server = await serveApp("applicant-portal", { noIssuers: true });
  try {
    allowedLocalOrigins.add(server.base);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
    await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    await expect(page.locator(".source-panel")).not.toContainText("No trust decision is available");
    await expect(page.locator("#trust-records")).not.toContainText("Local demo issuer");
    await expect(page.locator(".journey-cards")).toBeVisible();
    await expectNoWcagViolations(page, "applicant healthy empty fixture at 1440px");
    expect(server.requests.some((request) => request.startsWith("POST "))).toBe(false);
  } finally {
    await page.close();
    await server.close();
  }
});

test("applicant role cards focus one governed request without submitting it", async ({ page, allowedLocalOrigins }, testInfo) => {
  const server = await serveApp("applicant-portal");
  try {
    allowedLocalOrigins.add(server.base);
    await page.setViewportSize({ width: 390, height: 900 });
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
    await expect(page.locator(".source-badge")).toHaveText("Local fixture");

    const roles = ["issuer", "verifier", "auditor", "maintainer"];
    for (const role of roles) {
      const link = page.locator(`.journey-cards [data-open-workflow="${role}-request"]`);
      await expect(link).toHaveAttribute("aria-controls", `${role}-request`);
      await link.focus();
      await page.keyboard.press("Enter");
      await expect(page.locator(".role-workflow[open]")).toHaveCount(1);
      await expect(page.locator(`#${role}-request`)).toHaveAttribute("open", "");
      await expect(page.locator(`#${role}-request > summary`)).toBeFocused();
      await expect(link).toHaveAttribute("aria-expanded", "true");
      await expect(page.locator(`#${role}-request .step-hint`).first())
        .toContainText("Application ID tracks this submission; authorization ID names the grant");
      await expect(page.locator(`#${role}-request [data-private-host-guide]`)).toHaveCount(0);
      await expect(page.locator(`#${role}-request [data-prepare-${role}]`)).toBeEnabled();
      for (const other of roles.filter((candidate) => candidate !== role)) {
        await expect(page.locator(`.journey-cards [data-open-workflow="${other}-request"]`))
          .toHaveAttribute("aria-expanded", "false");
      }
    }

    await page.locator("#maintainer-request > summary").click();
    await expect(page.locator(".role-workflow[open]")).toHaveCount(0);
    await expect(page.locator('.journey-cards [data-open-workflow="maintainer-request"]'))
      .toHaveAttribute("aria-expanded", "false");
    await page.locator('.journey-cards [data-open-workflow="verifier-request"]').click();
    await expect(page.locator(".role-workflow[open]")).toHaveCount(1);
    await expect(page.locator("#verifier-request")).toHaveAttribute("open", "");
    await page.locator("#verifier-request > summary").focus();
    if (process.env.TR_UI_CAPTURE === "1") {
      await page.locator("#verifier-request > summary").evaluate((element) => element.scrollIntoView({ block: "start" }));
      await page.screenshot({ path: testInfo.outputPath("applicant-verifier-request-390.png") });
    }
    const refreshedSummary = page.waitForResponse((response) => response.url() === `${server.base}/v1/registry/summary`);
    await page.evaluate(() => document.querySelector("[data-refresh]").click());
    await refreshedSummary;
    await expect(page.locator("[data-refresh]")).toBeEnabled();
    await expect(page.locator("#verifier-request > summary")).toBeFocused();
    await expect(page.locator("#verifier-request")).toHaveAttribute("open", "");
    await expect(page.locator('.journey-cards [data-open-workflow="verifier-request"]'))
      .toHaveAttribute("aria-expanded", "true");
    await page.setViewportSize({ width: 320, height: 900 });
    await page.addStyleTag({ content: "html { font-size: 200%; }" });
    const requestGeometry = await page.evaluate(() => ({
      viewport: window.innerWidth,
      page: document.documentElement.scrollWidth,
      overflowing: [...document.querySelectorAll("#verifier-request *")]
        .filter((element) => !element.matches("input, textarea, select")
          && element.scrollWidth > element.clientWidth + 1)
        .slice(0, 12).map((element) => `${element.tagName}.${element.className}:${element.scrollWidth}/${element.clientWidth}`),
    }));
    expect(requestGeometry.page, JSON.stringify(requestGeometry)).toBeLessThanOrEqual(requestGeometry.viewport + 1);
    expect(requestGeometry.overflowing).toEqual([]);
    expect(server.requests.some((request) => request.startsWith("POST "))).toBe(false);
  } finally {
    await page.close();
    await server.close();
  }
});

test("applicant evidence link opens its advanced parent and remains usable after reload", async ({ page, allowedLocalOrigins }) => {
  const server = await serveApp("applicant-portal");
  try {
    allowedLocalOrigins.add(server.base);
    await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}#issuer-request`);
    await expect(page.locator("#issuer-request [data-issuer-application-form]")).toBeVisible();
    await page.locator('#issuer-request [data-open-workflow="pending-evidence"]').click();
    await expect(page).toHaveURL(/#pending-evidence$/u);
    await expect(page.locator(".advanced-tools")).toHaveAttribute("open", "");
    await expect(page.locator("#pending-evidence [data-application-registration-form]")).toBeVisible();
    await page.reload();
    await expect(page.locator(".advanced-tools")).toHaveAttribute("open", "");
    await expect(page.locator("#pending-evidence [data-application-registration-form]")).toBeVisible();
    expect(server.requests.some((request) => request.startsWith("POST "))).toBe(false);
  } finally {
    await page.close();
    await server.close();
  }
});

test("applicant explains why private signing is unavailable across origins", async ({ page, allowedLocalOrigins }) => {
  const staticHost = await serveApp("applicant-portal");
  const apiHost = await serveApp("applicant-portal");
  try {
    allowedLocalOrigins.add(staticHost.base);
    allowedLocalOrigins.add(apiHost.base);
    await page.goto(`${staticHost.base}/?apiBase=${encodeURIComponent(apiHost.base)}`);
    await page.locator('[data-open-workflow="issuer-request"]').click();
    await expect(page.locator("#issuer-request [data-private-host-guide]"))
      .toContainText("Open the portal through the same authenticated host as its API");
    await expect(page.locator("#issuer-request [data-prepare-issuer]")).toBeDisabled();
  } finally {
    await page.close();
    await staticHost.close();
    await apiHost.close();
  }
});

test("admin keyboard selection keeps the current record and detail in sync", async ({ page, allowedLocalOrigins }) => {
  const server = await serveApp("admin-console", { secondIssuer: true });
  try {
    allowedLocalOrigins.add(server.base);
    await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
    const cards = page.locator(".card");
    await expect(cards).toHaveCount(2);
    await expect(cards.first()).toHaveAttribute("aria-current", "true");

    await cards.nth(1).focus();
    await page.keyboard.press("Enter");
    await expect(cards.nth(1)).toBeFocused();
    await expect(cards.nth(1)).toHaveAttribute("aria-current", "true");
    await expect(cards.nth(1)).toHaveAttribute("aria-controls", "selected-record-detail");
    await expect(cards.first()).not.toHaveAttribute("aria-current");
    await expect(page.locator("#selected-record-detail h2")).toHaveText("Second demo issuer");
    expect(server.requests.some((request) => request.startsWith("POST "))).toBe(false);
  } finally {
    await page.close();
    await server.close();
  }
});

for (const app of ["admin-console", "applicant-portal"]) {
  test(`${app} keeps fixture shortcuts behind the loopback demo presentation flag`, async ({ page, allowedLocalOrigins }) => {
    const server = await serveApp(app);
    try {
      allowedLocalOrigins.add(server.base);
      await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      if (app === "admin-console") {
        await expect(page.locator("[data-action], #task-epoch, #task-signed-intent")).toHaveCount(0);
        await expect(page.locator("#advanced-governance")).toBeVisible();
      } else {
        await expect(page.locator("#demo-application")).toHaveCount(0);
        await expect(page.locator(".journey-cards")).toBeVisible();
      }

      await page.goto(`${server.base}/?demo=1&apiBase=${encodeURIComponent(server.base)}`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      if (app === "admin-console") {
        await expect(page.locator("[data-action]").first()).toBeAttached();
        await expect(page.locator("#task-epoch")).toBeAttached();
        await expect(page.locator("#task-signed-intent")).toBeAttached();
      } else {
        await expect(page.locator("#demo-application")).toBeAttached();
      }
      expect(server.requests.some((request) => request.startsWith("POST "))).toBe(false);
    } finally {
      await page.close();
      await server.close();
    }
  });

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
        await expect(page.locator(".journey-prerequisite")).toContainText("Submission requires an authenticated same-origin host");
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

  test(`${app} labels a read-only snapshot separately from demo data`, async ({ page, allowedLocalOrigins }) => {
    const server = await serveApp(app);
    try {
      server.setSourceMode("snapshot");
      allowedLocalOrigins.add(server.base);
      await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
      await expect(page.locator(".source-badge")).toHaveText("Snapshot");
      await expect(page.locator(".source-copy")).toContainText("Read-only registry snapshot");
      await page.locator(app === "admin-console"
        ? '.task-nav a[href="#workspace-settings"]'
        : '.task-nav a[href="#connection-details"]').click();
      await expect(page.locator(".settings-callout")).not.toContainText("fixture");
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
        await expect(page.getByRole("alert")).toContainText("Fixture host is offline");
        await expect(page.locator(".hero-actions a").first()).toHaveAttribute("href", "#connection-details");
        await expect(page.locator('a[href="#demo-application"]')).toHaveCount(0);
        await expect(page.locator("#demo-application")).toHaveCount(0);
        await expect(page.locator("#trust-records")).toHaveCount(0);
        await expect(page.locator(".hero-actions a")).toHaveCount(1);
        await expect(page.locator(".journey-prerequisite")).toContainText("Connect to a registry source");
      }
      await expectNoWcagViolations(page, `${app} unavailable source`);
      await expect(page.locator(".source-time")).toHaveCount(0);
      if (app === "applicant-portal") await page.locator(".hero-actions a").first().click();
      else await page.locator(".task-nav a").filter({ hasText: "Workspace settings" }).click();
      await expect(page.locator(".settings-callout"))
        .toContainText("No current registry source is available");
      await expect(page.locator(".settings-callout"))
        .not.toContainText("reports its local deployment plan");
      await page.locator(".settings-back").click();
      server.setHealthAvailable(true);
      await page.locator("[data-refresh]").click();
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    } finally {
      await page.close();
      await server.close();
    }
  });

  test(`${app} explains a pending source check and recovers after an offline result`, async ({ page, allowedLocalOrigins }) => {
    const server = await serveApp(app);
    let releaseHealth = () => {};
    try {
      allowedLocalOrigins.add(server.base);
      await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");

      const heldHealth = new Promise((resolve) => { releaseHealth = resolve; });
      await page.route(`${server.base}/health`, async (route) => {
        await heldHealth;
        await route.continue();
      }, { times: 1 });
      await page.locator("[data-refresh]").click();
      await expect(page.locator(".source-badge")).toHaveText("Checking");
      await expect(page.locator("[data-refresh]")).toBeDisabled();
      if (app === "admin-console") {
        await expect(page.locator(".source-panel")).toContainText("Showing last checked data while rechecking");
        await expect(page.locator(".card")).toHaveCount(1);
        await expect(page.locator("[data-governed-prepare]").first()).toBeDisabled();
        await page.locator(".task-nav a").filter({ hasText: "Workspace settings" }).click();
        await expect(page.locator(".settings-callout")).toContainText("may be stale");
        await expect(page.locator(".settings-callout")).not.toContainText("reports its local deployment plan");
        await page.locator(".settings-back").click();
      } else {
        await expect(page.locator(".source-panel")).toContainText("Records and results are hidden until the check completes");
        await expect(page.locator("#trust-records")).toHaveCount(0);
      }

      server.setHealthAvailable(false);
      releaseHealth();
      await expect(page.locator(".source-badge")).toHaveText("Unavailable");
      await expect(page.locator(".source-panel")).toContainText("No trust decision is available");
      await expect(page.locator(".card, #trust-records")).toHaveCount(0);

      server.setHealthAvailable(true);
      await page.locator("[data-refresh]").click();
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      expect(server.requests.some((request) => request.startsWith("POST "))).toBe(false);
    } finally {
      releaseHealth();
      await page.close();
      await server.close();
    }
  });
}

for (const app of ["admin-console", "applicant-portal"]) {
  test(`${app} clears the previous endpoint check time before the new host responds`, async ({ page, allowedLocalOrigins }) => {
    const first = await serveApp(app);
    const second = await serveApp(app);
    let releaseSecondHealth;
    try {
      allowedLocalOrigins.add(first.base);
      allowedLocalOrigins.add(second.base);
      await page.goto(`${first.base}/?apiBase=${encodeURIComponent(first.base)}`);
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await page.locator(".task-nav a").filter({ hasText: "Workspace settings" }).click();
      const settings = page.locator(".settings-view");
      await expect(settings).toBeVisible();
      releaseSecondHealth = second.pauseHealth();
      const form = page.locator("[data-api-base-form]");
      await form.locator("[name='apiBase']").fill(second.base);
      await form.locator("button[type='submit']").click();
      await expect(settings).toContainText("No successful check");
      releaseSecondHealth();
      releaseSecondHealth = undefined;
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    } finally {
      releaseSecondHealth?.();
      await page.close();
      await first.close();
      await second.close();
    }
  });
}

for (const app of ["admin-console", "applicant-portal"]) {
  test(`${app} does not return focus to Refresh after the user moves on`, async ({ page, allowedLocalOrigins }) => {
    const server = await serveApp(app);
    let releaseHealth;
    try {
      allowedLocalOrigins.add(server.base);
      await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
      releaseHealth = server.pauseHealth();
      const refresh = page.locator("[data-refresh]");
      await refresh.click();
      await page.locator(app === "admin-console"
        ? '.task-nav a[href="#workspace-settings"]'
        : '.task-nav a[href="#connection-details"]').focus();
      releaseHealth();
      releaseHealth = undefined;
      await expect(page.locator(".source-badge")).toHaveText("Local fixture");
      await expect(refresh).not.toBeFocused();
    } finally {
      releaseHealth?.();
      await page.close();
      await server.close();
    }
  });
}

test("applicant role links survive direct navigation and reload", async ({ page, allowedLocalOrigins }) => {
  const server = await serveApp("applicant-portal");
  try {
    allowedLocalOrigins.add(server.base);
    await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}#issuer-request`);
    await expect(page.locator("#issuer-request")).toHaveAttribute("open", "");
    await expect(page.locator("#issuer-request [data-issuer-application-form]")).toBeVisible();
    await page.locator('[data-open-workflow="verifier-request"]').click();
    await expect(page).toHaveURL(/#verifier-request$/u);
    await page.reload();
    await expect(page.locator("#verifier-request [data-verifier-application-form]")).toBeVisible();
  } finally {
    await page.close();
    await server.close();
  }
});

test("admin review board precedes advanced governance in keyboard order", async ({ page, allowedLocalOrigins }) => {
  const server = await serveApp("admin-console");
  try {
    allowedLocalOrigins.add(server.base);
    await page.goto(`${server.base}/?apiBase=${encodeURIComponent(server.base)}`);
    await expect(page.locator(".source-badge")).toHaveText("Local fixture");
    expect(await page.evaluate(() => Boolean(document.querySelector("#review-board")
      ?.compareDocumentPosition(document.querySelector("#advanced-governance")) & Node.DOCUMENT_POSITION_FOLLOWING))).toBe(true);
  } finally {
    await page.close();
    await server.close();
  }
});

for (const [app, title] of [
  ["admin-console", "Registry review workspace"],
  ["applicant-portal", "Find your place in the registry"],
]) {
  test(`${app} has no automated WCAG A/AA violations in workspace, workflow, and settings views`, async ({ page, allowedLocalOrigins }) => {
    const server = await serveApp(app);
    try {
      allowedLocalOrigins.add(server.base);
      for (const width of [1440, 768, 390]) {
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
        await page.evaluate(() => document.fonts.ready.then(() => true));
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
        if (width > 760) {
          expect(brandLockup.titleSize).toBeGreaterThanOrEqual(35);
          expect(brandLockup.contextSize).toBeGreaterThanOrEqual(14);
        }
        if (width === 320) expect(brandLockup.titleSize).toBeGreaterThanOrEqual(18);
        expect(brandLockup.contextLeft - brandLockup.logoRight).toBeLessThan(48);
        if (width === 320) {
          const headerRows = await page.evaluate(() => {
            const brand = document.querySelector(".brand-name").getBoundingClientRect();
            const menu = document.querySelector(".mobile-task-menu > summary").getBoundingClientRect();
            return Math.abs(brand.top + brand.height / 2 - menu.top - menu.height / 2);
          });
          expect(headerRows).toBeLessThan(5);
        }
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
          if (width === 768) {
            const tabletLayout = await page.evaluate(() => ({
              overviewHeight: document.querySelector(".hero-overview").getBoundingClientRect().height,
              rolesTop: document.querySelector("#governed-requests").getBoundingClientRect().top,
              metricRows: [...document.querySelectorAll(".hero-overview .metric")]
                .map((metric) => Math.round(metric.getBoundingClientRect().top)),
            }));
            expect(tabletLayout.overviewHeight, JSON.stringify(tabletLayout)).toBeLessThan(180);
            expect(tabletLayout.rolesTop, JSON.stringify(tabletLayout)).toBeLessThan(830);
            expect(tabletLayout.metricRows).toHaveLength(4);
            expect(new Set(tabletLayout.metricRows).size).toBe(2);
            expect(new Set(tabletLayout.metricRows.slice(1)).size).toBe(1);
          }
          if (width === 390) {
            const journeyLayout = await page.evaluate(() => ({
              sectionHeight: document.querySelector(".journey-picker").getBoundingClientRect().height,
              roleHeights: [...document.querySelectorAll(".journey-cards a")]
                .map((role) => role.getBoundingClientRect().height),
            }));
            expect(journeyLayout.sectionHeight).toBeLessThan(1050);
            expect(journeyLayout.roleHeights).toHaveLength(4);
            expect(Math.max(...journeyLayout.roleHeights)).toBeLessThan(95);
            await expect(page.locator(".journey-steps")).toContainText("A receipt is not approval");
            await expect(page.locator(".journey-steps")).not.toContainText("Check the decision");
            await expect(page.locator(".journey-requirements")).toContainText("authenticated host");
          }
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
        await expect(page.locator(".settings-view")).toContainText("Network profile (API report)");
        await expect(page.locator(".settings-view .settings-technical > summary")).toHaveText("Technical identifiers and plan");
        await expect(page.locator(".settings-view")).toContainText("Not exposed by this API response");
        await expect(page.locator(".settings-callout")).toContainText("does not report a deployment plan");
        await expect(page.locator(".settings-callout")).not.toContainText("reports its local deployment plan");
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
          const card = page.locator(".card");
          await card.focus();
          await page.keyboard.press("Enter");
          await expect(card).toBeFocused();
          await expect(card).toHaveAttribute("aria-current", "true");
          await expect(card).toHaveAttribute("aria-controls", "selected-record-detail");
          await expect(page.locator("#selected-record-detail")).toBeVisible();
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
          await expect(page.locator("[data-record-count]")).toHaveText("1 of 1 active record shown");
          await recordSearch.fill("issuer");
          await expect(page.locator("[data-record-count]")).toHaveText("1 of 1 active record shown");
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
        if (width === 390 || width === 320) {
          await page.addStyleTag({ content: "html { font-size: 200%; }" });
          const readZoomGeometry = async () => page.evaluate(() => ({
            page: document.documentElement.scrollWidth,
            header: (() => {
              const brand = document.querySelector(".brand-name").getBoundingClientRect();
              const menu = document.querySelector(".mobile-task-menu > summary").getBoundingClientRect();
              const bar = document.querySelector(".brand-bar").getBoundingClientRect();
              return {
                overlap: brand.left < menu.right && menu.left < brand.right
                  && brand.top < menu.bottom && menu.top < brand.bottom,
                brandInside: brand.left >= bar.left - 1 && brand.right <= bar.right + 1,
                menuInside: menu.left >= bar.left - 1 && menu.right <= bar.right + 1,
              };
            })(),
            overflowing: [...document.querySelectorAll("body *")]
              .filter((element) => !element.matches("input, textarea, select")
                && element.scrollWidth > element.clientWidth + 1)
              .slice(0, 12).map((element) => `${element.tagName}.${element.className}:${element.scrollWidth}/${element.clientWidth}`),
          }));
          const zoomGeometry = await readZoomGeometry();
          expect(zoomGeometry.header, JSON.stringify(zoomGeometry)).toEqual({
            overlap: false,
            brandInside: true,
            menuInside: true,
          });
          expect(zoomGeometry.page, JSON.stringify(zoomGeometry)).toBeLessThanOrEqual(width);
          expect(zoomGeometry.overflowing).toEqual([]);
          if (width === 320) {
            const advanced = app === "admin-console" ? ".advanced-workflows" : ".advanced-tools";
            await page.locator(`${advanced} > summary`).click();
            const advancedGeometry = await readZoomGeometry();
            expect(advancedGeometry.page, JSON.stringify(advancedGeometry)).toBeLessThanOrEqual(width);
            expect(advancedGeometry.overflowing).toEqual([]);
            await page.locator(".mobile-task-menu > summary").click();
            await page.locator(".mobile-task-menu nav a").filter({ hasText: "Workspace settings" }).click();
            await expect(page.locator(".settings-view")).toBeVisible();
            const settingsGeometry = await readZoomGeometry();
            expect(settingsGeometry.page, JSON.stringify(settingsGeometry)).toBeLessThanOrEqual(width);
            expect(settingsGeometry.overflowing).toEqual([]);
          }
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
