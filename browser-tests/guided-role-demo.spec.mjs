import { createServer } from "node:http";
import { resolve } from "node:path";

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "./offline-browser-fixture.mjs";
import { createStaticAssetHandler } from "../scripts/serve-static.mjs";

const registryId = "registry:guided-role-demo:trusted";
const registryLabel = "guided-role-demo";
const emptyCounts = () => ({
  proposed: 0, authorized: 0, active: 0, suspended: 0,
  revoked: 0, superseded: 0, archived: 0,
});

for (const target of ["issuer", "verifier", "auditor"]) {
for (const decision of ["approve", "reject"]) {
test(`${target} request needs three distinct demo votes to ${decision}`, async ({ page, allowedLocalOrigins }) => {
  const staticAssets = createStaticAssetHandler({
    distDir: resolve("packages/trust-registry-admin-console/dist"), name: "guided-demo",
  });
  const label = `Guided ${target}`;
  const id = `${target}:guided-demo:v1`;
  let status;
  const transitions = [];
  const entry = {
    label,
    authorization: {
      authorizationId: id, registryId, role: target,
      subjectDid: "did:midnight:undeployed:issuer",
      resourceType: target === "issuer" ? "schema" : "request-profile",
      resourceId: `tr:${target === "issuer" ? "issuer" : "request"}-resource:v1:${"a".repeat(64)}`,
      policyId: "policy:guided", trustLevel: "approved", proposedAt: "2026-05-20T00:00:00Z",
    },
    evidence: { epoch: { epochId: "epoch:guided:1", stateRoot: "0xroot" } },
  };
  const recognition = {
    label: "Unrelated recognition",
    recognition: {
      recognitionId: "recognition:unrelated:v1", registryId, status: "proposed",
      recognizedAuthorityDid: "did:midnight:undeployed:authority",
      recognizedRegistryId: "registry:external:trusted",
      scope: { resourceType: "schema", resourceId: "schema:unrelated" },
      trustLevel: "approved", policyId: "policy:guided", proposedAt: "2026-05-20T00:00:00Z",
    },
  };
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (path === "/demo.html" || path.endsWith(".js") || path === "/demo.css"
      || path === "/brand.css" || path === "/midnight-logo.svg"
      || path.startsWith("/fonts/")) {
      await staticAssets(request, response);
      return;
    }
    response.setHeader("content-type", "application/json");
    if (path === "/health") {
      response.end(JSON.stringify({ status: "ok", sourceMode: "workspace", registryId }));
      return;
    }
    if (path === "/v1/registry/summary") {
      const issuerCounts = emptyCounts();
      if (target === "issuer" && status !== undefined) issuerCounts[status] = 1;
      const verifierCounts = emptyCounts();
      if (target === "verifier" && status !== undefined) verifierCounts[status] = 1;
      const auditorCounts = emptyCounts();
      if (target === "auditor" && status !== undefined) auditorCounts[status] = 1;
      response.end(JSON.stringify({
        registryId, registryLabel,
        registryDid: "did:midnight:undeployed:registry", policyId: "policy:guided",
        currentEpochId: "epoch:guided:1", epochCount: 1,
        issuerCounts, verifierCounts, auditorCounts,
        recognitionCounts: emptyCounts(),
      }));
      return;
    }
    if (path === "/v1/applications" && request.method === "POST") {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const submitted = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (submitted.target !== target || submitted.label !== label || status !== undefined) {
        response.statusCode = 409;
        response.end(JSON.stringify({ title: "unexpected application" }));
        return;
      }
      status = "proposed";
      entry.authorization.status = status;
      response.statusCode = 201;
      response.end(JSON.stringify({ recordKind: "authorization",
        operation: { operation: "submit", target }, entry }));
      return;
    }
    if (path.startsWith(`/v1/applications/${target}/`) && request.method === "POST") {
      const action = path.slice(path.lastIndexOf("/") + 1);
      transitions.push(action);
      if (!path.includes(encodeURIComponent(id))
        || !((action === "approve" && status === "proposed")
          || (action === "archive" && status === "proposed")
          || (action === "activate" && status === "authorized"))) {
        response.statusCode = 409;
        response.end(JSON.stringify({ title: "unexpected transition" }));
        return;
      }
      status = action === "approve" ? "authorized" : action === "archive" ? "archived" : "active";
      entry.authorization.status = status;
      response.end(JSON.stringify({ recordKind: "authorization",
        operation: { operation: action, target }, entry }));
      return;
    }
    if (path === `/v1/authorizations/${target}`) {
      response.end(JSON.stringify({ entries: status === undefined ? [] : [entry] }));
      return;
    }
    if (path === "/v1/recognitions") {
      response.end(JSON.stringify({ entries: [recognition] }));
      return;
    }
    if (path === "/v1/authorizations/issuer" || path === "/v1/authorizations/verifier" || path === "/v1/authorizations/auditor") {
      response.end(JSON.stringify({ entries: [] }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ title: "not found" }));
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected TCP address");
  const base = `http://127.0.0.1:${address.port}`;
  allowedLocalOrigins.add(base);
  page.on("dialog", (dialog) => dialog.accept());
  try {
    await page.goto(`${base}/demo.html?apiBase=${encodeURIComponent(base)}`);
    await expect(page.getByRole("heading", { name: "Explore every role, one step at a time." })).toBeVisible();
    await expect(page.getByText("Local fixture connected")).toBeVisible();
    await expect(page.getByText("Unrelated recognition")).toHaveCount(0);
    if (decision === "approve" && target === "issuer") {
      const accessibility = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
      expect(accessibility.violations).toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    }
    await page.getByRole("navigation", { name: "Demo roles" }).getByRole("link", { name: `${target[0].toUpperCase()}${target.slice(1)} #1`, exact: true }).click();
    await page.getByLabel("Display name").fill(label);
    await page.getByRole("button", { name: "Send demo request" }).click();
    await expect(page.getByText("Waiting for committee demo votes.")).toBeVisible();
    for (const stage of decision === "approve" ? ["authorization", "activation"] : ["archive"]) {
      for (let number = 1; number <= 3; number++) {
        if (number === 1 && stage === (decision === "approve" ? "authorization" : "archive")) {
          await page.getByRole("link", { name: "Switch to Maintainer #1" }).click();
        } else if (number === 1) {
          await page.getByRole("navigation", { name: "Demo roles" }).locator('[data-role="maintainer-1"]').click();
        } else {
          await page.getByRole("link", { name: `Continue as Maintainer #${number}` }).click();
        }
        await expect(page.getByRole("heading", { name: "Your review inbox" })).toBeVisible();
        await expect(page.getByText("Unrelated recognition")).toHaveCount(0);
        await expect(page.getByText("1 open", { exact: true })).toBeVisible();
        await page.getByRole("button", { name: `${decision === "approve" ? "Approve" : "Reject"} in demo` }).click();
        await expect(page.getByText(`Maintainer #${number} recorded ${decision === "approve" ? "an" : "a"} ${decision} demo vote.`, { exact: false })).toBeVisible();
        if (number === 2) {
          await expect(page.getByRole("button", { name: `Apply ${stage} to demo` })).toHaveCount(0);
          expect(transitions).toHaveLength(stage === "activation" ? 1 : 0);
        }
      }
      await page.getByRole("button", { name: `Apply ${stage} to demo` }).click();
      if (stage === "authorization") {
        await expect(page.getByText("A new activation vote is now required.", { exact: false })).toBeVisible();
      }
    }
    await page.getByRole("link", { name: "View applicant result" }).click();
    await expect(page.getByText(decision === "approve" ? "Active in fixture only, not on chain." : "This record is no longer active.")).toBeVisible();
    expect(transitions).toEqual(decision === "approve" ? ["approve", "activate"] : ["archive"]);
  } finally {
    await page.close();
    server.closeAllConnections();
    await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
  }
});
}
}

for (const { name, sourceMode, sourceRegistryId, sourceLabel } of [
  { name: "snapshot", sourceMode: "snapshot", sourceRegistryId: registryId, sourceLabel: registryLabel },
  { name: "memory fixture", sourceMode: "memory", sourceRegistryId: registryId, sourceLabel: registryLabel },
  { name: "other mutable workspace", sourceMode: "workspace", sourceRegistryId: "registry:midnight:trusted", sourceLabel: "midnight" },
  { name: "mismatched workspace label", sourceMode: "workspace", sourceRegistryId: registryId, sourceLabel: "midnight" },
]) {
test(`${name} cannot submit guided demo applications`, async ({ page, allowedLocalOrigins }) => {
  const staticAssets = createStaticAssetHandler({
    distDir: resolve("packages/trust-registry-admin-console/dist"), name: "guided-demo",
  });
  let mutations = 0;
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (path === "/demo.html" || path.endsWith(".js") || path === "/demo.css"
      || path === "/brand.css" || path === "/midnight-logo.svg" || path.startsWith("/fonts/")) {
      await staticAssets(request, response);
      return;
    }
    response.setHeader("content-type", "application/json");
    if (request.method === "POST") mutations++;
    if (path === "/health") {
      response.end(JSON.stringify({ status: "ok", sourceMode, registryId: sourceRegistryId }));
    } else if (path === "/v1/registry/summary") {
      response.end(JSON.stringify({
        registryId: sourceRegistryId, registryLabel: sourceLabel,
        registryDid: "did:midnight:undeployed:registry",
        policyId: "policy:guided", currentEpochId: "epoch:guided:1", epochCount: 1,
        issuerCounts: emptyCounts(), verifierCounts: emptyCounts(), auditorCounts: emptyCounts(),
        recognitionCounts: emptyCounts(),
      }));
    } else if (path === "/v1/authorizations/issuer" && sourceMode === "workspace") {
      response.end(JSON.stringify({ entries: [{
        label: "Other workspace record",
        authorization: {
          authorizationId: "auth:other:v1", registryId: sourceRegistryId, role: "issuer",
          status: "proposed", subjectDid: "did:midnight:undeployed:other",
          resourceType: "schema", resourceId: "schema:other",
          trustLevel: "approved", policyId: "policy:guided", proposedAt: "2026-05-20T00:00:00Z",
        },
        evidence: { epoch: { epochId: "epoch:guided:1", stateRoot: "0xroot" } },
      }] }));
    } else if (path.startsWith("/v1/authorizations/") || path === "/v1/recognitions") {
      response.end(JSON.stringify({ entries: [] }));
    } else {
      response.statusCode = 404;
      response.end(JSON.stringify({ title: "not found" }));
    }
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected TCP address");
  const base = `http://127.0.0.1:${address.port}`;
  allowedLocalOrigins.add(base);
  try {
    await page.goto(`${base}/demo.html?apiBase=${encodeURIComponent(base)}`);
    await page.getByRole("navigation", { name: "Demo roles" }).getByRole("link", { name: "Issuer #1" }).click();
    await expect(page.getByText("This API is not the dedicated guided demo workspace.", { exact: false })).toBeVisible();
    await expect(page.getByText("Other workspace record")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Send demo request" })).toBeDisabled();
    expect(mutations).toBe(0);
  } finally {
    await page.close();
    server.closeAllConnections();
    await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
  }
});
}

test("unknown API status fails closed before HTML rendering", async ({ page, allowedLocalOrigins }) => {
  const staticAssets = createStaticAssetHandler({
    distDir: resolve("packages/trust-registry-admin-console/dist"), name: "guided-demo",
  });
  let mutations = 0;
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (path === "/demo.html" || path.endsWith(".js") || path === "/demo.css"
      || path === "/brand.css" || path === "/midnight-logo.svg" || path.startsWith("/fonts/")) {
      await staticAssets(request, response);
      return;
    }
    response.setHeader("content-type", "application/json");
    if (request.method === "POST") mutations++;
    if (path === "/health") {
      response.end(JSON.stringify({ status: "ok", sourceMode: "workspace", registryId }));
    } else if (path === "/v1/registry/summary") {
      response.end(JSON.stringify({
        registryId, registryLabel, registryDid: "did:midnight:undeployed:registry",
        policyId: "policy:guided", currentEpochId: "epoch:guided:1", epochCount: 1,
        issuerCounts: emptyCounts(), verifierCounts: emptyCounts(), auditorCounts: emptyCounts(),
        recognitionCounts: emptyCounts(),
      }));
    } else if (path === "/v1/authorizations/issuer") {
      response.end(JSON.stringify({ entries: [{
        label: "Hostile fixture",
        authorization: {
          authorizationId: "auth:hostile:v1", registryId, role: "issuer",
          status: 'proposed"><img data-hostile src=x>', subjectDid: "did:midnight:undeployed:issuer",
          resourceType: "schema", resourceId: "schema:hostile",
          trustLevel: "approved", policyId: "policy:guided", proposedAt: "2026-05-20T00:00:00Z",
        },
        evidence: { epoch: { epochId: "epoch:guided:1", stateRoot: "0xroot" } },
      }] }));
    } else if (path.startsWith("/v1/authorizations/") || path === "/v1/recognitions") {
      response.end(JSON.stringify({ entries: [] }));
    } else {
      response.statusCode = 404;
      response.end(JSON.stringify({ title: "not found" }));
    }
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected TCP address");
  const base = `http://127.0.0.1:${address.port}`;
  allowedLocalOrigins.add(base);
  try {
    await page.goto(`${base}/demo.html?apiBase=${encodeURIComponent(base)}`);
    await expect(page.getByText("The guided demo API returned an unknown record status.")).toBeVisible();
    await expect(page.locator("[data-hostile]")).toHaveCount(0);
    await page.getByRole("navigation", { name: "Demo roles" }).getByRole("link", { name: "Issuer #1" }).click();
    await expect(page.getByRole("button", { name: "Send demo request" })).toBeDisabled();
    expect(mutations).toBe(0);
  } finally {
    await page.close();
    server.closeAllConnections();
    await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
  }
});

test("hostile API text and identifiers stay inert in the guided view", async ({ page, allowedLocalOrigins }) => {
  const staticAssets = createStaticAssetHandler({
    distDir: resolve("packages/trust-registry-admin-console/dist"), name: "guided-demo",
  });
  const label = `Issuer & '<img data-hostile src=x onerror="window.__mtrExecuted=1">`;
  const id = `auth:fixture" autofocus onfocus="window.__mtrExecuted=1`;
  const errorText = `API failed: <svg data-hostile onload="window.__mtrExecuted=1"> & 'quoted'`;
  let failHealth = false;
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (path === "/demo.html" || path.endsWith(".js") || path === "/demo.css"
      || path === "/brand.css" || path === "/midnight-logo.svg" || path.startsWith("/fonts/")) {
      await staticAssets(request, response);
      return;
    }
    response.setHeader("content-type", "application/json");
    if (path === "/health") {
      if (failHealth) {
        response.statusCode = 500;
        response.end(JSON.stringify({ detail: errorText }));
      } else response.end(JSON.stringify({ status: "ok", sourceMode: "workspace", registryId }));
    } else if (path === "/v1/registry/summary") {
      response.end(JSON.stringify({
        registryId, registryLabel, registryDid: "did:midnight:undeployed:registry",
        policyId: "policy:guided", currentEpochId: "epoch:guided:1", epochCount: 1,
        issuerCounts: emptyCounts(), verifierCounts: emptyCounts(), auditorCounts: emptyCounts(),
        recognitionCounts: emptyCounts(),
      }));
    } else if (path === "/v1/applications" && request.method === "POST") {
      response.statusCode = 201;
      response.end(JSON.stringify({ recordKind: "authorization", entry: { authorization: { authorizationId: id } } }));
    } else if (path === "/v1/authorizations/issuer") {
      response.end(JSON.stringify({ entries: [{
        label,
        authorization: {
          authorizationId: id, registryId, role: "issuer", status: "proposed",
          subjectDid: "did:midnight:undeployed:issuer", resourceType: "schema",
          resourceId: "schema:fixture", trustLevel: "approved", policyId: "policy:guided",
          proposedAt: "2026-05-20T00:00:00Z",
        },
        evidence: { epoch: { epochId: "epoch:guided:1", stateRoot: "0xroot" } },
      }] }));
    } else if (path.startsWith("/v1/authorizations/") || path === "/v1/recognitions") {
      response.end(JSON.stringify({ entries: [] }));
    } else {
      response.statusCode = 404;
      response.end(JSON.stringify({ title: "not found" }));
    }
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected TCP address");
  const base = `http://127.0.0.1:${address.port}`;
  allowedLocalOrigins.add(base);
  try {
    await page.goto(`${base}/demo.html?apiBase=${encodeURIComponent(base)}#issuer`);
    await expect(page.getByText(label, { exact: true })).toBeVisible();
    await page.getByLabel("Display name").fill(label);
    await page.getByRole("button", { name: "Send demo request" }).click();
    await expect(page.locator('.demo-alert.success[role="status"]')).toContainText(label);
    expect(await page.locator("[data-hostile], [onerror]").count()).toBe(0);
    await page.getByRole("link", { name: "Switch to Maintainer #1" }).click();
    await expect(page.locator("[data-select-card]")).toHaveAttribute("data-select-card", `issuer:${id}`);
    await expect(page.locator(".demo-review code")).toHaveText(id);
    expect(await page.locator("[data-hostile], [autofocus], [onfocus], [onerror], [onload]").count()).toBe(0);
    expect(await page.evaluate(() => window.__mtrExecuted)).toBeUndefined();

    failHealth = true;
    await page.getByRole("button", { name: "Refresh records" }).click();
    await expect(page.getByRole("alert").filter({ hasText: errorText })).toBeVisible();
    expect(await page.locator("[data-hostile], [onload]").count()).toBe(0);
    expect(await page.evaluate(() => window.__mtrExecuted)).toBeUndefined();
  } finally {
    await page.close();
    server.closeAllConnections();
    await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
  }
});
