import { createServer } from "node:http";
import { resolve } from "node:path";

import { expect, test } from "@playwright/test";

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

test("a late governance receipt cannot replace another registry's board", async ({ page }) => {
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
    page.on("dialog", (dialog) => dialog.accept());
    await page.goto(`${base}/?apiBase=${encodeURIComponent(`${base}/a`)}`);
    const registryLabel = page.locator(".metrics .metric:first-child strong");
    await expect(registryLabel).toHaveText("Registry A");

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
