import assert from "node:assert/strict";
import { createServer } from "node:http";
import { networkInterfaces } from "node:os";

import { expect, test } from "@playwright/test";

import { installOfflineBrowserAudit } from "./offline-browser-fixture.mjs";

const listen = (server, host) => new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, host, () => {
    server.off("error", reject);
    resolve(server.address().port);
  });
});

const close = (server) => new Promise((resolve, reject) => {
  server.closeAllConnections();
  server.close((error) => error ? reject(error) : resolve());
});

test("loopback redirect cannot reach a non-allowlisted listener", async ({ page }) => {
  const externalAddress = Object.values(networkInterfaces()).flat()
    .find((address) => address?.family === "IPv4" && !address.internal)?.address;
  test.skip(!externalAddress, "The live redirect probe requires a non-loopback IPv4 interface");
  let externalHits = 0;
  const external = createServer((_request, response) => {
    externalHits += 1;
    response.end("unexpected external request");
  });
  const externalPort = await listen(external, "0.0.0.0");
  const local = createServer((_request, response) => {
    response.writeHead(302, { location: `http://${externalAddress}:${externalPort}/redirected` });
    response.end();
  });
  try {
    const localPort = await listen(local, "127.0.0.1");
    const preflight = await fetch(`http://${externalAddress}:${externalPort}/preflight`);
    assert.equal(preflight.status, 200);
    externalHits = 0;
    const assertNoExternalRequests = await installOfflineBrowserAudit(
      page.context(), new Set([`http://127.0.0.1:${localPort}`]));
    await page.goto(`http://127.0.0.1:${localPort}/start`).catch(() => {});
    assert.equal(externalHits, 0);
    assert.throws(assertNoExternalRequests, new RegExp(externalAddress.replaceAll(".", "\\."), "u"));
  } finally {
    if (local.listening) await close(local);
    await close(external);
  }
});

test("non-loopback WebSocket cannot reach a reachable listener", async ({ page }) => {
  const externalAddress = Object.values(networkInterfaces()).flat()
    .find((address) => address?.family === "IPv4" && !address.internal)?.address;
  test.skip(!externalAddress, "The live WebSocket probe requires a non-loopback IPv4 interface");
  let upgrades = 0;
  const external = createServer((_request, response) => response.end("reachable"));
  external.on("upgrade", (_request, socket) => {
    upgrades += 1;
    socket.destroy();
  });
  try {
    const port = await listen(external, "0.0.0.0");
    assert.equal((await fetch(`http://${externalAddress}:${port}/preflight`)).status, 200);
    const assertNoExternalRequests = await installOfflineBrowserAudit(page.context());
    await page.evaluate((url) => { new WebSocket(url); }, `ws://${externalAddress}:${port}/probe`);
    await expect.poll(() => {
      try {
        assertNoExternalRequests();
        return false;
      } catch {
        return true;
      }
    }, { timeout: 5000 }).toBe(true);
    assert.equal(upgrades, 0);
    assert.throws(assertNoExternalRequests, new RegExp(externalAddress.replaceAll(".", "\\."), "u"));
  } finally {
    await close(external);
  }
});
