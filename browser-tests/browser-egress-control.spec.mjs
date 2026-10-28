import assert from "node:assert/strict";
import { createServer } from "node:http";
import { networkInterfaces } from "node:os";

import { test } from "@playwright/test";

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
    const assertNoExternalRequests = await installOfflineBrowserAudit(page.context());
    await page.goto(`http://127.0.0.1:${localPort}/start`).catch(() => {});
    assert.equal(externalHits, 0);
    assert.throws(assertNoExternalRequests, new RegExp(externalAddress.replaceAll(".", "\\."), "u"));
  } finally {
    if (local.listening) await close(local);
    await close(external);
  }
});
