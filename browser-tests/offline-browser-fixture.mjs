import assert from "node:assert/strict";

import { expect, test as base } from "@playwright/test";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
const NETWORK_PROTOCOLS = new Set(["http:", "https:", "ws:", "wss:"]);
const LOCAL_PROTOCOLS = new Set(["about:", "blob:", "data:"]);

export function isLocalBrowserUrl(value, allowedOrigins = new Set()) {
  try {
    const url = new URL(value);
    return LOCAL_PROTOCOLS.has(url.protocol)
      || (NETWORK_PROTOCOLS.has(url.protocol) && LOOPBACK_HOSTS.has(url.hostname)
        && allowedOrigins.has(url.origin));
  } catch {
    return false;
  }
}

const requestOrigin = (value) => {
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}`;
  } catch {
    return "invalid-url";
  }
};

export async function installOfflineBrowserAudit(context, allowedOrigins = new Set()) {
  const externalOrigins = new Set();
  const record = (url) => {
    if (!isLocalBrowserUrl(url, allowedOrigins)) externalOrigins.add(requestOrigin(url));
  };
  context.on("request", (request) => record(request.url()));
  await context.route("**/*", async (route) => {
    const url = route.request().url();
    if (isLocalBrowserUrl(url, allowedOrigins)) {
      const response = await route.fetch({ maxRedirects: 0 });
      if (response.status() >= 300 && response.status() < 400) {
        const location = response.headers().location;
        if (location) record(new URL(location, url).href);
        return route.fulfill({ status: 403, body: "Fixture browser redirects are disabled" });
      }
      return route.fulfill({ response });
    }
    record(url);
    return route.abort("blockedbyclient");
  });
  await context.routeWebSocket("**/*", (route) => {
    const url = route.url();
    if (isLocalBrowserUrl(url, allowedOrigins)) return route.connectToServer();
    record(url);
    return route.close();
  });
  return () => assert.deepEqual([...externalOrigins], [],
    "Fixture browser attempted external network access");
}

export { expect };
export const test = base.extend({
  allowedLocalOrigins: async ({}, use) => { await use(new Set()); },
  page: async ({ page, allowedLocalOrigins }, use) => {
    const assertNoExternalRequests = await installOfflineBrowserAudit(page.context(), allowedLocalOrigins);
    await use(page);
    assertNoExternalRequests();
  },
});
