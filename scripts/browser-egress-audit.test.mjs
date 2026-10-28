import assert from "node:assert/strict";
import { test } from "node:test";

import { installOfflineBrowserAudit, isLocalBrowserUrl } from "../browser-tests/offline-browser-fixture.mjs";

test("browser audit accepts exact loopback origins and rejects deceptive hosts", () => {
  for (const url of ["http://127.0.0.1:4400/a", "https://localhost/a", "ws://[::1]:4400/a",
    "about:blank", "data:text/plain,local"]) {
    assert.equal(isLocalBrowserUrl(url), true, url);
  }
  for (const url of ["https://example.invalid/a", "http://localhost.example.invalid/a",
    "http://127.0.0.2/a", "file:///tmp/key", "not-a-url"]) {
    assert.equal(isLocalBrowserUrl(url), false, url);
  }
});

test("browser audit blocks external HTTP and WebSocket attempts and reports their origins", async () => {
  const handlers = {};
  const context = {
    on: (event, handler) => { handlers[event] = handler; },
    route: async (_pattern, handler) => { handlers.http = handler; },
    routeWebSocket: async (_pattern, handler) => { handlers.ws = handler; },
  };
  const assertNoExternalRequests = await installOfflineBrowserAudit(context);
  const observed = { fetched: 0, fulfilled: 0, aborted: 0, connected: 0, closed: 0 };
  const httpRoute = (url) => ({
    request: () => ({ url: () => url }),
    fetch: ({ maxRedirects }) => {
      assert.equal(maxRedirects, 0);
      observed.fetched += 1;
      return { status: () => 200 };
    },
    fulfill: ({ response }) => {
      assert.equal(response.status(), 200);
      observed.fulfilled += 1;
    },
    abort: () => { observed.aborted += 1; },
  });
  await handlers.http(httpRoute("http://127.0.0.1:4400/app"));
  assert.doesNotThrow(assertNoExternalRequests);
  await handlers.http(httpRoute("https://outside.invalid/secret?token=private"));
  await handlers.ws({
    url: () => "ws://localhost:4400/local",
    connectToServer: () => { observed.connected += 1; },
    close: () => { observed.closed += 1; },
  });
  await handlers.ws({
    url: () => "wss://outside.invalid/secret",
    connectToServer: () => { observed.connected += 1; },
    close: () => { observed.closed += 1; },
  });
  assert.deepEqual(observed, { fetched: 1, fulfilled: 1, aborted: 1, connected: 1, closed: 1 });
  assert.throws(assertNoExternalRequests, /outside\.invalid/u);
  assert.throws(assertNoExternalRequests, (error) => !error.message.includes("token=private"));
});

test("browser audit denies redirects before the browser can follow them", async () => {
  let handler;
  const context = {
    on: () => {},
    route: async (_pattern, callback) => { handler = callback; },
    routeWebSocket: async () => {},
  };
  const assertNoExternalRequests = await installOfflineBrowserAudit(context);
  let fulfilled;
  await handler({
    request: () => ({ url: () => "http://127.0.0.1:4400/start" }),
    fetch: async ({ maxRedirects }) => {
      assert.equal(maxRedirects, 0);
      return {
        status: () => 302,
        headers: () => ({ location: "https://outside.invalid/next?token=private" }),
      };
    },
    fulfill: async (options) => { fulfilled = options; },
  });
  assert.equal(fulfilled.status, 403);
  assert.throws(assertNoExternalRequests, /outside\.invalid/u);
  assert.throws(assertNoExternalRequests, (error) => !error.message.includes("token=private"));
});
