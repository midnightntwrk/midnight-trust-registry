import assert from "node:assert/strict";
import { createConnection, createServer } from "node:net";
import test from "node:test";

import { startInstallRelay } from "../deploy/standalone/local-install-relay.mjs";

const close = (server) => new Promise((resolve) => server.close(resolve));

test("the bundled Node relay forwards raw installation traffic", async () => {
  const upstream = createServer((socket) => socket.on("data", (data) => socket.write(data)));
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const [relay] = await startInstallRelay([{ listenPort: 0, host: "127.0.0.1",
    targetPort: upstream.address().port }], "127.0.0.1");
  let client;
  try {
    const reply = await new Promise((resolve, reject) => {
      client = createConnection({ host: "127.0.0.1", port: relay.address().port });
      client.setTimeout(3000, () => reject(new Error("Installation relay timed out")));
      client.once("error", reject);
      client.once("connect", () => client.write("local-ledger-readback"));
      client.once("data", (data) => resolve(data.toString("utf8")));
    });
    assert.equal(reply, "local-ledger-readback");
  } finally {
    client?.destroy();
    await close(relay);
    await close(upstream);
  }
});

test("the relay preserves a response after the client half-closes", async () => {
  const upstream = createServer({ allowHalfOpen: true }, (socket) => {
    socket.resume();
    socket.once("end", () => socket.end("readback-complete"));
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const [relay] = await startInstallRelay([{ listenPort: 0, host: "127.0.0.1",
    targetPort: upstream.address().port }], "127.0.0.1");
  let client;
  try {
    const reply = await new Promise((resolve, reject) => {
      client = createConnection({ host: "127.0.0.1", port: relay.address().port,
        allowHalfOpen: true });
      client.setTimeout(3000, () => reject(new Error("Installation relay timed out")));
      client.once("error", reject);
      client.once("connect", () => client.end("readback-request"));
      client.once("data", (data) => resolve(data.toString("utf8")));
    });
    assert.equal(reply, "readback-complete");
  } finally {
    client?.destroy();
    await close(relay);
    await close(upstream);
  }
});
