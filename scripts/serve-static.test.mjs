import assert from "node:assert/strict";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createStaticAssetHandler } from "./serve-static.mjs";

test("composable static handler serves portal assets without escaping its root", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-static-"));
  const outside = await mkdtemp(join(tmpdir(), "tr-static-outside-"));
  const server = createServer(createStaticAssetHandler({ distDir: root, name: "static-test" }));
  try {
    await writeFile(join(root, "index.html"), "<h1>Trust Registry</h1>");
    await writeFile(join(root, "index.js"), "export const portal = true;\n");
    await writeFile(join(outside, "secret.txt"), "never served\n");
    await symlink(join(outside, "secret.txt"), join(root, "linked.txt"));
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    assert.notEqual(address, null);
    assert.notEqual(typeof address, "string");
    const base = `http://127.0.0.1:${address.port.toString()}`;
    const index = await fetch(base);
    assert.equal(index.status, 200);
    assert.match(await index.text(), /Trust Registry/u);
    const module = await fetch(`${base}/index.js`);
    assert.equal(module.status, 200);
    assert.match(module.headers.get("content-type") ?? "", /javascript/u);
    assert.equal((await fetch(`${base}/linked.txt`)).status, 403);
    assert.equal((await fetch(`${base}/missing.js`)).status, 404);
  } finally {
    if (server.listening) {
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});
