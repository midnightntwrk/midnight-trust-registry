import { describe, expect, it } from "vitest";

import { createDemoSnapshot } from "@midnight-ntwrk/trust-registry-cli";

import { createTrustRegistryApiServer } from "../server.js";
import { createInMemorySource } from "../source.js";

describe("governed epoch HTTP boundary", () => {
  it("fails closed when no Compact-backed publication port is configured", async () => {
    const server = createTrustRegistryApiServer({
      source: createInMemorySource(createDemoSnapshot({ label: "epoch-port-unavailable" })),
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("TCP address unavailable");
      const response = await fetch(`http://127.0.0.1:${address.port}/v1/governed/epochs/prepare`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ label: "unavailable" }),
      });
      expect(response.status).toBe(503);
      expect((await response.json()).type).toMatch(/governed-epoch-unavailable$/u);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
