import { describe, expect, it } from "vitest";

import { parseTrustRegistryApiCliArgs } from "../cli.js";

describe("API CLI binding", () => {
  it("refuses public demo mutation listeners", () => {
    for (const host of ["0.0.0.0", "::", "192.0.2.1", "registry.example", "localhost"]) {
      expect(() => parseTrustRegistryApiCliArgs([
        "serve", "--workspace", "workspace.json", "--host", host, "--unsafe-demo-mutations",
      ])).toThrow(/requires a loopback host/u);
    }
    for (const host of ["127.0.0.1", "::1"]) {
      expect(parseTrustRegistryApiCliArgs([
        "serve", "--workspace", "workspace.json", "--host", host, "--unsafe-demo-mutations",
      ]).host).toBe(host);
    }
  });
});
