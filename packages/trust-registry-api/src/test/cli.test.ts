import { describe, expect, it } from "vitest";

import { parseTrustRegistryApiCliArgs } from "../cli.js";

describe("API CLI binding", () => {
  const localArgs = ["serve", "--local-ledger-plan", "/run/api-plan.json",
    "--local-ledger-signature", "/run/api-plan.sig",
    "--local-ledger-keyring", "/run/keyring",
    "--local-ledger-reviewer", "A".repeat(40)];

  it("requires complete local reviewer evidence and never combines local mode with demo files", () => {
    expect(parseTrustRegistryApiCliArgs(localArgs).localLedgerPlanPath).toBe("/run/api-plan.json");
    for (const args of [
      ["serve", "--local-ledger-plan", "/run/api-plan.json"],
      [...localArgs, "--snapshot", "fixture.json"],
      [...localArgs, "--workspace", "workspace.json"],
      [...localArgs, "--unsafe-demo-mutations"],
      ["serve", "--snapshot", "fixture.json", "--local-ledger-signature", "/run/api-plan.sig"],
    ]) {
      expect(() => parseTrustRegistryApiCliArgs(args)).toThrow();
    }
    expect(() => parseTrustRegistryApiCliArgs([
      ...localArgs, "--local-ledger-plan", "/run/replacement.json",
    ])).toThrow(/duplicate argument/u);
    expect(() => parseTrustRegistryApiCliArgs([
      ...localArgs, "--host", "0.0.0.0",
    ])).toThrow(/requires a loopback host/u);
  });

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
