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
      ["serve", "--snapshot", "fixture.json", "--serve-portals"],
      ["serve", "--workspace", "workspace.json", "--serve-portals"],
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
    expect(parseTrustRegistryApiCliArgs([
      ...localArgs, "--host", "0.0.0.0", "--cluster-bind",
    ]).clusterBind).toBe(true);
    expect(parseTrustRegistryApiCliArgs([...localArgs, "--serve-portals"]).servePortals).toBe(true);
    for (const args of [
      [...localArgs, "--cluster-bind"],
      ["serve", "--snapshot", "fixture.json", "--host", "0.0.0.0", "--cluster-bind"],
      ["serve", "--workspace", "workspace.json", "--host", "0.0.0.0", "--cluster-bind"],
      [...localArgs, "--host", "::", "--cluster-bind"],
    ]) {
      expect(() => parseTrustRegistryApiCliArgs(args)).toThrow(/--cluster-bind requires/u);
    }
    expect(() => parseTrustRegistryApiCliArgs([
      ...localArgs, "--host", "0.0.0.0", "--cluster-bind", "--unsafe-demo-mutations",
    ])).toThrow(/forbids demo mutations/u);
  });

  it("preflights only the complete signed local plan without listener options", () => {
    const preflight = ["check-local-ledger-plan", ...localArgs.slice(1)];
    expect(parseTrustRegistryApiCliArgs(preflight).command).toBe("check-local-ledger-plan");
    for (const args of [
      preflight.slice(0, -2),
      [...preflight, "--host", "0.0.0.0"],
      [...preflight, "--port", "4400"],
      [...preflight, "--cluster-bind"],
      [...preflight, "--serve-portals"],
      [...preflight, "--unsafe-demo-mutations"],
      ["check-local-ledger-plan", "--snapshot", "fixture.json"],
    ]) {
      expect(() => parseTrustRegistryApiCliArgs(args)).toThrow();
    }
  });

  it("observes only a signed local plan through an explicit loopback API origin", () => {
    const observation = ["observe-local-ledger-api", ...localArgs.slice(1),
      "--api-origin", "http://127.0.0.1:4400"];
    expect(parseTrustRegistryApiCliArgs(observation).apiOrigin).toBe("http://127.0.0.1:4400");
    for (const args of [
      observation.slice(0, -2),
      [...observation, "--host", "127.0.0.1"],
      [...observation, "--port", "4400"],
      [...observation, "--serve-portals"],
      [...observation, "--unsafe-demo-mutations"],
      ["observe-local-ledger-api", "--snapshot", "fixture.json", "--api-origin", "http://127.0.0.1:4400"],
      [...observation.slice(0, -1), "http://localhost:4400"],
      [...observation.slice(0, -1), "https://127.0.0.1:4400"],
      [...observation.slice(0, -1), "http://127.0.0.1:4400/path"],
    ]) {
      expect(() => parseTrustRegistryApiCliArgs(args)).toThrow();
    }
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

  it("keeps read-only fixture sources on loopback too", () => {
    for (const source of [["--snapshot", "fixture.json"], ["--workspace", "workspace.json"]]) {
      for (const host of ["0.0.0.0", "::", "192.0.2.1", "registry.example", "localhost"]) {
        expect(() => parseTrustRegistryApiCliArgs([
          "serve", ...source, "--host", host,
        ])).toThrow(/Fixture-backed API modes require a loopback host/u);
      }
      for (const host of ["127.0.0.1", "::1"]) {
        expect(parseTrustRegistryApiCliArgs(["serve", ...source, "--host", host]).host).toBe(host);
      }
    }
  });
});
