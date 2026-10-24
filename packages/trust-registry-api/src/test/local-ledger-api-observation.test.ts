import { once } from "node:events";
import type { AddressInfo } from "node:net";

import { createDemoSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import { describe, expect, it } from "vitest";

import { localApiOrigin, observeLocalApiCurrentReads } from "../local-ledger-api-observation.js";
import { createTrustRegistryApiServer } from "../server.js";
import type { TrustRegistryApiStateSource } from "../source.js";

const snapshot = createDemoSnapshot({ label: "observation-route-unit" });
const source: TrustRegistryApiStateSource = {
  mode: "local-ledger",
  async loadSnapshot() { return snapshot; },
};

describe("local API current-read observation (route-level only)", () => {
  it("compares current HTTP routes with the source and marks the result unqualified", async () => {
    const server = createTrustRegistryApiServer({ source });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      const port = (server.address() as AddressInfo).port;
      const result = await observeLocalApiCurrentReads({ source, apiOrigin: `http://127.0.0.1:${port}` });
      expect(result).toMatchObject({
        format: "tr-local-api-current-read-observation-v1",
        registryId: snapshot.registry.registryId,
        currentEpochId: snapshot.currentEpoch.epochId,
        counts: { issuer: 2, verifier: 2, auditor: 2, recognition: 2 },
        releaseQualified: false,
      });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("rejects non-loopback origins and fixture sources", async () => {
    for (const origin of ["http://localhost:4400", "http://0.0.0.0:4400",
      "https://127.0.0.1:4400", "http://127.0.0.1:4400/path"]) {
      expect(() => localApiOrigin(origin)).toThrow(/127\.0\.0\.1/u);
    }
    await expect(observeLocalApiCurrentReads({
      source: { ...source, mode: "snapshot" }, apiOrigin: "http://127.0.0.1:4400",
    })).rejects.toThrow(/signed local-ledger source/u);
  });

  it("rejects a substituted health response and a drifting source", async () => {
    const badFetch: typeof fetch = async () => new Response(JSON.stringify({
      status: "ok", sourceMode: "snapshot", registryId: snapshot.registry.registryId,
    }), { status: 200, headers: { "cache-control": "no-store" } });
    await expect(observeLocalApiCurrentReads({
      source, apiOrigin: "http://127.0.0.1:4400", fetchImpl: badFetch,
    })).rejects.toThrow(/health does not identify/u);

    let reads = 0;
    const drifting: TrustRegistryApiStateSource = {
      mode: "local-ledger",
      async loadSnapshot() {
        reads += 1;
        return reads === 1 ? snapshot : { ...snapshot, generatedAt: "2030-01-01T00:00:00Z" };
      },
    };
    const responding: typeof fetch = async (url) => {
      const path = new URL(String(url)).pathname;
      let body: unknown;
      let status = 200;
      if (path === "/health") body = { status: "ok", sourceMode: "local-ledger",
        registryId: snapshot.registry.registryId };
      else if (path === "/v1/registry") body = snapshot.registry;
      else if (path === "/v1/epochs/current") body = snapshot.currentEpoch;
      else if (path.startsWith("/v1/authorizations/")) {
        const [, , , role, id] = path.split("/");
        body = role === "issuer" || role === "verifier" || role === "auditor"
          ? snapshot[`${role}Entries`].find((entry) => entry.authorization.authorizationId === decodeURIComponent(id!))
          : undefined;
      } else if (path.startsWith("/v1/recognitions/")) {
        const id = path.split("/").at(-1);
        body = snapshot.recognitionEntries.find((entry) => entry.recognition.recognitionId === decodeURIComponent(id!));
      }
      if (body === undefined) { status = path.includes("/resolve") ? 501 : 404; body = {}; }
      return new Response(JSON.stringify(body), { status, headers: { "cache-control": "no-store" } });
    };
    await expect(observeLocalApiCurrentReads({
      source: drifting, apiOrigin: "http://127.0.0.1:4400", fetchImpl: responding,
    })).rejects.toThrow(/changed during API readback/u);
  });

  it("rejects substituted records and missing no-store policy", async () => {
    const server = createTrustRegistryApiServer({ source });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      const substituted: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (!new URL(String(url)).pathname.startsWith("/v1/authorizations/issuer/")) return response;
        return new Response(JSON.stringify({ label: "substituted" }), {
          status: 200, headers: { "cache-control": "no-store" },
        });
      };
      await expect(observeLocalApiCurrentReads({ source, apiOrigin: origin, fetchImpl: substituted }))
        .rejects.toThrow(/issuer record differs/u);
      const cacheable: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (new URL(String(url)).pathname !== "/health") return response;
        return new Response(await response.text(), { status: 200 });
      };
      await expect(observeLocalApiCurrentReads({ source, apiOrigin: origin, fetchImpl: cacheable }))
        .rejects.toThrow(/cache policy/u);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
