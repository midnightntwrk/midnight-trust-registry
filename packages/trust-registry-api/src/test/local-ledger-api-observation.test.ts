import { once } from "node:events";
import type { AddressInfo } from "node:net";

import { buildSnapshotSummary, createDemoSnapshot } from "@midnight-ntwrk/trust-registry-cli";
import { describe, expect, it } from "vitest";

import { localApiOrigin, observeLocalApiCurrentReads } from "../local-ledger-api-observation.js";
import { createTrustRegistryApiServer } from "../server.js";
import type { TrustRegistryApiStateSource } from "../source.js";

const snapshot = createDemoSnapshot({ label: "observation-route-unit" });
const selection = {
  snapshot,
  finalizedBlockHash: `0x${"a".repeat(64)}`,
  authorizationIds: {
    issuer: new Set([snapshot.issuerEntries[0]!.authorization.authorizationId]),
    verifier: new Set([snapshot.verifierEntries[0]!.authorization.authorizationId]),
    auditor: new Set([snapshot.auditorEntries[0]!.authorization.authorizationId]),
  },
  recognitionIds: new Set([snapshot.recognitionEntries[0]!.recognition.recognitionId]),
};
const source: TrustRegistryApiStateSource = {
  mode: "local-ledger",
  async loadSnapshot() { return snapshot; },
  async loadCurrentLedgerSelection() { return selection; },
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
        format: "tr-local-api-current-read-observation-v4",
        selectedStateSha256: expect.stringMatching(/^[0-9a-f]{64}$/u),
        registryId: snapshot.registry.registryId,
        sourceFinalizedBlockHash: selection.finalizedBlockHash,
        currentEpochId: snapshot.currentEpoch.epochId,
        counts: { issuer: 2, verifier: 2, auditor: 2, recognition: 2 },
        resolvedLookups: { issuer: 1, verifier: 1, auditor: 1, recognition: 1 },
        ambiguousLookups: { issuer: 0, verifier: 0, auditor: 0 },
        releaseQualified: false,
      });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("checks ambiguous current verifier scopes fail closed while reading both IDs", async () => {
    const first = snapshot.verifierEntries[0]!;
    const second = {
      ...first,
      label: snapshot.verifierEntries[1]!.label,
      authorization: {
        ...first.authorization,
        authorizationId: snapshot.verifierEntries[1]!.authorization.authorizationId,
      },
    };
    const ambiguousSnapshot = { ...snapshot, verifierEntries: [first, second] };
    const ambiguousSource: TrustRegistryApiStateSource = {
      mode: "local-ledger",
      async loadSnapshot() { return ambiguousSnapshot; },
      async loadCurrentLedgerSelection() {
        return { ...selection, snapshot: ambiguousSnapshot,
          authorizationIds: { ...selection.authorizationIds,
            verifier: new Set([first.authorization.authorizationId, second.authorization.authorizationId]) } };
      },
    };
    const server = createTrustRegistryApiServer({ source: ambiguousSource });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      const apiOrigin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      await expect(observeLocalApiCurrentReads({ source: ambiguousSource, apiOrigin }))
        .resolves.toMatchObject({ counts: { verifier: 2 },
          resolvedLookups: { verifier: 0 }, ambiguousLookups: { verifier: 2 },
          releaseQualified: false });
      const unsafeResolution: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (new URL(String(url)).pathname !== "/v1/authorizations/resolve"
          || (JSON.parse(String(init?.body)) as { role: string }).role !== "verifier") return response;
        return new Response(JSON.stringify(first), {
          status: 200, headers: { "cache-control": "no-store" },
        });
      };
      await expect(observeLocalApiCurrentReads({ source: ambiguousSource, apiOrigin,
        fetchImpl: unsafeResolution })).rejects.toThrow(/status or cache policy/u);
      const wrongProblem: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (new URL(String(url)).pathname !== "/v1/authorizations/resolve"
          || (JSON.parse(String(init?.body)) as { role: string }).role !== "verifier") return response;
        return new Response(JSON.stringify({ type: "https://example.invalid/problems/other" }), {
          status: 409, headers: { "cache-control": "no-store" },
        });
      };
      await expect(observeLocalApiCurrentReads({ source: ambiguousSource, apiOrigin,
        fetchImpl: wrongProblem })).rejects.toThrow(/did not fail closed/u);
      const grantInProblem: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (new URL(String(url)).pathname !== "/v1/authorizations/resolve"
          || (JSON.parse(String(init?.body)) as { role: string }).role !== "verifier") return response;
        return new Response(JSON.stringify({ ...await response.json(), authorization: first.authorization }), {
          status: 409, headers: { "cache-control": "no-store" },
        });
      };
      await expect(observeLocalApiCurrentReads({ source: ambiguousSource, apiOrigin,
        fetchImpl: grantInProblem })).rejects.toThrow(/did not fail closed/u);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("binds current-read observation to the plan digest held by the running server", async () => {
    const digest = "a".repeat(64);
    expect(() => createTrustRegistryApiServer({ source: { ...source, mode: "snapshot" },
      localPlanSha256: digest })).toThrow(/Startup plan digest/u);
    expect(() => createTrustRegistryApiServer({ source,
      localPlanSha256: "bad" })).toThrow(/Startup plan digest/u);
    const server = createTrustRegistryApiServer({ source, localPlanSha256: digest });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      const apiOrigin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      const health = await fetch(`${apiOrigin}/health`);
      expect(await health.json()).toMatchObject({
        localPlanSha256: digest, finalizedBlockHash: selection.finalizedBlockHash,
      });
      await expect(observeLocalApiCurrentReads({ source, apiOrigin,
        expectedPlanSha256: digest })).resolves.toMatchObject({ releaseQualified: false });
      const substitutedCheckpoint: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (new URL(String(url)).pathname !== "/health") return response;
        return new Response(JSON.stringify({ ...await response.json(),
          finalizedBlockHash: `0x${"b".repeat(64)}` }), {
          status: 200, headers: { "cache-control": "no-store" },
        });
      };
      await expect(observeLocalApiCurrentReads({ source, apiOrigin,
        expectedPlanSha256: digest, fetchImpl: substitutedCheckpoint }))
        .rejects.toThrow(/health does not identify/u);
      await expect(observeLocalApiCurrentReads({ source, apiOrigin,
        expectedPlanSha256: "b".repeat(64) })).rejects.toThrow(/signed-plan registry source/u);
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

  it("rejects a source without a finalized active entry for every role", async () => {
    const server = createTrustRegistryApiServer({ source });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      const apiOrigin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      const missingIssuer: TrustRegistryApiStateSource = { ...source,
        loadCurrentLedgerSelection: async () => ({
          ...selection, authorizationIds: { ...selection.authorizationIds, issuer: new Set<string>() },
        }),
      };
      await expect(observeLocalApiCurrentReads({ source: missingIssuer, apiOrigin }))
        .rejects.toThrow(/finalized current active authorization/u);
      const onlyHistoricalIssuer: TrustRegistryApiStateSource = { ...source,
        loadCurrentLedgerSelection: async () => ({ ...selection,
          authorizationIds: { ...selection.authorizationIds,
            issuer: new Set([snapshot.issuerEntries[1]!.authorization.authorizationId]) },
        }),
      };
      await expect(observeLocalApiCurrentReads({ source: onlyHistoricalIssuer, apiOrigin }))
        .rejects.toThrow(/finalized current active authorization/u);
      const missingRecognition: TrustRegistryApiStateSource = { ...source,
        loadCurrentLedgerSelection: async () => ({ ...selection, recognitionIds: new Set<string>() }),
      };
      await expect(observeLocalApiCurrentReads({ source: missingRecognition, apiOrigin }))
        .rejects.toThrow(/finalized current active recognition/u);
      const unknownIssuer: TrustRegistryApiStateSource = { ...source,
        loadCurrentLedgerSelection: async () => ({ ...selection,
          authorizationIds: { ...selection.authorizationIds, issuer: new Set(["issuer:unknown"]) },
        }),
      };
      await expect(observeLocalApiCurrentReads({ source: unknownIssuer, apiOrigin }))
        .rejects.toThrow(/references a missing snapshot entry/u);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
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
      async loadSnapshot() { return snapshot; },
      async loadCurrentLedgerSelection() {
        reads += 1;
        return reads === 1 ? selection : {
          ...selection, snapshot: { ...snapshot, generatedAt: "2030-01-01T00:00:00Z" },
        };
      },
    };
    const responding: typeof fetch = async (url, init) => {
      const path = new URL(String(url)).pathname;
      let body: unknown;
      let status = 200;
      if (path === "/health") body = { status: "ok", sourceMode: "local-ledger",
        registryId: snapshot.registry.registryId, generatedAt: snapshot.generatedAt,
        finalizedBlockHash: selection.finalizedBlockHash };
      else if (path === "/v1/registry/summary") body = buildSnapshotSummary(snapshot);
      else if (path === "/v1/registry") body = snapshot.registry;
      else if (path === "/v1/epochs/current") body = snapshot.currentEpoch;
      else if (path === "/v1/recognitions"
        || ["issuer", "verifier", "auditor"].some((role) => path === `/v1/authorizations/${role}`)) {
        status = 503;
        body = { type: "https://example.invalid/problems/local-list-projection-unavailable" };
      }
      else if (path === "/v1/authorizations/resolve") {
        const query = JSON.parse(String(init?.body)) as { role: "issuer" | "verifier" | "auditor";
          subjectDid: string };
        body = snapshot[`${query.role}Entries`][0]?.authorization.subjectDid === query.subjectDid
          ? snapshot[`${query.role}Entries`][0] : undefined;
      } else if (path === "/v1/recognitions/resolve") {
        const query = JSON.parse(String(init?.body)) as { recognizedAuthorityDid: string };
        body = snapshot.recognitionEntries[0]?.recognition.recognizedAuthorityDid
          === query.recognizedAuthorityDid ? snapshot.recognitionEntries[0] : undefined;
      }
      else if (path.startsWith("/v1/authorizations/")) {
        const [, , , role, id] = path.split("/");
        body = role === "issuer" || role === "verifier" || role === "auditor"
          ? snapshot[`${role}Entries`].find((entry) => entry.authorization.authorizationId === decodeURIComponent(id!)
            && selection.authorizationIds[role].has(entry.authorization.authorizationId))
          : undefined;
      } else if (path.startsWith("/v1/recognitions/")) {
        const id = path.split("/").at(-1);
        body = snapshot.recognitionEntries.find((entry) => entry.recognition.recognitionId === decodeURIComponent(id!)
          && selection.recognitionIds.has(entry.recognition.recognitionId));
      }
      if (body === undefined) { status = path === "/v1/epochs/resolve" ? 501 : 404; body = {}; }
      return new Response(JSON.stringify(body), { status, headers: { "cache-control": "no-store" } });
    };
    await expect(observeLocalApiCurrentReads({
      source: drifting, apiOrigin: "http://127.0.0.1:4400", fetchImpl: responding,
    })).rejects.toThrow(/changed during API readback/u);

    let checkpointReads = 0;
    const checkpointDrift: TrustRegistryApiStateSource = {
      ...source,
      async loadCurrentLedgerSelection() {
        checkpointReads += 1;
        return checkpointReads === 1 ? selection : {
          ...selection, finalizedBlockHash: `0x${"b".repeat(64)}`,
        };
      },
    };
    await expect(observeLocalApiCurrentReads({
      source: checkpointDrift, apiOrigin: "http://127.0.0.1:4400", fetchImpl: responding,
    })).rejects.toThrow(/changed during API readback/u);
  });

  it("rejects substituted records and missing no-store policy", async () => {
    const server = createTrustRegistryApiServer({ source });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      await expect(observeLocalApiCurrentReads({ source, apiOrigin: origin })).resolves
        .toMatchObject({ releaseQualified: false });
      expect(selection.authorizationIds.issuer.has(snapshot.issuerEntries[1]!.authorization.authorizationId))
        .toBe(false);
      expect(selection.recognitionIds.has(snapshot.recognitionEntries[1]!.recognition.recognitionId))
        .toBe(false);
      expect(snapshot.issuerEntries[0]!.authorization.subjectDid)
        .not.toBe(snapshot.issuerEntries[1]!.authorization.subjectDid);
      expect(snapshot.recognitionEntries[0]!.recognition.recognizedAuthorityDid)
        .not.toBe(snapshot.recognitionEntries[1]!.recognition.recognizedAuthorityDid);
      const substituted: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (!new URL(String(url)).pathname.startsWith("/v1/authorizations/issuer/")) return response;
        return new Response(JSON.stringify({ label: "substituted" }), {
          status: 200, headers: { "cache-control": "no-store" },
        });
      };
      await expect(observeLocalApiCurrentReads({ source, apiOrigin: origin, fetchImpl: substituted }))
        .rejects.toThrow(/issuer record differs/u);
      const substitutedResolution: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (new URL(String(url)).pathname !== "/v1/authorizations/resolve") return response;
        return new Response(JSON.stringify({ label: "substituted" }), {
          status: 200, headers: { "cache-control": "no-store" },
        });
      };
      await expect(observeLocalApiCurrentReads({ source, apiOrigin: origin,
        fetchImpl: substitutedResolution })).rejects.toThrow(/current resolution differs/u);
      const staleAsCurrent: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (new URL(String(url)).pathname !== "/v1/authorizations/resolve"
          || (JSON.parse(String(init?.body)) as { subjectDid: string }).subjectDid
            !== snapshot.issuerEntries[1]!.authorization.subjectDid) return response;
        return new Response(JSON.stringify(snapshot.issuerEntries[1]), {
          status: 200, headers: { "cache-control": "no-store" },
        });
      };
      await expect(observeLocalApiCurrentReads({ source, apiOrigin: origin,
        fetchImpl: staleAsCurrent })).rejects.toThrow(/status or cache policy/u);
      const staleRecognitionAsCurrent: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (new URL(String(url)).pathname !== "/v1/recognitions/resolve"
          || (JSON.parse(String(init?.body)) as { recognizedAuthorityDid: string }).recognizedAuthorityDid
            !== snapshot.recognitionEntries[1]!.recognition.recognizedAuthorityDid) return response;
        return new Response(JSON.stringify(snapshot.recognitionEntries[1]), {
          status: 200, headers: { "cache-control": "no-store" },
        });
      };
      await expect(observeLocalApiCurrentReads({ source, apiOrigin: origin,
        fetchImpl: staleRecognitionAsCurrent })).rejects.toThrow(/status or cache policy/u);
      const cacheable: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (new URL(String(url)).pathname !== "/health") return response;
        return new Response(await response.text(), { status: 200 });
      };
      await expect(observeLocalApiCurrentReads({ source, apiOrigin: origin, fetchImpl: cacheable }))
        .rejects.toThrow(/cache policy/u);
      const staleHealth: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (new URL(String(url)).pathname !== "/health") return response;
        return new Response(JSON.stringify({ ...await response.json(), generatedAt: "2020-01-01T00:00:00.000Z" }), {
          status: 200, headers: { "cache-control": "no-store" },
        });
      };
      await expect(observeLocalApiCurrentReads({ source, apiOrigin: origin, fetchImpl: staleHealth }))
        .rejects.toThrow(/health does not identify/u);
      let healthReads = 0;
      const changedHealth: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (new URL(String(url)).pathname !== "/health" || ++healthReads === 1) return response;
        return new Response(JSON.stringify({ ...await response.json(),
          generatedAt: "2020-01-01T00:00:00.000Z" }), {
          status: 200, headers: { "cache-control": "no-store" },
        });
      };
      await expect(observeLocalApiCurrentReads({ source, apiOrigin: origin,
        fetchImpl: changedHealth })).rejects.toThrow(/health changed during/u);
      const staleSummary: typeof fetch = async (url, init) => {
        const response = await fetch(url, init);
        if (new URL(String(url)).pathname !== "/v1/registry/summary") return response;
        return new Response(JSON.stringify({ ...await response.json(), generatedAt: "2020-01-01T00:00:00.000Z" }), {
          status: 200, headers: { "cache-control": "no-store" },
        });
      };
      await expect(observeLocalApiCurrentReads({ source, apiOrigin: origin, fetchImpl: staleSummary }))
        .rejects.toThrow(/registry summary differs/u);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
