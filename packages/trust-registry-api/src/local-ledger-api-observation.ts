import { isDeepStrictEqual } from "node:util";
import { randomUUID } from "node:crypto";

import { buildSnapshotSummary } from "@midnight-ntwrk/trust-registry-cli";

import type { TrustRegistryApiStateSource } from "./source.js";

const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_ENTRIES_PER_ROLE = 1000;

const jsonProjection = (value: unknown): unknown => JSON.parse(JSON.stringify(value)) as unknown;

export function localApiOrigin(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || !url.port
    || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new Error("Local API observation requires an explicit 127.0.0.1 HTTP origin");
  }
  return url.origin;
}

async function request(origin: string, path: string, expectedStatus: number,
  fetchImpl: typeof fetch, body?: unknown): Promise<unknown> {
  const response = await fetchImpl(`${origin}${path}`, {
    method: body === undefined ? "GET" : "POST",
    ...(body === undefined ? {} : { headers: { "content-type": "application/json" },
      body: JSON.stringify(body) }),
    redirect: "error", signal: AbortSignal.timeout(10_000),
  });
  if (response.status !== expectedStatus || response.headers.get("cache-control") !== "no-store") {
    throw new Error("Local API response status or cache policy differs from the expected current-only surface");
  }
  const reader = response.body?.getReader();
  if (reader === undefined) throw new Error("Local API response body is unavailable");
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      length += next.value.byteLength;
      if (length > MAX_RESPONSE_BYTES) throw new Error("Local API response exceeds the observation limit");
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  try {
    return JSON.parse(Buffer.concat(chunks, length).toString("utf8")) as unknown;
  } catch {
    throw new Error("Local API response is not valid JSON");
  }
}

/** Readback probe only; the caller must establish API process identity and finality separately. */
export async function observeLocalApiCurrentReads(input: {
  source: TrustRegistryApiStateSource;
  apiOrigin: string;
  fetchImpl?: typeof fetch;
}): Promise<{
  format: "tr-local-api-current-read-observation-v1";
  observedAt: string;
  apiOrigin: string;
  registryId: string;
  currentEpochId: string;
  counts: Record<"issuer" | "verifier" | "auditor" | "recognition", number>;
  releaseQualified: false;
  scope: string;
}> {
  if (input.source.mode !== "local-ledger" || input.source.loadCurrentLedgerSelection === undefined) {
    throw new Error("Current-read observation requires the signed local-ledger source");
  }
  const origin = localApiOrigin(input.apiOrigin);
  const fetchImpl = input.fetchImpl ?? fetch;
  const selection = await input.source.loadCurrentLedgerSelection();
  const { snapshot } = selection;
  const health = await request(origin, "/health", 200, fetchImpl) as Record<string, unknown>;
  if (health.status !== "ok" || health.sourceMode !== "local-ledger"
    || health.registryId !== snapshot.registry.registryId
    || health.generatedAt !== snapshot.generatedAt) {
    throw new Error("Local API health does not identify the signed-plan registry source");
  }
  const summary = await request(origin, "/v1/registry/summary", 200, fetchImpl);
  if (!isDeepStrictEqual(summary, jsonProjection(buildSnapshotSummary(snapshot)))) {
    throw new Error("Local API registry summary differs from the signed-plan source");
  }
  const registry = await request(origin, "/v1/registry", 200, fetchImpl) as Record<string, unknown>;
  if (!isDeepStrictEqual(registry, jsonProjection(snapshot.registry))) {
    throw new Error("Local API registry summary differs from the signed-plan source");
  }
  const epoch = await request(origin, "/v1/epochs/current", 200, fetchImpl);
  if (!isDeepStrictEqual(epoch, jsonProjection(snapshot.currentEpoch))) {
    throw new Error("Local API current epoch differs from signed-plan readback");
  }

  const counts = { issuer: 0, verifier: 0, auditor: 0, recognition: 0 };
  for (const role of ["issuer", "verifier", "auditor"] as const) {
    const entries = snapshot[`${role}Entries`];
    if (entries.length === 0 || entries.length > MAX_ENTRIES_PER_ROLE
      || !entries.some((entry) => entry.authorization.status === "active")) {
      throw new Error(`Local API ${role} readback requires a bounded set with an active authorization`);
    }
    for (const entry of entries) {
      const id = encodeURIComponent(entry.authorization.authorizationId);
      const observed = await request(origin, `/v1/authorizations/${role}/${id}`, 200, fetchImpl);
      if (!isDeepStrictEqual(observed, jsonProjection(entry))) {
        throw new Error(`Local API ${role} record differs from signed-plan readback`);
      }
      if (selection.authorizationIds[role].has(entry.authorization.authorizationId)) {
        const current = await request(origin, "/v1/authorizations/resolve", 200, fetchImpl, {
          role, subjectDid: entry.authorization.subjectDid,
          resourceId: entry.authorization.resourceId,
          resourceType: entry.authorization.resourceType,
          trustLevel: entry.authorization.trustLevel,
        });
        if (!isDeepStrictEqual(current, jsonProjection(entry))) {
          throw new Error(`Local API ${role} current resolution differs from finalized selection`);
        }
      }
    }
    counts[role] = entries.length;
  }
  const recognitions = snapshot.recognitionEntries;
  if (recognitions.length === 0 || recognitions.length > MAX_ENTRIES_PER_ROLE
    || !recognitions.some((entry) => entry.recognition.status === "active")) {
    throw new Error("Local API recognition readback requires a bounded set with an active recognition");
  }
  for (const entry of recognitions) {
    const id = encodeURIComponent(entry.recognition.recognitionId);
    const observed = await request(origin, `/v1/recognitions/${id}`, 200, fetchImpl);
    if (!isDeepStrictEqual(observed, jsonProjection(entry))) {
      throw new Error("Local API recognition differs from signed-plan readback");
    }
    if (selection.recognitionIds.has(entry.recognition.recognitionId)) {
      const current = await request(origin, "/v1/recognitions/resolve", 200, fetchImpl, {
        recognizedAuthorityDid: entry.recognition.recognizedAuthorityDid,
        recognizedRegistryId: entry.recognition.recognizedRegistryId,
        scopeResourceType: entry.recognition.scope.resourceType,
        scopeResourceId: entry.recognition.scope.resourceId,
        scopeContext: entry.recognition.scope.context,
        trustLevel: entry.recognition.trustLevel,
      });
      if (!isDeepStrictEqual(current, jsonProjection(entry))) {
        throw new Error("Local API recognition current resolution differs from finalized selection");
      }
    }
  }
  counts.recognition = recognitions.length;

  const absent = encodeURIComponent(`tr-observation-absent-${randomUUID()}`);
  await request(origin, `/v1/authorizations/issuer/${absent}`, 404, fetchImpl);
  await request(origin, `/v1/recognitions/${absent}`, 404, fetchImpl);
  await request(origin, `/v1/epochs/resolve?at=${encodeURIComponent(snapshot.generatedAt)}`, 501, fetchImpl);
  if (!isDeepStrictEqual(await input.source.loadCurrentLedgerSelection(), selection)) {
    throw new Error("Finalized local selection changed during API readback observation");
  }
  return {
    format: "tr-local-api-current-read-observation-v1",
    observedAt: new Date().toISOString(),
    apiOrigin: origin,
    registryId: snapshot.registry.registryId,
    currentEpochId: snapshot.currentEpoch.epochId,
    counts,
    releaseQualified: false,
    scope: "current HTTP resolution and all-record by-ID readback only; counts include all records, not just current IDs; not mutation, browser, DID/VC/status, egress, or independent finality evidence",
  };
}
