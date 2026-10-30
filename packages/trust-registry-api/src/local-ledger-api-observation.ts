import { isDeepStrictEqual } from "node:util";
import { createHash, randomUUID } from "node:crypto";

import { buildSnapshotSummary } from "@midnight-ntwrk/trust-registry-cli";
import { canonicalizeJson } from "@midnight-ntwrk/trust-registry-domain";

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
  expectedPlanSha256?: string;
  fetchImpl?: typeof fetch;
}): Promise<{
  format: "tr-local-api-current-read-observation-v4";
  observedAt: string;
  apiOrigin: string;
  registryId: string;
  sourceFinalizedBlockHash: string;
  currentEpochId: string;
  selectedStateSha256: string;
  counts: Record<"issuer" | "verifier" | "auditor" | "recognition", number>;
  resolvedLookups: Record<"issuer" | "verifier" | "auditor" | "recognition", number>;
  ambiguousLookups: Record<"issuer" | "verifier" | "auditor", number>;
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
  if (!/^0x[0-9a-f]{64}$/u.test(selection.finalizedBlockHash)
    || /^0x0{64}$/u.test(selection.finalizedBlockHash)) {
    throw new Error("Local API source lacks a finalized checkpoint hash");
  }
  const health = await request(origin, "/health", 200, fetchImpl) as Record<string, unknown>;
  if (health.status !== "ok" || health.sourceMode !== "local-ledger"
    || health.registryId !== snapshot.registry.registryId
    || health.generatedAt !== snapshot.generatedAt
    || health.finalizedBlockHash !== selection.finalizedBlockHash
    || (input.expectedPlanSha256 !== undefined
      && (!/^[0-9a-f]{64}$/u.test(input.expectedPlanSha256)
        || health.localPlanSha256 !== input.expectedPlanSha256))) {
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
  const resolvedLookups = { issuer: 0, verifier: 0, auditor: 0, recognition: 0 };
  const ambiguousLookups = { issuer: 0, verifier: 0, auditor: 0 };
  for (const role of ["issuer", "verifier", "auditor"] as const) {
    const listProblem = await request(origin, `/v1/authorizations/${role}`, 503, fetchImpl) as Record<string, unknown>;
    if (typeof listProblem.type !== "string" || !listProblem.type.endsWith("/local-list-projection-unavailable")) {
      throw new Error(`Local API ${role} list did not fail closed`);
    }
    const entries = snapshot[`${role}Entries`];
    const entryIds = new Set(entries.map((entry) => entry.authorization.authorizationId));
    if ([...selection.authorizationIds[role]].some((id) => !entryIds.has(id))) {
      throw new Error(`Local API ${role} finalized selection references a missing snapshot entry`);
    }
    if (entries.length === 0 || entries.length > MAX_ENTRIES_PER_ROLE
      || !entries.some((entry) => entry.authorization.status === "active"
        && selection.authorizationIds[role].has(entry.authorization.authorizationId))) {
      throw new Error(`Local API ${role} readback requires a bounded set with a finalized current active authorization`);
    }
    for (const entry of entries) {
      const id = encodeURIComponent(entry.authorization.authorizationId);
      const selected = selection.authorizationIds[role].has(entry.authorization.authorizationId);
      const observed = await request(origin, `/v1/authorizations/${role}/${id}`,
        selected ? 200 : 404, fetchImpl);
      if (selected && !isDeepStrictEqual(observed, jsonProjection(entry))) {
        throw new Error(`Local API ${role} record differs from signed-plan readback`);
      }
      const currentMatches = entries.filter((candidate) =>
        selection.authorizationIds[role].has(candidate.authorization.authorizationId)
        && candidate.authorization.subjectDid === entry.authorization.subjectDid
        && candidate.authorization.resourceId === entry.authorization.resourceId
        && candidate.authorization.resourceType === entry.authorization.resourceType
        && candidate.authorization.trustLevel === entry.authorization.trustLevel);
      let expectedStatus = 404;
      if (currentMatches.length === 1) expectedStatus = 200;
      if (currentMatches.length > 1) expectedStatus = 409;
      const current = await request(origin, "/v1/authorizations/resolve",
        expectedStatus, fetchImpl, {
          role, subjectDid: entry.authorization.subjectDid,
          resourceId: entry.authorization.resourceId,
          resourceType: entry.authorization.resourceType,
          trustLevel: entry.authorization.trustLevel,
        });
      if (currentMatches.length > 1) {
        const problem = typeof current === "object" && current !== null
          ? current as Record<string, unknown> : null;
        if (problem === null || Object.keys(problem).sort().join("\0") !== "status\0title\0type"
          || typeof problem.type !== "string"
          || !problem.type.endsWith("/ambiguous-current-scope")
          || problem.title !== "ambiguous current scope" || problem.status !== 409) {
          throw new Error(`Local API ${role} ambiguous resolution did not fail closed`);
        }
        ambiguousLookups[role] += 1;
      }
      if (currentMatches.length === 1 && !isDeepStrictEqual(current, jsonProjection(currentMatches[0]))) {
        throw new Error(`Local API ${role} current resolution differs from finalized selection`);
      }
      if (currentMatches.length === 1) resolvedLookups[role] += 1;
    }
    counts[role] = entries.length;
  }
  const recognitions = snapshot.recognitionEntries;
  const recognitionListProblem = await request(origin, "/v1/recognitions", 503, fetchImpl) as Record<string, unknown>;
  if (typeof recognitionListProblem.type !== "string"
    || !recognitionListProblem.type.endsWith("/local-list-projection-unavailable")) {
    throw new Error("Local API recognition list did not fail closed");
  }
  const recognitionIds = new Set(recognitions.map((entry) => entry.recognition.recognitionId));
  if ([...selection.recognitionIds].some((id) => !recognitionIds.has(id))) {
    throw new Error("Local API recognition finalized selection references a missing snapshot entry");
  }
  if (recognitions.length === 0 || recognitions.length > MAX_ENTRIES_PER_ROLE
    || !recognitions.some((entry) => entry.recognition.status === "active"
      && selection.recognitionIds.has(entry.recognition.recognitionId))) {
    throw new Error("Local API recognition readback requires a bounded set with a finalized current active recognition");
  }
  for (const entry of recognitions) {
    const id = encodeURIComponent(entry.recognition.recognitionId);
    const selected = selection.recognitionIds.has(entry.recognition.recognitionId);
    const observed = await request(origin, `/v1/recognitions/${id}`,
      selected ? 200 : 404, fetchImpl);
    if (selected && !isDeepStrictEqual(observed, jsonProjection(entry))) {
      throw new Error("Local API recognition differs from signed-plan readback");
    }
    const currentMatches = recognitions.filter((candidate) =>
      selection.recognitionIds.has(candidate.recognition.recognitionId)
      && candidate.recognition.recognizedAuthorityDid === entry.recognition.recognizedAuthorityDid
      && candidate.recognition.recognizedRegistryId === entry.recognition.recognizedRegistryId
      && candidate.recognition.scope.resourceType === entry.recognition.scope.resourceType
      && candidate.recognition.scope.resourceId === entry.recognition.scope.resourceId
      && canonicalizeJson(candidate.recognition.scope.context ?? null)
        === canonicalizeJson(entry.recognition.scope.context ?? null)
      && candidate.recognition.trustLevel === entry.recognition.trustLevel);
    if (currentMatches.length > 1) throw new Error("Local API recognition finalized selection is ambiguous");
    const current = await request(origin, "/v1/recognitions/resolve",
      currentMatches.length === 0 ? 404 : 200, fetchImpl, {
        recognizedAuthorityDid: entry.recognition.recognizedAuthorityDid,
        recognizedRegistryId: entry.recognition.recognizedRegistryId,
        scopeResourceType: entry.recognition.scope.resourceType,
        scopeResourceId: entry.recognition.scope.resourceId,
        scopeContext: entry.recognition.scope.context,
        trustLevel: entry.recognition.trustLevel,
      });
    if (currentMatches.length === 1 && !isDeepStrictEqual(current, jsonProjection(currentMatches[0]))) {
      throw new Error("Local API recognition current resolution differs from finalized selection");
    }
    if (currentMatches.length === 1) resolvedLookups.recognition += 1;
  }
  counts.recognition = recognitions.length;

  const absent = encodeURIComponent(`tr-observation-absent-${randomUUID()}`);
  await request(origin, `/v1/authorizations/issuer/${absent}`, 404, fetchImpl);
  await request(origin, `/v1/recognitions/${absent}`, 404, fetchImpl);
  await request(origin, `/v1/epochs/resolve?at=${encodeURIComponent(snapshot.generatedAt)}`, 501, fetchImpl);
  if (!isDeepStrictEqual(await input.source.loadCurrentLedgerSelection(), selection)) {
    throw new Error("Finalized local selection changed during API readback observation");
  }
  const finalHealth = await request(origin, "/health", 200, fetchImpl);
  if (!isDeepStrictEqual(finalHealth, health)) {
    throw new Error("Local API health changed during current-read observation");
  }
  return {
    format: "tr-local-api-current-read-observation-v4",
    observedAt: new Date().toISOString(),
    apiOrigin: origin,
    registryId: snapshot.registry.registryId,
    sourceFinalizedBlockHash: selection.finalizedBlockHash,
    currentEpochId: snapshot.currentEpoch.epochId,
    selectedStateSha256: createHash("sha256").update(canonicalizeJson({
      snapshot: jsonProjection(snapshot),
      authorizationIds: Object.fromEntries((["issuer", "verifier", "auditor"] as const)
        .map((role) => [role, [...selection.authorizationIds[role]].sort()])),
      recognitionIds: [...selection.recognitionIds].sort(),
    })).digest("hex"),
    counts,
    resolvedLookups,
    ambiguousLookups,
    releaseQualified: false,
    scope: "selected by-ID readback and counted successful current HTTP resolve attempts; ambiguous lookups verify fail-closed 409 only; counts include stale snapshot records and repeated lookup scopes; checkpoint hash identifies the source view, not the API process; list and stale by-ID routes fail closed; not mutation, browser, DID/VC/status, egress, or independent finality evidence",
  };
}
