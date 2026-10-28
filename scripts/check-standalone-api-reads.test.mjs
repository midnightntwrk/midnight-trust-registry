import assert from "node:assert/strict";
import { test } from "node:test";

import { probeStandaloneApiCurrentReads } from "./check-standalone-api-reads.mjs";

const sourceRevision = "a".repeat(40);
const fingerprint = "B".repeat(40);
const topology = {
  kind: "standalone-api-runtime-topology-observation",
  releaseQualified: false,
  sourceRevision,
  installInventorySha256: "9".repeat(64),
  apiContainerId: "c".repeat(64),
  apiStartedAt: "2026-10-24T10:00:00.000Z",
  apiRestartCount: 0,
  networkId: "n".repeat(64),
  approvalMountReadOnly: true,
  trustAnchorMountReadOnly: true,
  internalNetworkOnly: true,
  hostPortPublished: false,
};
const report = {
  format: "tr-local-api-current-read-observation-v4",
  apiOrigin: "http://127.0.0.1:4400",
  planSourceRevision: sourceRevision,
  planSha256: "d".repeat(64),
  planInstallInventorySha256: topology.installInventorySha256,
  planContractAddress: `0x${"a".repeat(64)}`,
  planExpectedGenesisHash: `0x${"b".repeat(64)}`,
  selectedStateSha256: "f".repeat(64),
  observedAt: "2026-10-24T11:00:00.000Z",
  planNotAfter: "2026-11-01T00:00:00.000Z",
  registryId: "registry:local",
  currentEpochId: "epoch:local",
  sourceFinalizedBlockHash: `0x${"e".repeat(64)}`,
  counts: { issuer: 2, verifier: 2, auditor: 1, recognition: 1 },
  resolvedLookups: { issuer: 1, verifier: 0, auditor: 1, recognition: 1 },
  ambiguousLookups: { issuer: 0, verifier: 2, auditor: 0 },
  releaseQualified: false,
};
const env = { TR_API_REVIEWER_FINGERPRINT: fingerprint };

test("probes loopback from the verified API container, then rechecks its identity", async () => {
  const events = [];
  const result = await probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async (bundle) => { events.push(["observe", bundle]); return topology; },
    execDocker: async (args) => { events.push(["exec", args]); return JSON.stringify(report); },
  });
  assert.deepEqual(events.map(([kind]) => kind), ["observe", "exec", "observe"]);
  assert.deepEqual(events[1][1], ["exec", topology.apiContainerId, "node",
    "/app/bin/trust-registry-api.mjs", "observe-local-ledger-api",
    "--local-ledger-plan", "/run/trust-registry/api-plan.json",
    "--local-ledger-signature", "/run/trust-registry/api-plan.sig",
    "--local-ledger-keyring", "/run/trust-registry/reviewer-keyring",
    "--local-ledger-reviewer", fingerprint,
    "--api-origin", "http://127.0.0.1:4400"]);
  assert.deepEqual(result, {
    format: "tr-standalone-api-current-read-probe-v4",
    sourceRevision, apiContainerId: topology.apiContainerId,
    apiStartedAt: topology.apiStartedAt, apiRestartCount: topology.apiRestartCount,
    networkId: topology.networkId,
    installInventorySha256: topology.installInventorySha256,
    planSha256: report.planSha256, planNotAfter: report.planNotAfter,
    planContractAddress: report.planContractAddress,
    planExpectedGenesisHash: report.planExpectedGenesisHash,
    observedAt: report.observedAt,
    registryId: report.registryId, currentEpochId: report.currentEpochId,
    sourceFinalizedBlockHash: report.sourceFinalizedBlockHash,
    selectedStateSha256: report.selectedStateSha256,
    counts: report.counts,
    resolvedLookups: report.resolvedLookups,
    ambiguousLookups: report.ambiguousLookups,
    routeReadback: "same-container-signed-plan-current-only",
    scope: "Selected by-ID readback and counted successful 200 resolves; ambiguous lookups checked for fail-closed 409 only. Counts include stale records and repeated lookup scopes; this is not independent finality or actor evidence.",
    independentFinality: "not-verified", egressDenied: "not-verified",
    actorJourneys: "not-run", releaseQualified: false,
  });
});

test("does not exec when topology or reviewer input is invalid", async () => {
  let execCount = 0;
  const execDocker = async () => { execCount += 1; return JSON.stringify(report); };
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async () => ({ ...topology, apiContainerId: "not-an-id" }), execDocker,
  }), /topology observation is incomplete/u);
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async () => ({ ...topology, installInventorySha256: "bad" }), execDocker,
  }), /topology observation is incomplete/u);
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", {
    TR_API_REVIEWER_FINGERPRINT: "bad",
  }, { observe: async () => topology, execDocker }), /fingerprint is missing/u);
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", {
    TR_API_REVIEWER_FINGERPRINT: 42,
  }, { observe: async () => topology, execDocker }), /fingerprint is missing/u);
  assert.equal(execCount, 0);
});

test("rejects malformed and source-mismatched packaged readback", async () => {
  const observe = async () => topology;
  for (const stdout of ["not-json", JSON.stringify({ ...report, releaseQualified: true }),
    JSON.stringify({ ...report, format: "tr-local-api-current-read-observation-v1" }),
    JSON.stringify({ ...report, planInstallInventorySha256: "bad" }),
    JSON.stringify({ ...report, planContractAddress: `0x${"0".repeat(64)}` }),
    JSON.stringify({ ...report, planExpectedGenesisHash: "invalid" }),
    JSON.stringify({ ...report, planSourceRevision: "b".repeat(40) })]) {
    await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
      observe, execDocker: async () => stdout,
    }), /did not return JSON|invalid report|source differs/u);
  }
});

test("rejects a signed plan for a different verified install inventory", async () => {
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async () => topology,
    execDocker: async () => JSON.stringify({ ...report,
      planInstallInventorySha256: "8".repeat(64) }),
  }), /plan install inventory differs/u);
});

test("rejects a replaced container or network after the HTTP probe", async () => {
  let observed = 0;
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async () => {
      observed += 1;
      return observed === 1 ? topology : { ...topology, apiContainerId: "d".repeat(64) };
    },
    execDocker: async () => JSON.stringify(report),
  }), /changed during current-read probe/u);
  observed = 0;
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async () => {
      observed += 1;
      return observed === 1 ? topology : { ...topology, networkId: "other" };
    },
    execDocker: async () => JSON.stringify(report),
  }), /changed during current-read probe/u);
  observed = 0;
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async () => {
      observed += 1;
      return observed === 1 ? topology : { ...topology, installInventorySha256: "8".repeat(64) };
    },
    execDocker: async () => JSON.stringify(report),
  }), /changed during current-read probe/u);
  observed = 0;
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async () => {
      observed += 1;
      return observed === 1 ? topology : { ...topology, apiRestartCount: 1 };
    },
    execDocker: async () => JSON.stringify(report),
  }), /changed during current-read probe/u);
  observed = 0;
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async () => {
      observed += 1;
      return observed === 1 ? topology : { ...topology,
        apiStartedAt: "2026-10-24T11:00:01.000Z" };
    },
    execDocker: async () => JSON.stringify(report),
  }), /changed during current-read probe/u);
});

test("rejects invalid report time, expired observation, and incomplete topology", async () => {
  for (const current of [{ ...report, observedAt: "not-a-time" },
    { ...report, observedAt: "2026-11-02T00:00:00.000Z" },
    { ...report, planSha256: undefined },
    { ...report, selectedStateSha256: undefined },
    { ...report, planNotAfter: "2026-11-01" },
    { ...report, planSourceRevision: undefined },
    { ...report, sourceFinalizedBlockHash: undefined },
    { ...report, sourceFinalizedBlockHash: `0x${"0".repeat(64)}` },
    { ...report, counts: { ...report.counts, issuer: -1 } },
    { ...report, resolvedLookups: undefined },
    { ...report, resolvedLookups: { ...report.resolvedLookups, verifier: 3 } },
    { ...report, ambiguousLookups: undefined },
    { ...report, ambiguousLookups: { ...report.ambiguousLookups, verifier: 3 } },
    { ...report, apiOrigin: "http://api:4400" }]) {
    await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
      observe: async () => topology, execDocker: async () => JSON.stringify(current),
    }), /invalid report/u);
  }
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async () => ({ ...topology, approvalMountReadOnly: false }),
    execDocker: async () => JSON.stringify(report),
  }), /topology observation is incomplete/u);
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async () => ({ ...topology, trustAnchorMountReadOnly: false }),
    execDocker: async () => JSON.stringify(report),
  }), /topology observation is incomplete/u);
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async () => ({ ...topology, apiRestartCount: -1 }),
    execDocker: async () => JSON.stringify(report),
  }), /topology observation is incomplete/u);
});

test("fails closed when execution or the post-probe observation fails", async () => {
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async () => topology,
    execDocker: async () => { throw new Error("packaged CLI failed"); },
  }), /packaged CLI failed/u);
  let observations = 0;
  await assert.rejects(probeStandaloneApiCurrentReads("/bundle", env, {
    observe: async () => {
      observations += 1;
      if (observations === 2) throw new Error("post-probe inspection unavailable");
      return topology;
    },
    execDocker: async () => JSON.stringify(report),
  }), /post-probe inspection unavailable/u);
});
