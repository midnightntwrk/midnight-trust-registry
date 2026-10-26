import assert from "node:assert/strict";
import { test } from "node:test";

import { observeStandaloneCurrentQueryJourney } from "./check-standalone-current-query-journey.mjs";

const sourceRevision = "a".repeat(40);
const status = {
  sourceRevision,
  releaseQualified: false,
  setupLock: "absent",
  install: "verified-staged-bytes-only",
  stackConfiguration: "observed-ledger-bridge-only",
  localLedger: "operator-pinned-reviewer-signature-verified",
  deployment: "observed",
  stagedVerifierKeys: [{ state: "verified" }],
  maintenanceApproval: "deployment-bound-roster-signature-verified-transition-pending",
  maintenanceTransition: "observed",
  maintenanceLastReadback: "observed",
  maintenanceTransitionAlert: null,
};
const roles = { issuer: 1, verifier: 1, auditor: 1, recognition: 1 };
const read = {
  format: "tr-standalone-api-current-read-probe-v3",
  sourceRevision,
  releaseQualified: false,
  routeReadback: "same-container-signed-plan-current-only",
  planSha256: "b".repeat(64),
  sourceFinalizedBlockHash: `0x${"c".repeat(64)}`,
  registryId: "registry-1",
  currentEpochId: "epoch-1",
  apiContainerId: "d".repeat(64),
  apiStartedAt: "2026-01-01T00:00:00Z",
  apiRestartCount: 0,
  networkId: "network-1",
  counts: roles,
  resolvedLookups: roles,
};
const egress = {
  kind: "standalone-api-egress-observation",
  sourceRevision,
  releaseQualified: false,
  apiContainerId: read.apiContainerId,
  networkId: read.networkId,
  bridgePositiveControlReachable: true,
  bridgeDnsCanaryReachable: true,
  apiCanaryConnectionDenied: true,
  apiBridgeDnsRouteDenied: true,
  apiRoutesConfinedToLedgerSubnet: true,
};

function dependencies(overrides = {}) {
  return {
    setupStatus: async () => status,
    read: async () => read,
    egress: async () => egress,
    ...overrides,
  };
}

test("combines two live current reads around the API egress probe without release claims", async () => {
  let reads = 0;
  const result = await observeStandaloneCurrentQueryJourney("/setup", "/bundle", {},
    dependencies({ read: async () => { reads += 1; return read; } }));
  assert.equal(reads, 2);
  assert.equal(result.format, "tr-standalone-current-query-journey-v1");
  assert.deepEqual(result.resolvedLookups, roles);
  assert.equal(result.actorJourneys, "not-run");
  assert.equal(result.independentFinality, "not-verified");
  assert.equal(result.releaseQualified, false);
});

test("missing wizard approval stops before touching the running API", async () => {
  let called = false;
  await assert.rejects(observeStandaloneCurrentQueryJourney("/setup", "/bundle", {},
    dependencies({ setupStatus: async () => ({ ...status, localLedger: "pending" }),
      read: async () => { called = true; return read; } })), /genesisApproved/u);
  assert.equal(called, false);
});

test("rejects an empty or mocked actor selection", async () => {
  await assert.rejects(observeStandaloneCurrentQueryJourney("/setup", "/bundle", {},
    dependencies({ read: async () => ({ ...read, resolvedLookups: { ...roles, issuer: 0 } }) })),
  /no resolved actor role/u);
});

test("rejects egress denial without positive controls", async () => {
  await assert.rejects(observeStandaloneCurrentQueryJourney("/setup", "/bundle", {},
    dependencies({ egress: async () => ({ ...egress, bridgeDnsCanaryReachable: false }) })),
  /egress probe/u);
});

test("rejects a swapped signed plan or API container between reads", async () => {
  for (const mutation of [{ planSha256: "e".repeat(64) }, { apiContainerId: "f".repeat(64) }]) {
    let reads = 0;
    await assert.rejects(observeStandaloneCurrentQueryJourney("/setup", "/bundle", {},
      dependencies({ read: async () => { reads += 1; return reads === 1 ? read : { ...read, ...mutation }; } })),
    /changed during egress probe/u);
  }
});

test("rejects role count drift between reads", async () => {
  let reads = 0;
  await assert.rejects(observeStandaloneCurrentQueryJourney("/setup", "/bundle", {},
    dependencies({ read: async () => { reads += 1; return reads === 1 ? read
      : { ...read, counts: { ...roles, verifier: 2 } }; } })), /changed during egress probe/u);
});
