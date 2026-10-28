import assert from "node:assert/strict";
import { test } from "node:test";

import { observeStandaloneCurrentQueryJourney } from "./check-standalone-current-query-journey.mjs";

const sourceRevision = "a".repeat(40);
const status = {
  sourceRevision,
  releaseQualified: false,
  stackProject: "local-registry-test",
  stackNetworkId: "1".repeat(64),
  installInventorySha256: "2".repeat(64),
  setupLock: "absent",
  install: "verified-staged-bytes-only",
  stackConfiguration: "observed-ledger-bridge-only",
  localLedger: "operator-pinned-reviewer-signature-verified",
  approvedGenesisHash: `0x${"f".repeat(64)}`,
  deployment: "observed",
  deployedContractAddress: `0x${"a".repeat(64)}`,
  stagedVerifierKeys: [{ circuitName: "test", state: "verified" }],
  maintenanceApproval: "deployment-bound-roster-signature-verified-transition-pending",
  maintenanceTransition: "observed",
  maintenanceLastReadback: "observed",
  maintenanceTransitionAlert: null,
};
const roles = { issuer: 1, verifier: 1, auditor: 1, recognition: 1 };
const read = {
  format: "tr-standalone-api-current-read-probe-v4",
  sourceRevision,
  releaseQualified: false,
  routeReadback: "same-container-signed-plan-current-only",
  planSha256: "b".repeat(64),
  planContractAddress: `0x${"a".repeat(64)}`,
  planExpectedGenesisHash: `0x${"f".repeat(64)}`,
  selectedStateSha256: "e".repeat(64),
  sourceFinalizedBlockHash: `0x${"c".repeat(64)}`,
  registryId: "registry-1",
  currentEpochId: "epoch-1",
  apiContainerId: "d".repeat(64),
  apiStartedAt: "2026-01-01T00:00:00Z",
  apiRestartCount: 0,
  networkId: status.stackNetworkId,
  installInventorySha256: status.installInventorySha256,
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

const env = { TR_STACK_NAME: status.stackProject };

test("combines two live current reads around the API egress probe without release claims", async () => {
  let reads = 0;
  const result = await observeStandaloneCurrentQueryJourney("/setup", "/bundle", env,
    dependencies({ read: async () => { reads += 1; return read; } }));
  assert.equal(reads, 2);
  assert.equal(result.format, "tr-standalone-current-query-journey-v2");
  assert.equal(result.selectedStateSha256, read.selectedStateSha256);
  assert.equal(result.planContractAddress, read.planContractAddress);
  assert.equal(result.planExpectedGenesisHash, read.planExpectedGenesisHash);
  assert.deepEqual(result.resolvedLookups, roles);
  assert.equal(result.actorJourneys, "not-run");
  assert.equal(result.independentFinality, "not-verified");
  assert.equal(result.releaseQualified, false);
});

test("missing wizard approval stops before touching the running API", async () => {
  let called = false;
  await assert.rejects(observeStandaloneCurrentQueryJourney("/setup", "/bundle", env,
    dependencies({ setupStatus: async () => ({ ...status, localLedger: "pending" }),
      read: async () => { called = true; return read; } })), /genesisApproved/u);
  assert.equal(called, false);
});

test("signed API runtime must match wizard-approved install, genesis, deployment, and network before egress", async () => {
  for (const mismatch of [
    { approvedGenesisHash: `0x${"e".repeat(64)}` },
    { deployedContractAddress: `0x${"e".repeat(64)}` },
    { stackNetworkId: "e".repeat(64) },
    { installInventorySha256: "e".repeat(64) },
  ]) {
    let egressCalled = false;
    await assert.rejects(observeStandaloneCurrentQueryJourney("/setup", "/bundle", env,
      dependencies({
        setupStatus: async () => ({ ...status, ...mismatch }),
        egress: async () => { egressCalled = true; return egress; },
      })), /differs from the approved wizard install, deployment, genesis, or network/u);
    assert.equal(egressCalled, false);
  }
});

test("selected API project and wizard install identity fail before runtime reads", async () => {
  for (const mismatch of [{ stackProject: "other-project" },
    { installInventorySha256: "bad" }]) {
    let readCalled = false;
    await assert.rejects(observeStandaloneCurrentQueryJourney("/setup", "/bundle", env,
      dependencies({
        setupStatus: async () => ({ ...status, ...mismatch }),
        read: async () => { readCalled = true; return read; },
      })), /Approved wizard install, project, or network differs/u);
    assert.equal(readCalled, false);
  }
});

test("rejects an empty or mocked actor selection", async () => {
  await assert.rejects(observeStandaloneCurrentQueryJourney("/setup", "/bundle", env,
    dependencies({ read: async () => ({ ...read, resolvedLookups: { ...roles, issuer: 0 } }) })),
  /no resolved actor role/u);
});

test("rejects missing process identity on either side of the egress probe", async () => {
  for (const mutation of [{ apiStartedAt: undefined }, { apiRestartCount: undefined }]) {
    for (const badRead of [1, 2]) {
      let reads = 0;
      await assert.rejects(observeStandaloneCurrentQueryJourney("/setup", "/bundle", env,
        dependencies({ read: async () => {
          reads += 1;
          return reads === badRead ? { ...read, ...mutation } : read;
        } })), /process identity is incomplete/u);
    }
  }
});

test("rejects egress denial without positive controls", async () => {
  await assert.rejects(observeStandaloneCurrentQueryJourney("/setup", "/bundle", env,
    dependencies({ egress: async () => ({ ...egress, bridgeDnsCanaryReachable: false }) })),
  /egress probe/u);
});

test("rejects a swapped signed plan, selected state, or API container between reads", async () => {
  for (const [mutation, expectedError] of [
    [{ planSha256: "e".repeat(64) }, /changed during egress probe/u],
    [{ planContractAddress: `0x${"e".repeat(64)}` }, /differs from the approved wizard/u],
    [{ planExpectedGenesisHash: `0x${"d".repeat(64)}` }, /differs from the approved wizard/u],
    [{ installInventorySha256: "d".repeat(64) }, /differs from the approved wizard/u],
    [{ selectedStateSha256: "f".repeat(64) }, /changed during egress probe/u],
    [{ apiContainerId: "f".repeat(64) }, /changed during egress probe/u],
  ]) {
    let reads = 0;
    await assert.rejects(observeStandaloneCurrentQueryJourney("/setup", "/bundle", env,
      dependencies({ read: async () => { reads += 1; return reads === 1 ? read : { ...read, ...mutation }; } })),
    expectedError);
  }
});

test("rejects role count drift between reads", async () => {
  let reads = 0;
  await assert.rejects(observeStandaloneCurrentQueryJourney("/setup", "/bundle", env,
    dependencies({ read: async () => { reads += 1; return reads === 1 ? read
      : { ...read, counts: { ...roles, verifier: 2 } }; } })), /changed during egress probe/u);
});
