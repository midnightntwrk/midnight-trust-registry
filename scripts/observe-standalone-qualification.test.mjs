import assert from "node:assert/strict";
import { test } from "node:test";

import { observeStandaloneQualification } from "./observe-standalone-qualification.mjs";

const source = "a".repeat(40);
const install = { sourceRevision: source, inventorySha256: "b".repeat(64) };
const project = "tr-standalone-local-test";
const networkId = "e".repeat(64);
const contractAddress = `0x${"f".repeat(64)}`;
const genesisHash = `0x${"1".repeat(64)}`;
const status = {
  sourceRevision: source,
  installInventorySha256: install.inventorySha256,
  stackProject: project,
  stackNetworkId: networkId,
  approvedGenesisHash: genesisHash,
  deployedContractAddress: contractAddress,
  releaseQualified: false,
  setupLock: "absent",
  install: "verified-staged-bytes-only",
  stackConfiguration: "observed-ledger-bridge-only",
  localLedger: "operator-pinned-reviewer-signature-verified",
  deployment: "observed",
  stagedVerifierKeys: [{ circuitName: "test", state: "verified" }],
  maintenanceApproval: "deployment-bound-roster-signature-verified-transition-pending",
  maintenanceTransition: "observed",
  maintenanceLastReadback: "observed",
  maintenanceTransitionAlert: null,
};
const query = {
  format: "tr-standalone-current-query-journey-v2",
  sourceRevision: source,
  installInventorySha256: install.inventorySha256,
  networkId,
  apiContainerId: "6".repeat(64),
  planContractAddress: contractAddress,
  planExpectedGenesisHash: genesisHash,
  planSha256: "c".repeat(64),
  selectedStateSha256: "d".repeat(64),
  counts: { issuer: 1, verifier: 1, auditor: 1, recognition: 1 },
  resolvedLookups: { issuer: 1, verifier: 1, auditor: 1, recognition: 1 },
  ambiguousLookups: { issuer: 0, verifier: 0, auditor: 0 },
  apiEgressCanaryDenied: true,
  apiDnsCanaryDenied: true,
  actorJourneys: "not-run",
  hostAndBrowserEgress: "not-verified",
  independentFinality: "not-verified",
  planToDeploymentBinding: "not-verified",
  releaseQualified: false,
};
const restart = {
  format: "tr-standalone-api-restart-observation-v1",
  sourceRevision: source,
  installInventorySha256: install.inventorySha256,
  networkId,
  apiContainerId: query.apiContainerId,
  planSha256: query.planSha256,
  selectedStateSha256: query.selectedStateSha256,
  apiEgressCanaryDenied: true,
  apiDnsCanaryDenied: true,
  releaseQualified: false,
};

function dependencies(overrides = {}) {
  return {
    verifyBundle: async () => install,
    setupStatus: async () => status,
    query: async () => query,
    restart: async () => restart,
    ...overrides,
  };
}

test("pre-deployment status stops before live probes and never claims qualification", async () => {
  let probed = false;
  const report = await observeStandaloneQualification("/setup", "/bundle", source,
    { env: { TR_STACK_NAME: project } },
    dependencies({ setupStatus: async () => ({ ...status, deployment: "pending" }),
      query: async () => { probed = true; return query; } }));
  assert.equal(probed, false);
  assert.deepEqual(report.prerequisites.missing, ["deploymentObserved"]);
  assert.equal(report.currentQuery, "not-run");
  assert.equal(report.releaseQualified, false);
});

test("rejects a bundle from another source before reading setup or runtime", async () => {
  let touchedSetup = false;
  await assert.rejects(observeStandaloneQualification("/setup", "/bundle", source, {},
    dependencies({ verifyBundle: async () => ({ ...install, sourceRevision: "e".repeat(40) }),
      setupStatus: async () => { touchedSetup = true; return status; } })), /does not match/u);
  assert.equal(touchedSetup, false);
});

test("rejects setup inventory, project, network, contract, and genesis mixups", async () => {
  let probed = false;
  const guarded = dependencies({ query: async () => { probed = true; return query; } });
  await assert.rejects(observeStandaloneQualification("/setup", "/bundle", source, {},
    { ...guarded, setupStatus: async () => ({ ...status, installInventorySha256: "0".repeat(64) }) }),
  /inventory differs/u);
  for (const env of [{ TR_STACK_NAME: "tr-standalone-local-other" }, {}]) {
    await assert.rejects(observeStandaloneQualification("/setup", "/bundle", source,
      { env }, guarded), /identity is incomplete/u);
  }
  assert.equal(probed, false);
  for (const mutation of [
    { installInventorySha256: "0".repeat(64) },
    { networkId: "0".repeat(64) },
    { planContractAddress: `0x${"2".repeat(64)}` },
    { planExpectedGenesisHash: `0x${"3".repeat(64)}` },
  ]) {
    await assert.rejects(observeStandaloneQualification("/setup", "/bundle", source,
      { env: { TR_STACK_NAME: project } },
      dependencies({ query: async () => ({ ...query, ...mutation }) })), /disagrees/u);
  }
});

test("observes read-only current queries without an implicit restart", async () => {
  let restarted = false;
  const report = await observeStandaloneQualification("/setup", "/bundle", source,
    { env: { TR_STACK_NAME: project } },
    dependencies({ restart: async () => { restarted = true; return restart; } }));
  assert.equal(restarted, false);
  assert.equal(report.currentQuery, query);
  assert.equal(report.apiRestart, "not-run");
  assert.equal(report.governedActorJourneys, "not-run");
  assert.equal(report.releaseQualified, false);
});

test("rejects child reports that imply unobserved actor, finality, or egress evidence", async () => {
  for (const mutation of [
    { apiEgressCanaryDenied: false },
    { apiDnsCanaryDenied: false },
    { actorJourneys: "observed" },
    { hostAndBrowserEgress: "verified" },
    { independentFinality: "verified" },
    { planToDeploymentBinding: "verified" },
    { ambiguousLookups: undefined },
    { ambiguousLookups: { issuer: 2, verifier: 0, auditor: 0 } },
    { resolvedLookups: { issuer: 1, verifier: 2, auditor: 1, recognition: 1 } },
  ]) {
    await assert.rejects(observeStandaloneQualification("/setup", "/bundle", source,
      { env: { TR_STACK_NAME: project } },
      dependencies({ query: async () => ({ ...query, ...mutation }) })), /disagrees/u);
  }
});

test("opt-in API restart must preserve the observed plan and selected state", async () => {
  const report = await observeStandaloneQualification("/setup", "/bundle", source,
    { apiRestart: true, env: { TR_STACK_NAME: project } }, dependencies());
  assert.equal(report.apiRestart, restart);
  await assert.rejects(observeStandaloneQualification("/setup", "/bundle", source,
    { apiRestart: true, env: { TR_STACK_NAME: project } },
    dependencies({ restart: async () => ({ ...restart, planSha256: "f".repeat(64) }) })),
  /incompatible/u);
  for (const mutation of [{ apiContainerId: "7".repeat(64) },
    { networkId: "8".repeat(64) }, { installInventorySha256: "0".repeat(64) },
    { apiEgressCanaryDenied: false }, { apiDnsCanaryDenied: false }]) {
    await assert.rejects(observeStandaloneQualification("/setup", "/bundle", source,
      { apiRestart: true, env: { TR_STACK_NAME: project } },
      dependencies({ restart: async () => ({ ...restart, ...mutation }) })), /incompatible/u);
  }
});
