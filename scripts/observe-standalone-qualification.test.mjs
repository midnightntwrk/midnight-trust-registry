import assert from "node:assert/strict";
import { test } from "node:test";

import { observeStandaloneQualification } from "./observe-standalone-qualification.mjs";

const source = "a".repeat(40);
const install = { sourceRevision: source, inventorySha256: "b".repeat(64) };
const status = {
  sourceRevision: source,
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
const query = {
  format: "tr-standalone-current-query-journey-v2",
  sourceRevision: source,
  planSha256: "c".repeat(64),
  selectedStateSha256: "d".repeat(64),
  releaseQualified: false,
};
const restart = {
  format: "tr-standalone-api-restart-observation-v1",
  sourceRevision: source,
  planSha256: query.planSha256,
  selectedStateSha256: query.selectedStateSha256,
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
  const report = await observeStandaloneQualification("/setup", "/bundle", source, {},
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

test("observes read-only current queries without an implicit restart", async () => {
  let restarted = false;
  const report = await observeStandaloneQualification("/setup", "/bundle", source, {},
    dependencies({ restart: async () => { restarted = true; return restart; } }));
  assert.equal(restarted, false);
  assert.equal(report.currentQuery, query);
  assert.equal(report.apiRestart, "not-run");
  assert.equal(report.governedActorJourneys, "not-run");
  assert.equal(report.releaseQualified, false);
});

test("opt-in API restart must preserve the observed plan and selected state", async () => {
  const report = await observeStandaloneQualification("/setup", "/bundle", source,
    { apiRestart: true }, dependencies());
  assert.equal(report.apiRestart, restart);
  await assert.rejects(observeStandaloneQualification("/setup", "/bundle", source,
    { apiRestart: true }, dependencies({ restart: async () => ({ ...restart, planSha256: "f".repeat(64) }) })),
  /incompatible/u);
});
