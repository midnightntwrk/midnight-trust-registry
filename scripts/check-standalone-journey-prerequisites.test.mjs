import assert from "node:assert/strict";
import test from "node:test";

import { assessStandaloneJourneyPrerequisites } from "./check-standalone-journey-prerequisites.mjs";

const approved = {
  sourceRevision: "a".repeat(40), releaseQualified: false,
  setupLock: "absent", install: "verified-staged-bytes-only",
  stackConfiguration: "observed-ledger-bridge-only",
  localLedger: "operator-pinned-reviewer-signature-verified",
  approvedGenesisHash: `0x${"1".repeat(64)}`,
  deployment: "observed", stagedVerifierKeys: [{ circuitName: "test", state: "verified" }],
  deployedContractAddress: `0x${"2".repeat(64)}`,
  maintenanceApproval: "deployment-bound-roster-signature-verified-transition-pending",
  maintenanceTransition: "observed", maintenanceLastReadback: "observed",
  maintenanceTransitionAlert: null,
};

test("only reports wizard ledger prerequisites, never actor or release qualification", () => {
  const report = assessStandaloneJourneyPrerequisites(approved);
  assert.equal(report.ledgerPrerequisitesObserved, true);
  assert.deepEqual(report.missing, []);
  assert.deepEqual(report.nextActions, []);
  assert.equal(report.actorJourney, "not-run");
  assert.equal(report.completeVerifierKeyInventory, "not-verified");
  assert.equal(report.independentFinality, "not-verified");
  assert.equal(report.releaseQualified, false);
});

test("fails closed for missing approval, unresolved key or alert", () => {
  const report = assessStandaloneJourneyPrerequisites({
    ...approved, localLedger: "node-observed-not-independently-approved",
    stagedVerifierKeys: [{ circuitName: "test", state: "pending" }],
    maintenanceTransitionAlert: "conflict",
  });
  assert.equal(report.ledgerPrerequisitesObserved, false);
  assert.deepEqual(report.missing, ["genesisApproved", "recordedKeyInsertionsReconciled", "maintenanceObserved"]);
  assert.deepEqual(report.nextActions.map(({ gate }) => gate), report.missing);
  assert.match(report.nextActions[0].action, /Independently review the real chain specification/u);
});

test("empty key evidence and active setup lock block the journey", () => {
  const report = assessStandaloneJourneyPrerequisites({
    ...approved, stagedVerifierKeys: [], setupLock: "present-inspect-before-removal",
  });
  assert.deepEqual(report.missing, ["setupUnlocked", "recordedKeyInsertionsReconciled"]);
});

test("approval labels without pinned identities cannot open the actor prerequisite gate", () => {
  for (const value of [null, undefined, "bad", `0x${"0".repeat(64)}`]) {
    const missingGenesis = assessStandaloneJourneyPrerequisites({ ...approved, approvedGenesisHash: value });
    assert.deepEqual(missingGenesis.missing, ["genesisApproved"]);
    const missingContract = assessStandaloneJourneyPrerequisites({ ...approved, deployedContractAddress: value });
    assert.deepEqual(missingContract.missing, ["deploymentObserved"]);
  }
});

test("candidate source revision must match the retained install setup", () => {
  const matching = assessStandaloneJourneyPrerequisites(approved, "a".repeat(40));
  assert.equal(matching.expectedSourceRevision, "a".repeat(40));
  assert.equal(matching.gates.sourceMatchesCandidate, true);
  assert.equal(matching.ledgerPrerequisitesObserved, true);

  const stale = assessStandaloneJourneyPrerequisites(approved, "b".repeat(40));
  assert.equal(stale.gates.sourceMatchesCandidate, false);
  assert.deepEqual(stale.missing, ["sourceMatchesCandidate"]);
  assert.match(stale.nextActions[0].action, /never reuse an older setup/u);
  assert.equal(stale.ledgerPrerequisitesObserved, false);
  assert.throws(() => assessStandaloneJourneyPrerequisites(approved, "bad"),
    /Expected candidate source revision/u);
});

test("rejects malformed status rather than implying a clean run", () => {
  assert.throws(() => assessStandaloneJourneyPrerequisites({ ...approved, releaseQualified: true }),
    /Invalid standalone wizard status/u);
  assert.throws(() => assessStandaloneJourneyPrerequisites({ ...approved, sourceRevision: "bad" }),
    /Invalid standalone wizard status/u);
  assert.throws(() => assessStandaloneJourneyPrerequisites(null),
    /Invalid standalone wizard status/u);
  assert.throws(() => assessStandaloneJourneyPrerequisites({ ...approved, stagedVerifierKeys: undefined }),
    /Invalid standalone wizard status/u);
  assert.throws(() => assessStandaloneJourneyPrerequisites({ ...approved, sourceRevision: 42 }),
    /Invalid standalone wizard status/u);
});

test("malformed or duplicate verifier-key evidence cannot satisfy the recorded-insertions gate", () => {
  for (const stagedVerifierKeys of [[null], ["verified"], [{}], [{ state: "pending" }],
    [{ state: "verified" }], [{ circuitName: "test", state: "verified" },
      { circuitName: "test", state: "verified" }]]) {
    const report = assessStandaloneJourneyPrerequisites({ ...approved, stagedVerifierKeys });
    assert.deepEqual(report.missing, ["recordedKeyInsertionsReconciled"]);
    assert.equal(report.ledgerPrerequisitesObserved, false);
    assert.equal(report.releaseQualified, false);
  }
});
