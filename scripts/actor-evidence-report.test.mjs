import assert from "node:assert/strict";
import test from "node:test";

import { buildActorEvidenceReport } from "./actor-evidence-report.mjs";

const roles = ["issuer", "verifier", "auditor", "recognition", "maintainer"];
const actors = () => roles.map((role) => ({
  role,
  policyVersion: "v1",
  epochId: `epoch:${role}`,
  epochSource: role === "maintainer" ? "membership-snapshot" : "active-evidence",
  activationSignerKeyIds: [`0x${"1".repeat(64)}`, `0x${"2".repeat(64)}`],
  expectedResult: "active",
  observedResult: "active",
}));
const matrix = () => ({
  format: "tr-adversarial-matrix-v1",
  cases: roles.map((role) => ({
    id: `${role}-wrong-scope`,
    expected: "rejected",
    observed: "matched:Error",
  })),
});

test("exports one redacted positive and rule-specific negative for every actor", () => {
  const input = actors();
  input[0].presentation = { holderSecret: "private-vp-data" };
  const report = buildActorEvidenceReport(input, matrix());
  assert.equal(report.format, "tr-actor-evidence-report-v1");
  assert.deepEqual(report.actors.map((actor) => actor.role), roles);
  assert.deepEqual(report.actors[0].rejectionCaseIds, ["issuer-wrong-scope"]);
  assert.equal(JSON.stringify(report).includes("private-vp-data"), false);
  assert.equal(report.actors[4].epochSource, "membership-snapshot");
});

test("refuses missing actors, duplicate signers, and missing negative coverage", () => {
  assert.throws(() => buildActorEvidenceReport(actors().slice(1), matrix()), /Every governed actor/);
  const duplicate = actors();
  duplicate[0].activationSignerKeyIds[1] = duplicate[0].activationSignerKeyIds[0];
  assert.throws(() => buildActorEvidenceReport(duplicate, matrix()), /duplicate signer/);
  const noAuditorNegative = matrix();
  noAuditorNegative.cases = noAuditorNegative.cases.filter((entry) => !entry.id.startsWith("auditor-"));
  assert.throws(() => buildActorEvidenceReport(actors(), noAuditorNegative), /auditor: no rule-specific rejection/);
});

test("refuses observed outcomes that diverge from the expected grant state", () => {
  const input = actors();
  input[2].observedResult = "suspended";
  assert.throws(() => buildActorEvidenceReport(input, matrix()), /auditor: decision mismatch/);
});
