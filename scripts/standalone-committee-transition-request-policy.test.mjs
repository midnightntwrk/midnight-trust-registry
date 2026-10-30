import assert from "node:assert/strict";
import { test } from "node:test";

import { parseCommitteeTransitionRequest } from "./standalone-committee-transition-request-policy.mjs";

const revision = "a".repeat(40);
const hash = (digit) => `0x${digit.repeat(64)}`;
const request = () => ({
  format: "tr-local-committee-transition-request-v1",
  sourceRevision: revision,
  bootstrapMaintenanceVerifyingKey: hash("1"),
  expiresAt: "2026-10-28T12:00:00.000Z",
  bootstrap: {
    registryId: "registry:local:one", registryDidCommitment: hash("2"),
    governancePolicyCommitment: hash("3"), maintainerId: hash("4"),
    maintainerDidCommitment: hash("5"), maintainerKeyId: hash("6"),
    maintainerPublicKey: { x: "7", y: "8" }, maintainerThreshold: "1",
  },
  governance: {
    policyCommitment: hash("9"), policyVersion: "2", actionSequence: "4",
    maintainerThreshold: "2", activeMaintainerCount: "3",
  },
});

test("accepts only the exact public transition request for the selected source", () => {
  const input = request();
  assert.equal(parseCommitteeTransitionRequest(input, revision), input);
  assert.throws(() => parseCommitteeTransitionRequest(input, "b".repeat(40)), /source revision/u);
});

test("rejects missing, extra, and NUL-aliased fields at every request level", () => {
  const input = request();
  for (const malformed of [
    { ...input, bootstrap: undefined },
    { ...input, unexpected: true },
    { ...input, ["bootstrap\0governance"]: true },
    { ...input, bootstrap: { ...input.bootstrap, maintainerId: undefined } },
    { ...input, bootstrap: { ...input.bootstrap, ["maintainerId\0maintainerKeyId"]: hash("4") } },
    { ...input, bootstrap: { ...input.bootstrap, maintainerPublicKey: { x: "7" } } },
    { ...input, governance: { ...input.governance, policyVersion: undefined } },
  ]) assert.throws(() => parseCommitteeTransitionRequest(malformed, revision));
});

test("rejects malformed commitments, counters, and expiration before Compact input construction", () => {
  const input = request();
  for (const malformed of [
    { ...input, bootstrapMaintenanceVerifyingKey: null },
    { ...input, expiresAt: "not-a-date" },
    { ...input, bootstrap: { ...input.bootstrap, maintainerId: 7 } },
    { ...input, bootstrap: { ...input.bootstrap, maintainerPublicKey: { x: "07", y: "8" } } },
    { ...input, governance: { ...input.governance, actionSequence: -1 } },
    { ...input, governance: { ...input.governance, policyCommitment: "0x123" } },
  ]) assert.throws(() => parseCommitteeTransitionRequest(malformed, revision));
});
