import assert from "node:assert/strict";
import { test } from "node:test";

import { sampleSigningKey, signatureVerifyingKey } from "@midnight-ntwrk/compact-runtime";

import {
  canonicalReviewerMetadata, reviewerProposal, validateReleaseCommittee,
} from "./standalone-approval-policy.mjs";

const now = Date.parse("2026-10-27T12:00:00.000Z");
const reviewer = {
  reviewerFingerprint: "A".repeat(40),
  reviewedReference: "chain-spec-sha256:1234567890abcdef",
  approvedAt: new Date(now).toISOString(),
};
const fields = ["reviewerFingerprint", "reviewedReference", "approvedAt"];

test("reviewer metadata requires exact canonical fields and a bounded human review time", () => {
  assert.equal(canonicalReviewerMetadata(reviewer, now - 1000, now), true);
  assert.doesNotThrow(() => reviewerProposal(reviewer, fields, now));
  assert.deepEqual(fields, ["reviewerFingerprint", "reviewedReference", "approvedAt"]);
  for (const proposal of [
    { ...reviewer, reviewedReference: "demo:fixture-chain" },
    { ...reviewer, approvedAt: "2026-10-27T12:00:00Z" },
    { ...reviewer, approvedAt: new Date(now + 5 * 60_000 + 1).toISOString() },
    { ...reviewer, reviewerFingerprint: "a".repeat(40) },
    { ...reviewer, unexpected: true },
    { reviewedReference: reviewer.reviewedReference, approvedAt: reviewer.approvedAt },
    null,
  ]) {
    assert.throws(() => reviewerProposal(proposal, fields, now), /Canonical reviewer metadata/);
  }
});

test("reviewer proposal rejects a delimiter-collided field schema", () => {
  const extendedFields = [...fields, "extensionA", "extensionB"];
  assert.throws(() => reviewerProposal({
    ...reviewer, "extensionA\u0000extensionB": true,
  }, extendedFields, now), /Canonical reviewer metadata/u);
});

test("release committee binds distinct usable keys to distinct custodian roles", () => {
  const keys = Array.from({ length: 3 }, () => `0x${signatureVerifyingKey(sampleSigningKey())}`);
  const policy = { mode: "committee", threshold: 2, verifyingKeys: keys };
  const custodians = keys.map((verifyingKey, index) => ({
    verifyingKey,
    holderRole: `maintainer-${index + 1}`,
    custodyReference: `custody-record-${index + 1}`,
  }));
  assert.doesNotThrow(() => validateReleaseCommittee(policy, custodians));
  assert.throws(() => validateReleaseCommittee({ ...policy, threshold: 1 }, custodians), /multi-party threshold/);
  assert.throws(() => validateReleaseCommittee({ ...policy, verifyingKeys: [keys[0], keys[0], keys[2]] }, custodians), /distinct canonical keys/);
  assert.throws(() => validateReleaseCommittee({ ...policy, threshold: "2" }, custodians), /canonical committee policy/);
  assert.throws(() => validateReleaseCommittee({ ...policy, extra: true }, custodians), /canonical committee policy/);
  assert.throws(() => validateReleaseCommittee(policy, [
    custodians[0], { ...custodians[1], holderRole: custodians[0].holderRole }, custodians[2],
  ]), /distinct holder roles/);
  assert.throws(() => validateReleaseCommittee(policy, [
    custodians[0], { ...custodians[1], verifyingKey: keys[0] }, custodians[2],
  ]), /bind distinct holder roles/);
  assert.throws(() => validateReleaseCommittee(policy, custodians.slice(1)), /bind distinct holder roles/);
});
