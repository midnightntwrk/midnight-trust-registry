import assert from "node:assert/strict";
import test from "node:test";

import { assertApprovedReviewerSignatureStatus } from "../packages/trust-registry-api/src/local-reviewer-signature.ts";
import { assertDetachedReviewerSignatureStatus } from "./standalone-setup-wizard.mjs";
import { approvedMappingSigner } from "./verify-helm-mapping-signature.mjs";

const signer = "A".repeat(40);
const primary = "B".repeat(40);
const now = Date.now();
const signedAt = Math.floor(now / 1000) - 30;
const approvedAt = new Date((signedAt - 60) * 1000).toISOString();
const valid = `[GNUPG:] VALIDSIG ${signer} 2026-10-20 ${signedAt} 0 4 0 22 8 00 ${primary}\n`;
const good = `[GNUPG:] GOODSIG ${signer.slice(-16)} Reviewer\n`;
const status = `${good}${valid}`;

function acceptedByAll(output, fingerprint = primary) {
  const checks = [
    () => assertApprovedReviewerSignatureStatus(output, 0, fingerprint, now),
    () => assertDetachedReviewerSignatureStatus(output, fingerprint, approvedAt, now),
    () => approvedMappingSigner(output, fingerprint, now),
  ];
  return checks.map((check) => {
    try {
      check();
      return true;
    } catch {
      return false;
    }
  });
}

test("wizard, API, and Helm agree on pinned primary and signing subkey", () => {
  assert.deepEqual(acceptedByAll(status), [true, true, true]);
  assert.deepEqual(acceptedByAll(status, signer), [false, false, false]);
});

test("wizard, API, and Helm reject the same adversarial detached statuses", () => {
  for (const output of [
    valid,
    `${status}${valid}`,
    `${status}${good}`,
    status.replace(" 22 8 00 ", " 22 2 00 "),
    status.replace(" 22 8 00 ", " 22 8 01 "),
    status.replace(` ${primary}`, ` ${"C".repeat(40)}`),
    status.replace(`${signedAt} 0`, `${signedAt} ${signedAt - 1}`),
    `${status}[GNUPG:] REVKEYSIG ${signer}\n`,
    `${status}[GNUPG:] PLAINTEXT_LENGTH 10\n`,
  ]) {
    assert.deepEqual(acceptedByAll(output), [false, false, false], output);
  }
});
