import assert from "node:assert/strict";
import { test } from "node:test";

import { ACCEPTANCE_CASES, parseStandaloneAcceptanceManifest } from "./standalone-acceptance-manifest-policy.mjs";

const valid = () => ({
  format: "tr-standalone-acceptance-evidence-v1",
  sourceRevision: "a".repeat(40),
  installInventorySha256: "b".repeat(64),
  signedPlanSha256: "c".repeat(64),
  genesisHash: `0x${"d".repeat(64)}`,
  contractAddress: `0x${"e".repeat(64)}`,
  cases: Object.fromEntries(ACCEPTANCE_CASES.map((id) => [id, { status: "not-run", evidence: [] }])),
});

test("acceptance manifest shape rejects missing, extra and placeholder identity fields", () => {
  assert.equal(parseStandaloneAcceptanceManifest(valid()).cases.L01.status, "not-run");
  for (const changed of [
    { ...valid(), sourceRevision: "0".repeat(40) },
    { ...valid(), installInventorySha256: "0".repeat(64) },
    { ...valid(), signedPlanSha256: "0".repeat(64) },
    { ...valid(), genesisHash: `0x${"0".repeat(64)}` },
    { ...valid(), extra: true },
    { ...valid(), cases: { ...valid().cases, L01: undefined } },
  ]) assert.throws(() => parseStandaloneAcceptanceManifest(changed));
});

test("acceptance manifest shape rejects malformed case and evidence entries", () => {
  for (const entry of [
    { status: "ready", evidence: [] },
    { status: "pass" },
    { status: "not-run", evidence: [{ path: "raw.log", sha256: "bad" }] },
    { status: "not-run", evidence: [{ path: 123, sha256: "a".repeat(64) }] },
    { status: "not-run", evidence: [], extra: true },
  ]) assert.throws(() => parseStandaloneAcceptanceManifest({
    ...valid(), cases: { ...valid().cases, L01: entry },
  }));
});
