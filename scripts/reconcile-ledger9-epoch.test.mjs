import assert from "node:assert/strict";
import { test } from "node:test";

import { bytes32Commitment } from "@midnightntwrk/trust-registry-client";
import { computeCreateEpochCommitmentPayloadHash } from "@midnightntwrk/trust-registry-contract";

import {
  assertEpochAttempt,
  parseEpochReconcileArgs,
  reconcileEpochAttempt,
} from "./reconcile-ledger9-epoch.mjs";

const hex = (value) => `0x${Buffer.from(value).toString("hex")}`;
const bytes = (value) => Buffer.from(value.slice(2), "hex");
const h = (byte) => `0x${byte.repeat(64)}`;
const epochId = "epoch:registry:local:seq-5";
const journal = {
  kind: "development-registry-snapshot-epoch-v1",
  sourceRevision: "a".repeat(40),
  genesisHash: h("b"),
  contractAddress: h("c"),
  beforeFinalizedBlockHash: h("d"),
  actionSequence: "5",
  epochId,
  epochIdCommitment: hex(bytes32Commitment(epochId)),
  stateRoot: h("1"),
  eventRoot: h("2"),
  policyRoot: h("3"),
  validUntilSequence: "65",
  actionPayloadHash: "",
  signature: `0x${"4".repeat(192)}`,
};
journal.actionPayloadHash = hex(computeCreateEpochCommitmentPayloadHash(
  bytes(journal.epochIdCommitment), bytes(journal.stateRoot), bytes(journal.eventRoot),
  bytes(journal.policyRoot), 5n, 65n,
));
const submitted = { txId: "a".repeat(66), eventHash: h("5") };
const epoch = {
  idCommitment: journal.epochIdCommitment,
  stateRoot: journal.stateRoot,
  eventRoot: journal.eventRoot,
  policyRoot: journal.policyRoot,
  publicationPolicyCommitment: journal.policyRoot,
  publicationEventHash: submitted.eventHash,
  validFromSequence: "5",
  validUntilSequence: "65",
  publishedAtSequence: "5",
};
const state = {
  genesisHash: journal.genesisHash,
  contractAddress: journal.contractAddress,
  sourceRevision: journal.sourceRevision,
  verifierKeyCatalogMatched: true,
  governanceActionCount: "6",
  selectedEpoch: epoch,
};

test("epoch recovery requires exact paths and a self-consistent one-shot attempt", () => {
  assert.deepEqual(parseEpochReconcileArgs(["--journal", "private.json", "--manifest", "pack.json"]), {
    journalPath: "private.json", manifestPath: "pack.json",
  });
  assert.throws(() => parseEpochReconcileArgs(["--journal", "private.json"]), /required/u);
  assert.throws(() => parseEpochReconcileArgs(["--journal", "a", "--journal", "b",
    "--manifest", "pack.json"]), /Duplicate/u);
  assert.equal(assertEpochAttempt(journal), journal);
  assert.throws(() => assertEpochAttempt({ ...journal, stateRoot: h("6") }), /inconsistent/u);
  assert.throws(() => assertEpochAttempt({ ...journal, epochId: "epoch:other" }), /inconsistent/u);
  assert.throws(() => assertEpochAttempt({ ...journal, signature: h("4") }), /invalid/u);
});

test("epoch recovery matches a finalized historical record, not only the latest epoch", () => {
  assert.deepEqual(reconcileEpochAttempt(journal, submitted, state), {
    status: "finalized-journal-match",
    epochIdCommitment: journal.epochIdCommitment,
    publicationEventHash: submitted.eventHash,
    recordedTxId: submitted.txId,
  });
  assert.equal(reconcileEpochAttempt(journal, null, state).status, "finalized-journal-match");
  assert.throws(() => reconcileEpochAttempt(journal, submitted, {
    ...state, selectedEpoch: { ...epoch, stateRoot: h("7") },
  }), /conflicts/u);
  assert.throws(() => reconcileEpochAttempt(journal, submitted, {
    ...state, selectedEpoch: { ...epoch, publicationPolicyCommitment: h("7") },
  }), /conflicts/u);
  assert.throws(() => reconcileEpochAttempt(journal, submitted, {
    ...state, sourceRevision: "e".repeat(40),
  }), /differs/u);
  assert.throws(() => reconcileEpochAttempt(journal, {
    ...submitted, eventHash: h("8"),
  }, state), /conflicts/u);
});

test("unresolved epoch attempts never invite an automatic resubmission", () => {
  assert.equal(reconcileEpochAttempt(journal, submitted, {
    ...state, selectedEpoch: null,
  }).status, "submitted-unresolved");
  assert.equal(reconcileEpochAttempt(journal, null, {
    ...state, selectedEpoch: null,
  }).status, "reserved-stale-or-ambiguous");
  assert.equal(reconcileEpochAttempt(journal, null, {
    ...state, governanceActionCount: "5", selectedEpoch: null,
  }).status, "reserved-unresolved");
  assert.throws(() => reconcileEpochAttempt(journal, {
    ...submitted, txId: "a".repeat(64),
  }, state), /invalid/u);
});
