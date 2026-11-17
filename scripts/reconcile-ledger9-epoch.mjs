import { lstat, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import { computeCreateEpochCommitmentPayloadHash } from "@midnight-ntwrk/trust-registry-contract";

import { readLedger9Registry } from "./read-ledger9-registry.mjs";

const HEX32 = /^0x[0-9a-f]{64}$/u;
const SIGNATURE = /^0x[0-9a-f]{192}$/u;
const TX_ID = /^[0-9a-f]{66}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const hex = (value) => `0x${Buffer.from(value).toString("hex")}`;
const bytes = (value) => Buffer.from(value.slice(2), "hex");

export function parseEpochReconcileArgs(args) {
  let journalPath;
  let manifestPath;
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!value || !["--journal", "--manifest"].includes(flag)) {
      throw new Error("Usage: reconcile-ledger9-epoch.mjs --journal path --manifest path");
    }
    if (flag === "--journal" && journalPath === undefined) journalPath = value;
    else if (flag === "--manifest" && manifestPath === undefined) manifestPath = value;
    else throw new Error(`Duplicate option: ${flag}`);
  }
  if (!journalPath || !manifestPath) {
    throw new Error("An epoch journal and source-matched manifest are required");
  }
  return { journalPath, manifestPath };
}

async function readPrivateJson(path, optional = false) {
  let stat;
  try {
    stat = await lstat(path);
  } catch (error) {
    if (optional && error?.code === "ENOENT") return null;
    throw error;
  }
  if (!stat.isFile() || stat.size < 2 || stat.size > 64 * 1024 || (stat.mode & 0o077) !== 0) {
    throw new Error("Epoch journal must be a bounded private regular file");
  }
  return JSON.parse(await readFile(path, "utf8"));
}

export function assertEpochAttempt(journal) {
  if (journal === null || typeof journal !== "object" || Array.isArray(journal)
    || journal.kind !== "development-registry-snapshot-epoch-v1"
    || !/^[0-9a-f]{40}$/u.test(journal.sourceRevision)
    || ![journal.genesisHash, journal.contractAddress, journal.beforeFinalizedBlockHash,
      journal.epochIdCommitment, journal.stateRoot, journal.eventRoot, journal.policyRoot,
      journal.actionPayloadHash].every((value) => HEX32.test(value))
    || !SIGNATURE.test(journal.signature)
    || typeof journal.epochId !== "string" || journal.epochId.length > 256
    || !DECIMAL.test(journal.actionSequence) || !DECIMAL.test(journal.validUntilSequence)
    || BigInt(journal.validUntilSequence) <= BigInt(journal.actionSequence)) {
    throw new Error("Epoch attempt journal is invalid");
  }
  if (hex(bytes32Commitment(journal.epochId)) !== journal.epochIdCommitment
    || hex(computeCreateEpochCommitmentPayloadHash(
      bytes(journal.epochIdCommitment), bytes(journal.stateRoot),
      bytes(journal.eventRoot), bytes(journal.policyRoot),
      BigInt(journal.actionSequence), BigInt(journal.validUntilSequence),
    )) !== journal.actionPayloadHash) {
    throw new Error("Epoch attempt journal has inconsistent commitments");
  }
  return journal;
}

export function reconcileEpochAttempt(journal, submitted, state) {
  const attempt = assertEpochAttempt(journal);
  if (state.genesisHash !== attempt.genesisHash
    || state.contractAddress !== attempt.contractAddress
    || state.sourceRevision !== attempt.sourceRevision
    || state.verifierKeyCatalogMatched !== true) {
    throw new Error("Finalized chain, contract, or source manifest differs from the attempt");
  }
  if (submitted !== null && (typeof submitted !== "object" || Array.isArray(submitted)
    || !TX_ID.test(submitted.txId) || !HEX32.test(submitted.eventHash))) {
    throw new Error("Epoch submission receipt is invalid");
  }
  const epoch = state.selectedEpoch;
  if (epoch === null) {
    return {
      status: submitted !== null ? "submitted-unresolved"
        : BigInt(state.governanceActionCount) > BigInt(attempt.actionSequence)
          ? "reserved-stale-or-ambiguous" : "reserved-unresolved",
      epochIdCommitment: attempt.epochIdCommitment,
      recordedTxId: submitted?.txId ?? null,
    };
  }
  if (epoch === undefined || epoch.idCommitment !== attempt.epochIdCommitment
    || epoch.stateRoot !== attempt.stateRoot || epoch.eventRoot !== attempt.eventRoot
    || epoch.policyRoot !== attempt.policyRoot
    || epoch.publicationPolicyCommitment !== attempt.policyRoot
    || epoch.validFromSequence !== attempt.actionSequence
    || epoch.validUntilSequence !== attempt.validUntilSequence
    || epoch.publishedAtSequence !== attempt.actionSequence
    || (submitted !== null && epoch.publicationEventHash !== submitted.eventHash)) {
    throw new Error("Finalized epoch conflicts with the one-shot journal");
  }
  return {
    status: "finalized-journal-match",
    epochIdCommitment: attempt.epochIdCommitment,
    publicationEventHash: epoch.publicationEventHash,
    recordedTxId: submitted?.txId ?? null,
  };
}

export async function reconcileLedger9Epoch(args = process.argv.slice(2), env = process.env) {
  const { journalPath, manifestPath } = parseEpochReconcileArgs(args);
  const journal = assertEpochAttempt(await readPrivateJson(journalPath));
  const submitted = await readPrivateJson(`${journalPath}.submitted`, true);
  const state = await readLedger9Registry([
    "--address", journal.contractAddress,
    "--epoch-id", journal.epochIdCommitment,
    "--manifest", manifestPath,
  ], env);
  return reconcileEpochAttempt(journal, submitted, state);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const result = await reconcileLedger9Epoch();
    console.log(JSON.stringify(result));
    if (result.status !== "finalized-journal-match") process.exitCode = 2;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
