import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";

import { TrustRegistryOperatorSnapshotSchema } from "@midnight-ntwrk/trust-registry-cli";
import { bytes32Commitment, type SequenceToTimestamp } from "@midnight-ntwrk/trust-registry-client";
import type { Ledger } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import type {
  FinalizedRegistryBootstrapReader,
} from "@midnight-ntwrk/trust-registry-integration";

import { assertLocalLedgerEvidenceMatchesSnapshot } from "./local-ledger-projection.js";
import type { FinalizedProposalLedgerReader } from "./compact-proposal-observation.js";
import type { TrustRegistryApiCurrentLedgerSelection, TrustRegistryApiStateSource } from "./source.js";

const CONTRACT_ADDRESS = /^0x[0-9a-f]{64}$/u;
const FINALIZED_HASH = /^0x[0-9a-f]{64}$/u;
const SNAPSHOT_SHA256 = /^[0-9a-f]{64}$/u;
const MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024;
const DEFAULT_READ_TIMEOUT_MS = 15_000;
const FINALIZED_READ_RETRY_DELAY_MS = 1_000;
const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;

function selectedIds<T>(entries: readonly T[], idOf: (entry: T) => string,
  index: Iterable<[Uint8Array, Uint8Array]>): ReadonlySet<string> {
  const byCommitment = new Map(entries.map((entry) => {
    const id = idOf(entry);
    return [hex(bytes32Commitment(id)), id];
  }));
  const selected = new Set<string>();
  for (const [, idBytes] of index) {
    const id = byCommitment.get(hex(idBytes));
    if (id === undefined) throw new Error("Finalized current ID is absent from the verified snapshot");
    selected.add(id);
  }
  return selected;
}

function currentSelection(snapshot: TrustRegistryApiCurrentLedgerSelection["snapshot"],
  ledger: Ledger,
): TrustRegistryApiCurrentLedgerSelection {
  return {
    snapshot,
    authorizationIds: {
      issuer: selectedIds(snapshot.issuerEntries, (entry) => entry.authorization.authorizationId,
        ledger.currentIssuerAuthorizationIdsByScopeKey),
      verifier: selectedIds(snapshot.verifierEntries, (entry) => entry.authorization.authorizationId,
        ledger.currentVerifierAuthorizationIdsByScopeKey),
      auditor: selectedIds(snapshot.auditorEntries, (entry) => entry.authorization.authorizationId,
        ledger.currentAuditorAuthorizationIdsByScopeKey),
    },
    recognitionIds: selectedIds(snapshot.recognitionEntries, (entry) => entry.recognition.recognitionId,
      ledger.currentRecognitionIdsByScopeKey),
  };
}

export class LocalLedgerSourceUnavailableError extends Error {
  constructor(cause: unknown) {
    super("Finalized local Trust Registry state is unavailable", { cause });
    this.name = "LocalLedgerSourceUnavailableError";
  }
}

class FinalizedReadNotReadyError extends Error {
  constructor() {
    super("Finalized local ledger checkpoint is not yet readable");
  }
}

async function readBoundedSnapshot(path: string): Promise<Buffer> {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.size === 0n || before.size > BigInt(MAX_SNAPSHOT_BYTES)) {
      throw new Error("Pinned local snapshot must be a bounded regular file");
    }
    const bytes = Buffer.alloc(Number(before.size));
    let count = 0;
    while (count < bytes.length) {
      const result = await file.read(bytes, count, bytes.length - count, count);
      if (result.bytesRead === 0) break;
      count += result.bytesRead;
    }
    const after = await file.stat({ bigint: true });
    if (count !== bytes.length || after.size !== before.size || after.dev !== before.dev
      || after.ino !== before.ino || after.nlink !== before.nlink || after.mode !== before.mode
      || after.uid !== before.uid || after.mtimeNs !== before.mtimeNs
      || after.ctimeNs !== before.ctimeNs) {
      throw new Error("Pinned local snapshot changed during read");
    }
    return bytes;
  } finally {
    await file.close();
  }
}

/**
 * The injected reader must pin an independently approved local genesis and authenticate
 * each finalized checkpoint. The timestamp mapper must be derived from trusted ledger
 * history, not from the candidate snapshot or an indexer claim.
 */
export function createLocalLedgerBoundSource(input: {
  snapshotPath: string;
  /** An independently approved digest of the exact serialized snapshot file. */
  expectedSnapshotSha256: string;
  contractAddress: string;
  reader: Pick<FinalizedRegistryBootstrapReader, "readCurrentFinalizedLedger">;
  sequenceToTimestamp: SequenceToTimestamp;
  readTimeoutMs?: number;
}): TrustRegistryApiStateSource & {
  loadCurrentLedgerSelection(): Promise<TrustRegistryApiCurrentLedgerSelection>;
  readFinalizedProposalLedger: FinalizedProposalLedgerReader;
} {
  const address = input.contractAddress.toLowerCase();
  if (!CONTRACT_ADDRESS.test(address) || /^0x0{64}$/u.test(address)) {
    throw new Error("A nonzero deployed local contract address is required");
  }
  const expectedSnapshotSha256 = input.expectedSnapshotSha256.toLowerCase();
  if (!SNAPSHOT_SHA256.test(expectedSnapshotSha256)) {
    throw new Error("An approved snapshot SHA-256 digest is required");
  }
  const readTimeoutMs = input.readTimeoutMs ?? DEFAULT_READ_TIMEOUT_MS;
  if (!Number.isSafeInteger(readTimeoutMs) || readTimeoutMs < 1 || readTimeoutMs > 30_000) {
    throw new Error("Local finalized read timeout must be between 1 and 30000 milliseconds");
  }
  const addressBytes = Uint8Array.from(Buffer.from(address.slice(2), "hex"));
  const readVerifiedState = async () => {
    try {
      const view = await input.reader.readCurrentFinalizedLedger(address);
      if (view === null) throw new FinalizedReadNotReadyError();
      if (view.networkId !== "undeployed" || view.contractAddress.toLowerCase() !== address
        || !FINALIZED_HASH.test(view.finalizedBlockHash.toLowerCase())
        || /^0x0{64}$/u.test(view.finalizedBlockHash.toLowerCase())) {
        throw new Error("Finalized local Trust Registry view does not match the pinned deployment");
      }
      const raw = await readBoundedSnapshot(input.snapshotPath);
      if (createHash("sha256").update(raw).digest("hex") !== expectedSnapshotSha256) {
        throw new Error("Candidate snapshot differs from the approved SHA-256 digest");
      }
      const snapshotJson = raw.toString("utf8");
      const parsed: unknown = JSON.parse(snapshotJson);
      if (snapshotJson !== `${JSON.stringify(parsed, null, 2)}\n`) {
        throw new Error("Pinned local snapshot must use the CLI canonical JSON format");
      }
      const snapshot = TrustRegistryOperatorSnapshotSchema.parse(parsed);
      assertLocalLedgerEvidenceMatchesSnapshot({
        snapshot,
        ledger: view.ledger,
        expectedNetworkId: "undeployed",
        contractAddress: addressBytes,
        sequenceToTimestamp: input.sequenceToTimestamp,
      });
      return { snapshot, ledger: view.ledger, selection: currentSelection(snapshot, view.ledger) };
    } catch (cause) {
      throw new LocalLedgerSourceUnavailableError(cause);
    }
  };
  let requiresRestart = false;
  let retryNotBefore = 0;
  let pendingRead: ReturnType<typeof readVerifiedState> | undefined;
  const readBoundState = () => {
    if (requiresRestart) {
      return Promise.reject(new LocalLedgerSourceUnavailableError(
        new Error("Local finalized read failed; operator restart is required")));
    }
    if (pendingRead) return pendingRead;
    if (Date.now() < retryNotBefore) {
      return Promise.reject(new LocalLedgerSourceUnavailableError(
        new Error("Finalized reader retry is cooling down")));
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        // A provider without cancellation may still be running; never start another read after its timeout.
        requiresRestart = true;
        reject(new LocalLedgerSourceUnavailableError(new Error("Finalized reader timed out")));
      }, readTimeoutMs);
    });
    pendingRead = Promise.race([readVerifiedState(), deadline]).catch((error: unknown) => {
      if (error instanceof LocalLedgerSourceUnavailableError
        && error.cause instanceof FinalizedReadNotReadyError) {
        retryNotBefore = Date.now() + FINALIZED_READ_RETRY_DELAY_MS;
      } else {
        requiresRestart = true;
      }
      throw error;
    }).finally(() => {
      if (timer) clearTimeout(timer);
      pendingRead = undefined;
    });
    return pendingRead;
  };
  return {
    mode: "local-ledger",
    async loadSnapshot() {
      return (await readBoundState()).snapshot;
    },
    async loadCurrentLedgerSelection() {
      return (await readBoundState()).selection;
    },
    async readFinalizedProposalLedger() {
      return (await readBoundState()).ledger;
    },
  };
}
