import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { TrustRegistryOperatorSnapshotSchema } from "@midnight-ntwrk/trust-registry-cli";
import type { SequenceToTimestamp } from "@midnight-ntwrk/trust-registry-client";
import type {
  FinalizedRegistryBootstrapReader,
} from "@midnight-ntwrk/trust-registry-integration";

import { assertLocalLedgerEvidenceMatchesSnapshot } from "./local-ledger-projection.js";
import type { TrustRegistryApiStateSource } from "./source.js";

const CONTRACT_ADDRESS = /^0x[0-9a-f]{64}$/u;
const FINALIZED_HASH = /^0x[0-9a-f]{64}$/u;
const SNAPSHOT_SHA256 = /^[0-9a-f]{64}$/u;

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
}): TrustRegistryApiStateSource {
  const address = input.contractAddress.toLowerCase();
  if (!CONTRACT_ADDRESS.test(address) || /^0x0{64}$/u.test(address)) {
    throw new Error("A nonzero deployed local contract address is required");
  }
  const expectedSnapshotSha256 = input.expectedSnapshotSha256.toLowerCase();
  if (!SNAPSHOT_SHA256.test(expectedSnapshotSha256)) {
    throw new Error("An approved snapshot SHA-256 digest is required");
  }
  const addressBytes = Uint8Array.from(Buffer.from(address.slice(2), "hex"));
  return {
    mode: "local-ledger",
    async loadSnapshot() {
      const view = await input.reader.readCurrentFinalizedLedger(address);
      if (view === null) throw new Error("Finalized local Trust Registry ledger is unavailable");
      if (view.networkId !== "undeployed" || view.contractAddress.toLowerCase() !== address
        || !FINALIZED_HASH.test(view.finalizedBlockHash.toLowerCase())
        || /^0x0{64}$/u.test(view.finalizedBlockHash.toLowerCase())) {
        throw new Error("Finalized local Trust Registry view does not match the pinned deployment");
      }
      const raw = await readFile(input.snapshotPath);
      if (createHash("sha256").update(raw).digest("hex") !== expectedSnapshotSha256) {
        throw new Error("Candidate snapshot differs from the approved SHA-256 digest");
      }
      const snapshot = TrustRegistryOperatorSnapshotSchema.parse(JSON.parse(raw.toString("utf8")));
      assertLocalLedgerEvidenceMatchesSnapshot({
        snapshot,
        ledger: view.ledger,
        expectedNetworkId: "undeployed",
        contractAddress: addressBytes,
        sequenceToTimestamp: input.sequenceToTimestamp,
      });
      return snapshot;
    },
  };
}
