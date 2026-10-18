import type {
  FinalizedRegistryDecisionSnapshot,
  TrustedDecisionEvidenceReaders,
} from "@midnight-ntwrk/trust-registry-client";
import type { DecisionEvidenceSelection } from "@midnight-ntwrk/trust-registry-domain";

import { createCompactLedgerDecisionReaders } from "./compact-decision-reader.js";
import type { FinalizedRegistryLedgerView } from "./finalized-deployment-action-reader.js";

type Selection = Omit<DecisionEvidenceSelection, "evaluationTime">;

/** The publication port must authenticate historical signers at the pinned checkpoint. */
export function createCheckpointedCompactDecisionReaders(input: {
  readCurrentFinalizedLedger(contractAddress: string): Promise<FinalizedRegistryLedgerView | null>;
  readAuthenticatedEpochPublication(
    selection: Selection,
    epochIdHint: string,
    finalizedBlockHash: string,
  ): Promise<Pick<FinalizedRegistryDecisionSnapshot, "acceptedEpoch" | "publication"> | null>;
  readEvaluationTime(): string;
  sequenceToTimestamp(sequence: bigint): string;
  readFinalizedDidState: TrustedDecisionEvidenceReaders["readCurrentFinalizedDidState"];
}): TrustedDecisionEvidenceReaders {
  return createCompactLedgerDecisionReaders({
    readFinalizedView: async (selection, epochIdHint) => {
      const observed = await input.readCurrentFinalizedLedger(selection.contractAddress);
      if (observed === null) return null;
      if (observed.networkId !== selection.networkId
        || observed.contractAddress !== selection.contractAddress.toLowerCase()
        || !/^0x[0-9a-f]{64}$/u.test(observed.finalizedBlockHash)
        || /^0x0{64}$/u.test(observed.finalizedBlockHash)) {
        throw new Error("Finalized checkpoint does not match selected deployment");
      }
      const historical = await input.readAuthenticatedEpochPublication(
        selection, epochIdHint, observed.finalizedBlockHash,
      );
      if (historical === null) return null;
      return {
        ledger: observed.ledger,
        acceptedEpoch: historical.acceptedEpoch,
        publication: historical.publication,
        evaluationTime: input.readEvaluationTime(),
        sequenceToTimestamp: input.sequenceToTimestamp,
      };
    },
    readFinalizedDidState: input.readFinalizedDidState,
  });
}
