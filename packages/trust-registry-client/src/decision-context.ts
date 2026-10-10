import {
  DecisionEvidenceSchema,
  assertDecisionEvidenceMatchesAcceptedEpoch,
  assertDecisionEvidenceSelection,
  type AcceptedDecisionEpoch,
  type DecisionEvidenceSelection,
} from "@midnight-ntwrk/trust-registry-domain";

import { assertDecisionEpochPublicationSignatures, type ActivePublicationMaintainer } from "./decision-epoch-signatures.js";
import { assertDecisionEvidenceDidMethodMatchesObservation, type DidStateObservation } from "./did-observation.js";

export type DecisionEvidenceSuppliedContext = {
  acceptedEpoch: AcceptedDecisionEpoch;
  publication: {
    registryIdCommitment: Uint8Array;
    epochIdCommitment: Uint8Array;
    firstSignerKeyIdCommitment: Uint8Array;
    activeMaintainersAtPublication: readonly ActivePublicationMaintainer[];
  };
  didState: DidStateObservation;
  selection: Omit<DecisionEvidenceSelection, "evaluationTime">;
  /** A joint sequence/time observation authenticated by the caller's ledger reader. */
  decisionPoint: { sequence: string; evaluationTime: string };
};

/** Consistency only: the caller must authenticate every supplied ledger/DID context and establish finality. */
export const assertDecisionEvidenceConsistentWithSuppliedContext = (
  input: unknown,
  context: DecisionEvidenceSuppliedContext,
): void => {
  const evidence = DecisionEvidenceSchema.parse(input);
  if (evidence.decisionSequence !== context.decisionPoint.sequence) {
    throw new Error("Decision evidence selected sequence mismatch");
  }
  assertDecisionEvidenceMatchesAcceptedEpoch(evidence, context.acceptedEpoch);
  assertDecisionEpochPublicationSignatures(
    evidence.epoch,
    evidence.governanceEvents.epochPublication,
    context.acceptedEpoch,
    context.publication,
  );
  assertDecisionEvidenceSelection(evidence, {
    ...context.selection,
    evaluationTime: context.decisionPoint.evaluationTime,
  });
  assertDecisionEvidenceDidMethodMatchesObservation(
    evidence.didMethod,
    context.didState,
    context.selection.networkId,
  );
};
