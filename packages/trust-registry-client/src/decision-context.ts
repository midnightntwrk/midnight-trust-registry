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
  /** One authenticated read at the selected sequence; a historical epoch leaf alone is insufficient. */
  decisionPoint: {
    sequence: string;
    evaluationTime: string;
    currentGrant: {
      authorizationId: string;
      lifecycleEventRoot: string;
      status: string;
      observedAtSequence: string;
    };
  };
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
  const currentGrant = context.decisionPoint.currentGrant;
  if (
    currentGrant.observedAtSequence !== context.decisionPoint.sequence
    || currentGrant.authorizationId !== evidence.grant.authorizationId
    || currentGrant.lifecycleEventRoot !== evidence.grant.lifecycleEventRoot
    || currentGrant.status !== "active"
  ) {
    throw new Error("Decision evidence current grant mismatch");
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
