import {
  DecisionEvidenceSchema,
  assertDecisionEvidenceMatchesAcceptedEpoch,
  assertDecisionEvidenceSelection,
  assertInactiveDecisionEvidenceSelection,
  computeAuthorizationScopeCommitment,
  type AcceptedDecisionEpoch,
  type DecisionEvidence,
  type DecisionEvidenceSelection,
} from "@midnight-ntwrk/trust-registry-domain";

import { assertDecisionEpochPublicationSignatures, type ActivePublicationMaintainer } from "./decision-epoch-signatures.js";
import { assertDecisionEvidenceDidMethodMatchesObservation, type DidStateObservation } from "./did-observation.js";

export type DecisionEvidenceSuppliedContext = {
  acceptedEpoch: AcceptedDecisionEpoch;
  publication: {
    registryIdCommitment: Uint8Array;
    networkIdCommitment: Uint8Array;
    contractAddress: Uint8Array;
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
    currentPolicy: {
      root: string;
      observedAtSequence: string;
    };
    currentGrant: {
      authorizationId: string;
      lifecycleEventRoot: string;
      status: string;
      observedAtSequence: string;
    };
  };
};

export type FinalizedRegistryDecisionSnapshot = Pick<
  DecisionEvidenceSuppliedContext,
  "acceptedEpoch" | "publication" | "decisionPoint"
>;

/** Implementations must authenticate both reads, including finality and latest-state currency. */
export type TrustedDecisionEvidenceReaders = {
  /** The epoch and grant IDs are untrusted lookup hints; authenticate the returned snapshot independently. */
  readCurrentFinalizedRegistryDecision(
    selection: Omit<DecisionEvidenceSelection, "evaluationTime">,
    epochIdHint: string,
    authorizationIdHint: string,
  ): Promise<FinalizedRegistryDecisionSnapshot | null>;
  readCurrentFinalizedDidState(
    did: string,
    networkId: string,
    registryDecisionSequence: string,
  ): Promise<DidStateObservation | null>;
};

type DecisionEvidenceCandidateBase = {
  grantStatus: "active" | "suspended" | "revoked";
  registryId: string;
  networkId: string;
  contractAddress: string;
  authorizationId: string;
  subjectDid: string;
  resourceId: string;
  scopeCommitment: string;
  policyId: string;
  policyVersion: string;
  policyRoot: string;
  decisionSequence: string;
  evaluationTime: string;
  didStateVersion: string;
  epochId: string;
  stateRoot: string;
  publicationEventHash: string;
};

export type DecisionEvidenceCandidate =
  | DecisionEvidenceCandidateBase & {
    role: "issuer";
    resourceType: Extract<DecisionEvidence, { role: "issuer" }>["grant"]["resourceType"];
    scope: Extract<DecisionEvidence, { role: "issuer" }>["scope"];
    didMethod: Extract<DecisionEvidence, { role: "issuer" }>["didMethod"];
    statusPolicyBinding: Extract<DecisionEvidence, { role: "issuer" }>["statusPolicyBinding"];
  }
  | DecisionEvidenceCandidateBase & {
    role: "verifier";
    resourceType: "request-profile";
    scope: Extract<DecisionEvidence, { role: "verifier" }>["scope"];
    didMethod: Extract<DecisionEvidence, { role: "verifier" }>["didMethod"];
    statusPolicyBinding?: never;
  };

const assertDecisionEvidenceConsistentWithExpectedState = (
  input: unknown,
  context: DecisionEvidenceSuppliedContext,
  expectedState: "active" | "suspended" | "revoked",
): void => {
  const evidence = DecisionEvidenceSchema.parse(input);
  if (evidence.decisionSequence !== context.decisionPoint.sequence) {
    throw new Error("Decision evidence selected sequence mismatch");
  }
  if (
    context.decisionPoint.currentPolicy.observedAtSequence !== context.decisionPoint.sequence
    || context.decisionPoint.currentPolicy.root !== evidence.epoch.policyRoot
  ) {
    throw new Error("Decision evidence current policy mismatch");
  }
  const currentGrant = context.decisionPoint.currentGrant;
  if (
    currentGrant.observedAtSequence !== context.decisionPoint.sequence
    || currentGrant.authorizationId !== evidence.grant.authorizationId
    || currentGrant.lifecycleEventRoot !== evidence.grant.lifecycleEventRoot
    || currentGrant.status !== expectedState
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
  const selection = {
    ...context.selection,
    evaluationTime: context.decisionPoint.evaluationTime,
  };
  if (expectedState === "active") assertDecisionEvidenceSelection(evidence, selection);
  else assertInactiveDecisionEvidenceSelection(evidence, selection, expectedState);
  assertDecisionEvidenceDidMethodMatchesObservation(
    evidence.didMethod,
    context.didState,
    context.selection.networkId,
  );
};

/** Consistency only: the caller must authenticate every supplied ledger/DID context and establish finality. */
export const assertDecisionEvidenceConsistentWithSuppliedContext = (
  input: unknown,
  context: DecisionEvidenceSuppliedContext,
): void => assertDecisionEvidenceConsistentWithExpectedState(input, context, "active");

/** An inactive status must be selected explicitly; it never qualifies as an active grant. */
export const assertInactiveDecisionEvidenceConsistentWithSuppliedContext = (
  input: unknown,
  context: DecisionEvidenceSuppliedContext,
  state: "suspended" | "revoked",
): void => assertDecisionEvidenceConsistentWithExpectedState(input, context, state);

const verifyDecisionEvidenceForExpectedState = async (
  input: unknown,
  selection: Omit<DecisionEvidenceSelection, "evaluationTime">,
  readers: TrustedDecisionEvidenceReaders,
  expectedState: "active" | "suspended" | "revoked",
): Promise<DecisionEvidenceCandidate> => {
  const evidence = DecisionEvidenceSchema.parse(input);
  const snapshot = await readers.readCurrentFinalizedRegistryDecision(
    selection, evidence.epoch.epochId, evidence.grant.authorizationId,
  );
  if (snapshot === null) {
    throw new Error("Current finalized registry decision is unavailable");
  }
  const didState = await readers.readCurrentFinalizedDidState(
    selection.subjectDid,
    selection.networkId,
    snapshot.decisionPoint.sequence,
  );
  if (didState === null) {
    throw new Error("Current finalized DID state is unavailable");
  }
  assertDecisionEvidenceConsistentWithExpectedState(evidence, {
    ...snapshot,
    didState,
    selection,
  }, expectedState);
  const common: DecisionEvidenceCandidateBase = {
    grantStatus: expectedState,
    registryId: snapshot.acceptedEpoch.registryId,
    networkId: snapshot.acceptedEpoch.networkId,
    contractAddress: snapshot.acceptedEpoch.contractAddress,
    authorizationId: evidence.grant.authorizationId,
    subjectDid: selection.subjectDid,
    resourceId: selection.resourceId,
    scopeCommitment: computeAuthorizationScopeCommitment(evidence.scope),
    policyId: evidence.policy.policyId,
    policyVersion: evidence.policy.policyVersion,
    policyRoot: snapshot.acceptedEpoch.policyRoot,
    decisionSequence: snapshot.decisionPoint.sequence,
    evaluationTime: snapshot.decisionPoint.evaluationTime,
    didStateVersion: didState.stateVersion,
    epochId: snapshot.acceptedEpoch.epochId,
    stateRoot: snapshot.acceptedEpoch.stateRoot,
    publicationEventHash: snapshot.acceptedEpoch.publicationEventHash,
  };
  return evidence.role === "issuer"
    ? {
      ...common,
      role: "issuer",
      resourceType: evidence.grant.resourceType,
      scope: evidence.scope,
      didMethod: evidence.didMethod,
      statusPolicyBinding: evidence.statusPolicyBinding,
    }
    : {
      ...common,
      role: "verifier",
      resourceType: "request-profile",
      scope: evidence.scope,
      didMethod: evidence.didMethod,
    };
};

/** A candidate is safe only to the extent that both readers authenticate current finalized state. */
export const verifyDecisionEvidenceWithTrustedReaders = (
  input: unknown,
  selection: Omit<DecisionEvidenceSelection, "evaluationTime">,
  readers: TrustedDecisionEvidenceReaders,
): Promise<DecisionEvidenceCandidate> => verifyDecisionEvidenceForExpectedState(input, selection, readers, "active");

/** Inactive evidence is suitable for status updates, never for new active authorization. */
export const verifyInactiveDecisionEvidenceWithTrustedReaders = (
  input: unknown,
  selection: Omit<DecisionEvidenceSelection, "evaluationTime">,
  readers: TrustedDecisionEvidenceReaders,
  state: "suspended" | "revoked",
): Promise<DecisionEvidenceCandidate> => {
  if (state !== "suspended" && state !== "revoked") {
    return Promise.reject(new Error("Inactive decision state is invalid"));
  }
  return verifyDecisionEvidenceForExpectedState(input, selection, readers, state);
};
