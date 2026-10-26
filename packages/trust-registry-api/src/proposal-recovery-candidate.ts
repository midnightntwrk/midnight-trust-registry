import type { FinalizedRegistryLedgerView } from "@midnight-ntwrk/trust-registry-integration";
import { resolveCompactProposalObservation } from "./compact-proposal-observation.js";
import { proposalAttemptDigest, type ProposalSubmissionAttempt } from "./proposal-submission-journal.js";

type RecoveryView = Pick<FinalizedRegistryLedgerView,
  "networkId" | "finalizedBlockHash" | "contractAddress" | "ledger">;

export type ProposalRecoveryCandidateReason =
  | "matching-record"
  | "conflicting-record"
  | "non-reserved-attempt"
  | "legacy-reservation"
  | "sequence-still-live"
  | "sequence-ahead-of-finality"
  | "sequence-invalidated-record-absent";

/** An audit input only; no candidate report authorizes journal release or retry. */
export async function assessProposalRecoveryCandidate(input: {
  attempt: ProposalSubmissionAttempt;
  view: RecoveryView;
  registryId: string;
  contractAddress: string;
  planExpectedGenesisHash: string;
  planSourceRevision: string;
  journalBindingDigest: string;
}): Promise<{
  format: "tr-local-proposal-recovery-candidate-v1";
  networkId: "undeployed";
  registryId: string;
  contractAddress: string;
  planExpectedGenesisHash: string;
  planSourceRevision: string;
  journalBindingDigest: string;
  finalizedBlockHash: string;
  role: ProposalSubmissionAttempt["role"];
  authorizationId: string;
  evidenceCommitment: string;
  attemptDigest: string;
  reservationState: ProposalSubmissionAttempt["state"];
  reservationActionSequence: string | null;
  reservationActionKind: string | null;
  reservationActionPayloadHash: string | null;
  finalizedGovernanceActionCount: string;
  observedEventHash: string | null;
  reason: ProposalRecoveryCandidateReason;
  reviewCandidate: boolean;
  retryPermitted: false;
  releaseQualified: false;
}> {
  const { attempt, view } = input;
  if (view.networkId !== "undeployed"
    || !/^0x[0-9a-f]{64}$/u.test(input.contractAddress.toLowerCase())
    || /^0x0{64}$/u.test(input.contractAddress.toLowerCase())
    || view.contractAddress.toLowerCase() !== input.contractAddress.toLowerCase()
    || !/^0x[0-9a-f]{64}$/u.test(input.planExpectedGenesisHash.toLowerCase())
    || /^0x0{64}$/u.test(input.planExpectedGenesisHash.toLowerCase())
    || !/^[0-9a-f]{40}$/u.test(input.planSourceRevision)
    || !/^0x[0-9a-f]{64}$/u.test(input.journalBindingDigest)
    || !/^0x[0-9a-f]{64}$/u.test(view.finalizedBlockHash.toLowerCase())
    || /^0x0{64}$/u.test(view.finalizedBlockHash.toLowerCase())
    || typeof view.ledger.governanceActionCount !== "bigint") {
    throw new Error("Recovery candidate requires the pinned finalized local ledger view");
  }
  const observed = await resolveCompactProposalObservation(
    async () => view.ledger, input.registryId, attempt.role, attempt.authorizationId,
  );
  const context = attempt.reservationContext;
  const sequence = context?.actionSequence;
  if (sequence !== undefined
    && (!/^(0|[1-9][0-9]{0,19})$/u.test(sequence) || BigInt(sequence) >= (1n << 64n)
      || !/^0x[0-9a-f]{64}$/u.test(context?.actionKind ?? "")
      || !/^0x[0-9a-f]{64}$/u.test(context?.actionPayloadHash ?? ""))) {
    throw new Error("Recovery reservation action sequence is invalid");
  }
  const reason: ProposalRecoveryCandidateReason = observed !== null
    ? observed.evidenceCommitment !== attempt.evidenceCommitment
      || (attempt.eventHash !== null && observed.eventHash !== attempt.eventHash)
      ? "conflicting-record" : "matching-record"
    : attempt.state !== "reserved" ? "non-reserved-attempt"
      : sequence === undefined ? "legacy-reservation"
        : view.ledger.governanceActionCount < BigInt(sequence) ? "sequence-ahead-of-finality"
          : view.ledger.governanceActionCount === BigInt(sequence) ? "sequence-still-live"
            : "sequence-invalidated-record-absent";
  return {
    format: "tr-local-proposal-recovery-candidate-v1",
    networkId: "undeployed",
    registryId: input.registryId,
    contractAddress: input.contractAddress.toLowerCase(),
    planExpectedGenesisHash: input.planExpectedGenesisHash.toLowerCase(),
    planSourceRevision: input.planSourceRevision,
    journalBindingDigest: input.journalBindingDigest,
    finalizedBlockHash: view.finalizedBlockHash.toLowerCase(),
    role: attempt.role,
    authorizationId: attempt.authorizationId,
    evidenceCommitment: attempt.evidenceCommitment,
    attemptDigest: proposalAttemptDigest(attempt),
    reservationState: attempt.state,
    reservationActionSequence: sequence ?? null,
    reservationActionKind: context?.actionKind ?? null,
    reservationActionPayloadHash: context?.actionPayloadHash ?? null,
    finalizedGovernanceActionCount: view.ledger.governanceActionCount.toString(),
    observedEventHash: observed?.eventHash ?? null,
    reason,
    reviewCandidate: reason === "sequence-invalidated-record-absent",
    retryPermitted: false,
    releaseQualified: false,
  };
}
