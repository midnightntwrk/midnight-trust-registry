import { Buffer } from "node:buffer";

import { encodeCompactActionKind } from "@midnight-ntwrk/trust-registry-contract";
import { getLocalNetworkProfile, type FinalizedRegistryLedgerView } from "@midnight-ntwrk/trust-registry-integration";
import { resolveCompactProposalObservation } from "./compact-proposal-observation.js";
import { proposalAttemptDigest, type ProposalSubmissionAttempt } from "./proposal-submission-journal.js";

type RecoveryView = Pick<FinalizedRegistryLedgerView,
  "networkId" | "finalizedBlockHash" | "contractAddress" | "ledger">;

const proposalActionKind = (role: ProposalSubmissionAttempt["role"]): string =>
  `0x${Buffer.from(encodeCompactActionKind(`tr:${role}:propose`)).toString("hex")}`;

export type ProposalRecoveryCandidateReason =
  | "matching-record"
  | "conflicting-record"
  | "non-reserved-attempt"
  | "legacy-reservation"
  | "sequence-still-live"
  | "sequence-ahead-of-finality"
  | "sequence-occupied-by-matching-payload"
  | "sequence-advanced-history-unavailable"
  | "sequence-invalidated-record-absent";

/** An audit input only; no candidate report authorizes journal release or retry. */
export async function assessProposalRecoveryCandidate(input: {
  attempt: ProposalSubmissionAttempt;
  view: RecoveryView;
  registryId: string;
  contractAddress: string;
  planExpectedGenesisHash: string;
  planSourceRevision: string;
  approvedPlanSha256: string;
  journalBindingDigest: string;
}): Promise<{
  format: "tr-local-proposal-recovery-candidate-v3";
  networkId: ReturnType<typeof getLocalNetworkProfile>["networkId"];
  registryId: string;
  contractAddress: string;
  planExpectedGenesisHash: string;
  planSourceRevision: string;
  approvedPlanSha256: string;
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
  finalizedLastActionKind: string | null;
  finalizedLastActionPayloadHash: string | null;
  observedEventHash: string | null;
  reason: ProposalRecoveryCandidateReason;
  reviewCandidate: boolean;
  retryPermitted: false;
  releaseQualified: false;
}> {
  const { attempt, view } = input;
  if (view.networkId !== getLocalNetworkProfile().networkId
    || !/^0x[0-9a-f]{64}$/u.test(input.contractAddress.toLowerCase())
    || /^0x0{64}$/u.test(input.contractAddress.toLowerCase())
    || view.contractAddress.toLowerCase() !== input.contractAddress.toLowerCase()
    || !/^0x[0-9a-f]{64}$/u.test(input.planExpectedGenesisHash.toLowerCase())
    || /^0x0{64}$/u.test(input.planExpectedGenesisHash.toLowerCase())
    || !/^[0-9a-f]{40}$/u.test(input.planSourceRevision)
    || !/^[0-9a-f]{64}$/u.test(input.approvedPlanSha256)
    || !/^0x[0-9a-f]{64}$/u.test(input.journalBindingDigest)
    || !/^0x[0-9a-f]{64}$/u.test(view.finalizedBlockHash.toLowerCase())
    || /^0x0{64}$/u.test(view.finalizedBlockHash.toLowerCase())
    || typeof view.ledger.governanceActionCount !== "bigint"
    || view.ledger.governanceActionCount < 0n
    || view.ledger.governanceActionCount >= (1n << 64n)) {
    throw new Error("Recovery candidate requires the pinned finalized local ledger view");
  }
  const context = attempt.reservationContext;
  const sequence = context?.actionSequence;
  if (sequence !== undefined
    && (!/^(0|[1-9][0-9]{0,19})$/u.test(sequence) || BigInt(sequence) >= (1n << 64n)
      || !/^0x[0-9a-f]{64}$/u.test(context?.actionKind ?? "")
      || !/^0x[0-9a-f]{64}$/u.test(context?.actionPayloadHash ?? ""))) {
    throw new Error("Recovery reservation action sequence is invalid");
  }
  if (context !== undefined && context.actionKind !== proposalActionKind(attempt.role)) {
    throw new Error("Recovery reservation action kind does not match its proposal role");
  }
  const observed = await resolveCompactProposalObservation(
    async () => view.ledger, input.registryId, attempt.role, attempt.authorizationId,
  );
  const immediatelyConsumed = sequence !== undefined
    && view.ledger.governanceActionCount === BigInt(sequence) + 1n;
  const needsLastAction = observed === null && attempt.state === "reserved" && immediatelyConsumed;
  if (needsLastAction
    && (!(view.ledger.lastAuthorizedActionKind instanceof Uint8Array)
      || view.ledger.lastAuthorizedActionKind.length !== 32
      || !(view.ledger.lastAuthorizedActionPayloadHash instanceof Uint8Array)
      || view.ledger.lastAuthorizedActionPayloadHash.length !== 32)) {
    throw new Error("Recovery candidate requires the finalized last action readback");
  }
  const finalizedLastActionKind = needsLastAction
    ? `0x${Buffer.from(view.ledger.lastAuthorizedActionKind).toString("hex")}` : null;
  const finalizedLastActionPayloadHash = needsLastAction
    ? `0x${Buffer.from(view.ledger.lastAuthorizedActionPayloadHash).toString("hex")}` : null;
  const lastActionDiffers = context !== undefined && needsLastAction
    && (finalizedLastActionKind !== context.actionKind
      || finalizedLastActionPayloadHash !== context.actionPayloadHash);
  const reason: ProposalRecoveryCandidateReason = observed !== null
    ? observed.evidenceCommitment !== attempt.evidenceCommitment
      || (attempt.eventHash !== null && observed.eventHash !== attempt.eventHash)
      ? "conflicting-record" : "matching-record"
    : attempt.state !== "reserved" ? "non-reserved-attempt"
      : sequence === undefined ? "legacy-reservation"
        : view.ledger.governanceActionCount < BigInt(sequence) ? "sequence-ahead-of-finality"
          : view.ledger.governanceActionCount === BigInt(sequence) ? "sequence-still-live"
            : !immediatelyConsumed ? "sequence-advanced-history-unavailable"
              : lastActionDiffers ? "sequence-invalidated-record-absent"
                : "sequence-occupied-by-matching-payload";
  return {
    format: "tr-local-proposal-recovery-candidate-v3",
    networkId: getLocalNetworkProfile().networkId,
    registryId: input.registryId,
    contractAddress: input.contractAddress.toLowerCase(),
    planExpectedGenesisHash: input.planExpectedGenesisHash.toLowerCase(),
    planSourceRevision: input.planSourceRevision,
    approvedPlanSha256: input.approvedPlanSha256,
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
    finalizedLastActionKind,
    finalizedLastActionPayloadHash,
    observedEventHash: observed?.eventHash ?? null,
    reason,
    reviewCandidate: reason === "sequence-invalidated-record-absent",
    retryPermitted: false,
    releaseQualified: false,
  };
}
