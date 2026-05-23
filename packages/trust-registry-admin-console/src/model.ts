import type {
  TrustRegistryApiApplicationAction,
  TrustRegistryApiApplicationTarget,
  TrustRegistryApiApplicationMutationResponse,
  TrustRegistryApiSummary,
} from "@midnight-ntwrk/trust-registry-api";
import type {
  TrustRegistryAuthorizationSnapshotEntry,
  TrustRegistryRecognitionSnapshotEntry,
} from "@midnight-ntwrk/trust-registry-cli";

export type ReviewTarget = TrustRegistryApiApplicationTarget;
export type ReviewAction = TrustRegistryApiApplicationAction;
export type ReviewStatus =
  | TrustRegistryAuthorizationSnapshotEntry["authorization"]["status"]
  | TrustRegistryRecognitionSnapshotEntry["recognition"]["status"];

export type ReviewCard = {
  detailRows: readonly { label: string; value: string }[];
  id: string;
  key: string;
  label: string;
  scope: string;
  status: ReviewStatus;
  subject: string;
  target: ReviewTarget;
  trustLevel: string;
  updatedAt: string;
};

export type ReviewBoard = {
  recognitions: readonly TrustRegistryRecognitionSnapshotEntry[];
  summary: TrustRegistryApiSummary;
  verifiers: readonly TrustRegistryAuthorizationSnapshotEntry[];
  issuers: readonly TrustRegistryAuthorizationSnapshotEntry[];
};

export type ReviewBoardMutation = TrustRegistryApiApplicationMutationResponse;

export type ReviewStatusBucket = Record<ReviewStatus, ReviewCard[]>;

export const REVIEW_STATUSES: readonly ReviewStatus[] = [
  "proposed",
  "authorized",
  "active",
  "suspended",
  "revoked",
  "superseded",
  "archived",
];

export const REVIEW_STATUS_LABELS: Record<ReviewStatus, string> = {
  proposed: "Proposed",
  authorized: "Authorized",
  active: "Active",
  suspended: "Suspended",
  revoked: "Revoked",
  superseded: "Superseded",
  archived: "Archived",
};

const REVIEW_ACTIONS_BY_STATUS: Record<ReviewStatus, readonly ReviewAction[]> = {
  proposed: ["approve", "archive"],
  authorized: ["activate", "revoke", "archive"],
  active: ["suspend", "revoke"],
  suspended: ["revoke", "archive"],
  revoked: ["archive"],
  superseded: [],
  archived: [],
};

const defaultBuckets = (): ReviewStatusBucket => ({
  proposed: [],
  authorized: [],
  active: [],
  suspended: [],
  revoked: [],
  superseded: [],
  archived: [],
});

const latestAuthorizationTimestamp = (
  entry: TrustRegistryAuthorizationSnapshotEntry,
): string =>
  entry.authorization.archivedAt
  ?? entry.authorization.supersededAt
  ?? entry.authorization.revokedAt
  ?? entry.authorization.suspendedAt
  ?? entry.authorization.effectiveUntil
  ?? entry.authorization.activeFrom
  ?? entry.authorization.authorizedAt
  ?? entry.authorization.proposedAt;

const latestRecognitionTimestamp = (
  entry: TrustRegistryRecognitionSnapshotEntry,
): string =>
  entry.recognition.archivedAt
  ?? entry.recognition.supersededAt
  ?? entry.recognition.revokedAt
  ?? entry.recognition.suspendedAt
  ?? entry.recognition.effectiveUntil
  ?? entry.recognition.effectiveFrom
  ?? entry.recognition.authorizedAt
  ?? entry.recognition.proposedAt;

const statusSort = (left: ReviewCard, right: ReviewCard): number =>
  right.updatedAt.localeCompare(left.updatedAt);

export const getReviewActions = (
  status: ReviewStatus,
): readonly ReviewAction[] => REVIEW_ACTIONS_BY_STATUS[status];

export const toAuthorizationReviewCard = (
  target: Extract<ReviewTarget, "issuer" | "verifier">,
  entry: TrustRegistryAuthorizationSnapshotEntry,
): ReviewCard => ({
  detailRows: [
    { label: "Authorization ID", value: entry.authorization.authorizationId },
    { label: "Subject DID", value: entry.authorization.subjectDid },
    { label: "Scope", value: `${entry.authorization.resourceType}:${entry.authorization.resourceId}` },
    { label: "Trust level", value: entry.authorization.trustLevel },
    { label: "Policy", value: entry.authorization.policyId },
  ],
  id: entry.authorization.authorizationId,
  key: `${target}:${entry.authorization.authorizationId}`,
  label: entry.label,
  scope: `${entry.authorization.resourceType}:${entry.authorization.resourceId}`,
  status: entry.authorization.status,
  subject: entry.authorization.subjectDid,
  target,
  trustLevel: entry.authorization.trustLevel,
  updatedAt: latestAuthorizationTimestamp(entry),
});

export const toRecognitionReviewCard = (
  entry: TrustRegistryRecognitionSnapshotEntry,
): ReviewCard => ({
  detailRows: [
    { label: "Recognition ID", value: entry.recognition.recognitionId },
    { label: "Authority DID", value: entry.recognition.recognizedAuthorityDid },
    { label: "Recognized registry", value: entry.recognition.recognizedRegistryId },
    { label: "Scope", value: `${entry.recognition.scope.resourceType}:${entry.recognition.scope.resourceId}` },
    { label: "Trust level", value: entry.recognition.trustLevel },
    { label: "Policy", value: entry.recognition.policyId },
  ],
  id: entry.recognition.recognitionId,
  key: `recognition:${entry.recognition.recognitionId}`,
  label: entry.label,
  scope: `${entry.recognition.scope.resourceType}:${entry.recognition.scope.resourceId}`,
  status: entry.recognition.status,
  subject: entry.recognition.recognizedAuthorityDid,
  target: "recognition",
  trustLevel: entry.recognition.trustLevel,
  updatedAt: latestRecognitionTimestamp(entry),
});

export const buildReviewCards = (
  board: ReviewBoard,
): readonly ReviewCard[] => [
  ...board.issuers.map((entry) => toAuthorizationReviewCard("issuer", entry)),
  ...board.verifiers.map((entry) => toAuthorizationReviewCard("verifier", entry)),
  ...board.recognitions.map(toRecognitionReviewCard),
].sort(statusSort);

export const groupReviewCards = (
  cards: readonly ReviewCard[],
): ReviewStatusBucket => {
  const buckets = defaultBuckets();
  for (const card of cards) {
    buckets[card.status].push(card);
  }
  for (const status of REVIEW_STATUSES) {
    buckets[status].sort(statusSort);
  }
  return buckets;
};

export const describeMutation = (
  result: ReviewBoardMutation,
): string => {
  switch (result.recordKind) {
    case "authorization":
      return `${result.operation.operation}d ${result.entry.label} (${result.entry.authorization.status})`;
    case "recognition":
      return `${result.operation.operation}d ${result.entry.label} (${result.entry.recognition.status})`;
    case "epoch":
      return `published epoch ${result.epoch.epochId}`;
  }
};
