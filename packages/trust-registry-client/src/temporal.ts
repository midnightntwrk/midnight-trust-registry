import type {
  AuthorizationRecord,
  EpochCommitment,
  RecognitionRecord,
} from "@midnight-ntwrk/trust-registry-domain";
import { compareRfc3339Instants } from "@midnight-ntwrk/trust-registry-domain";

export type AuthorizationTemporalEvaluation = {
  evaluatedAt: string;
  statusAtTime: AuthorizationRecord["status"] | null;
  trustedAtTime: boolean;
};

export type RecognitionTemporalEvaluation = {
  evaluatedAt: string;
  statusAtTime: RecognitionRecord["status"] | null;
  trustedAtTime: boolean;
};

const happenedBy = (
  timestamp: string | undefined,
  evaluatedAt: string,
): boolean =>
  timestamp !== undefined && compareRfc3339Instants(timestamp, evaluatedAt) <= 0;

const selectLatestEntry = <T>(
  entries: readonly T[],
  projectedTimestamp: (entry: T) => string,
): T | null =>
  [...entries].sort(
    (left, right) =>
      compareRfc3339Instants(projectedTimestamp(right), projectedTimestamp(left)),
  )[0] ?? null;

export const evaluateAuthorizationRecordAtTime = (
  record: AuthorizationRecord,
  evaluatedAt: string,
): AuthorizationTemporalEvaluation => {
  if (!happenedBy(record.proposedAt, evaluatedAt)) {
    return {
      evaluatedAt,
      statusAtTime: null,
      trustedAtTime: false,
    };
  }

  let statusAtTime: AuthorizationRecord["status"] = "proposed";
  // Authorization lifecycle timestamps are monotonic in the domain model.
  // This ordered cascade mirrors that invariant to recover the visible status.

  if (happenedBy(record.authorizedAt, evaluatedAt)) {
    statusAtTime = "authorized";
  }
  if (happenedBy(record.activeFrom, evaluatedAt)) {
    statusAtTime = "active";
  }
  if (happenedBy(record.suspendedAt, evaluatedAt)) {
    statusAtTime = "suspended";
  }
  if (happenedBy(record.revokedAt, evaluatedAt)) {
    statusAtTime = "revoked";
  }
  if (happenedBy(record.supersededAt, evaluatedAt)) {
    statusAtTime = "superseded";
  }
  if (happenedBy(record.archivedAt, evaluatedAt)) {
    statusAtTime = "archived";
  }

  const trustedAtTime = statusAtTime === "active"
    && (
      record.effectiveUntil === undefined
      || compareRfc3339Instants(evaluatedAt, record.effectiveUntil) <= 0
    );

  return {
    evaluatedAt,
    statusAtTime,
    trustedAtTime,
  };
};

export const evaluateRecognitionRecordAtTime = (
  record: RecognitionRecord,
  evaluatedAt: string,
): RecognitionTemporalEvaluation => {
  if (!happenedBy(record.proposedAt, evaluatedAt)) {
    return {
      evaluatedAt,
      statusAtTime: null,
      trustedAtTime: false,
    };
  }

  let statusAtTime: RecognitionRecord["status"] = "proposed";
  // Recognition lifecycle timestamps are monotonic in the domain model.
  // This ordered cascade mirrors that invariant to recover the visible status.

  if (happenedBy(record.authorizedAt, evaluatedAt)) {
    statusAtTime = "authorized";
  }
  if (happenedBy(record.effectiveFrom, evaluatedAt)) {
    statusAtTime = "active";
  }
  if (happenedBy(record.suspendedAt, evaluatedAt)) {
    statusAtTime = "suspended";
  }
  if (happenedBy(record.revokedAt, evaluatedAt)) {
    statusAtTime = "revoked";
  }
  if (happenedBy(record.supersededAt, evaluatedAt)) {
    statusAtTime = "superseded";
  }
  if (happenedBy(record.archivedAt, evaluatedAt)) {
    statusAtTime = "archived";
  }

  const trustedAtTime = statusAtTime === "active"
    && (
      record.effectiveUntil === undefined
      || compareRfc3339Instants(evaluatedAt, record.effectiveUntil) <= 0
    );

  return {
    evaluatedAt,
    statusAtTime,
    trustedAtTime,
  };
};

export const selectEpochCommitmentAtTime = (
  epochs: readonly EpochCommitment[],
  evaluatedAt: string,
): EpochCommitment | null => {
  return selectLatestEntry(
    epochs.filter((epoch) => {
      return compareRfc3339Instants(epoch.validFrom, evaluatedAt) <= 0
        && compareRfc3339Instants(evaluatedAt, epoch.validUntil) <= 0;
    }),
    (epoch) => epoch.validFrom,
  );
};

export const selectAuthorizationEntryAtTime = <
  T extends { authorization: AuthorizationRecord },
>(
  entries: readonly T[],
  evaluatedAt: string,
  predicate: (entry: T) => boolean = () => true,
): T | null => {
  const visible = entries.filter((entry) => {
      if (!predicate(entry)) {
        return false;
      }
      return evaluateAuthorizationRecordAtTime(
        entry.authorization,
        evaluatedAt,
      ).statusAtTime !== null;
    });
  const effective = visible.filter((entry) => {
    const status = evaluateAuthorizationRecordAtTime(
      entry.authorization,
      evaluatedAt,
    ).statusAtTime;
    return status !== "proposed" && status !== "authorized";
  });
  return selectLatestEntry(
    effective.length > 0 ? effective : visible,
    (entry) => entry.authorization.proposedAt,
  );
};

export const selectRecognitionEntryAtTime = <
  T extends { recognition: RecognitionRecord },
>(
  entries: readonly T[],
  evaluatedAt: string,
  predicate: (entry: T) => boolean = () => true,
): T | null => {
  const visible = entries.filter((entry) => {
      if (!predicate(entry)) {
        return false;
      }
      return evaluateRecognitionRecordAtTime(
        entry.recognition,
        evaluatedAt,
      ).statusAtTime !== null;
    });
  const effective = visible.filter((entry) => {
    const status = evaluateRecognitionRecordAtTime(
      entry.recognition,
      evaluatedAt,
    ).statusAtTime;
    return status !== "proposed" && status !== "authorized";
  });
  return selectLatestEntry(
    effective.length > 0 ? effective : visible,
    (entry) => entry.recognition.proposedAt,
  );
};
