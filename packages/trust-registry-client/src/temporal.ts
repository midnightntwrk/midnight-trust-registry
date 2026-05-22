import type {
  AuthorizationRecord,
  EpochCommitment,
  RecognitionRecord,
} from "@midnight-ntwrk/trust-registry-domain";

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

const timestampValue = (timestamp: string): number => {
  const value = Date.parse(timestamp);
  if (Number.isNaN(value)) {
    throw new Error(`invalid timestamp: ${timestamp}`);
  }

  return value;
};

const happenedBy = (
  timestamp: string | undefined,
  evaluatedAtMs: number,
): boolean =>
  timestamp !== undefined && timestampValue(timestamp) <= evaluatedAtMs;

const selectLatestEntry = <T>(
  entries: readonly T[],
  projectedTimestamp: (entry: T) => string,
): T | null =>
  [...entries].sort(
    (left, right) =>
      timestampValue(projectedTimestamp(right)) - timestampValue(projectedTimestamp(left)),
  )[0] ?? null;

export const evaluateAuthorizationRecordAtTime = (
  record: AuthorizationRecord,
  evaluatedAt: string,
): AuthorizationTemporalEvaluation => {
  const evaluatedAtMs = timestampValue(evaluatedAt);

  if (!happenedBy(record.proposedAt, evaluatedAtMs)) {
    return {
      evaluatedAt,
      statusAtTime: null,
      trustedAtTime: false,
    };
  }

  let statusAtTime: AuthorizationRecord["status"] = "proposed";

  if (happenedBy(record.authorizedAt, evaluatedAtMs)) {
    statusAtTime = "authorized";
  }
  if (happenedBy(record.activeFrom, evaluatedAtMs)) {
    statusAtTime = "active";
  }
  if (happenedBy(record.suspendedAt, evaluatedAtMs)) {
    statusAtTime = "suspended";
  }
  if (happenedBy(record.revokedAt, evaluatedAtMs)) {
    statusAtTime = "revoked";
  }
  if (happenedBy(record.supersededAt, evaluatedAtMs)) {
    statusAtTime = "superseded";
  }
  if (happenedBy(record.archivedAt, evaluatedAtMs)) {
    statusAtTime = "archived";
  }

  const trustedAtTime = statusAtTime === "active"
    && (
      record.effectiveUntil === undefined
      || evaluatedAtMs <= timestampValue(record.effectiveUntil)
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
  const evaluatedAtMs = timestampValue(evaluatedAt);

  if (!happenedBy(record.proposedAt, evaluatedAtMs)) {
    return {
      evaluatedAt,
      statusAtTime: null,
      trustedAtTime: false,
    };
  }

  let statusAtTime: RecognitionRecord["status"] = "proposed";

  if (happenedBy(record.authorizedAt, evaluatedAtMs)) {
    statusAtTime = "authorized";
  }
  if (happenedBy(record.effectiveFrom, evaluatedAtMs)) {
    statusAtTime = "active";
  }
  if (happenedBy(record.suspendedAt, evaluatedAtMs)) {
    statusAtTime = "suspended";
  }
  if (happenedBy(record.revokedAt, evaluatedAtMs)) {
    statusAtTime = "revoked";
  }
  if (happenedBy(record.supersededAt, evaluatedAtMs)) {
    statusAtTime = "superseded";
  }
  if (happenedBy(record.archivedAt, evaluatedAtMs)) {
    statusAtTime = "archived";
  }

  const trustedAtTime = statusAtTime === "active"
    && (
      record.effectiveUntil === undefined
      || evaluatedAtMs <= timestampValue(record.effectiveUntil)
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
  const evaluatedAtMs = timestampValue(evaluatedAt);
  return selectLatestEntry(
    epochs.filter((epoch) => {
      const validFrom = timestampValue(epoch.validFrom);
      const validUntil = timestampValue(epoch.validUntil);
      return validFrom <= evaluatedAtMs && evaluatedAtMs <= validUntil;
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
): T | null =>
  selectLatestEntry(
    entries.filter((entry) => {
      if (!predicate(entry)) {
        return false;
      }
      return evaluateAuthorizationRecordAtTime(
        entry.authorization,
        evaluatedAt,
      ).statusAtTime !== null;
    }),
    (entry) => entry.authorization.proposedAt,
  );

export const selectRecognitionEntryAtTime = <
  T extends { recognition: RecognitionRecord },
>(
  entries: readonly T[],
  evaluatedAt: string,
  predicate: (entry: T) => boolean = () => true,
): T | null =>
  selectLatestEntry(
    entries.filter((entry) => {
      if (!predicate(entry)) {
        return false;
      }
      return evaluateRecognitionRecordAtTime(
        entry.recognition,
        evaluatedAt,
      ).statusAtTime !== null;
    }),
    (entry) => entry.recognition.proposedAt,
  );
