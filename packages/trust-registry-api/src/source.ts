import {
  applyWorkspaceOperation,
  buildSnapshotSummary,
  findEpochAtTimestamp,
  loadSnapshotFromFile,
  loadWorkspaceFromFile,
  resolveIssuerEntryAtTimestamp,
  resolveRecognitionEntryAtTimestamp,
  resolveVerifierEntryAtTimestamp,
  resolveWorkspaceOperationRecord,
  writeWorkspaceToFile,
  type SnapshotTemporalAuthorizationInspection,
  type SnapshotTemporalRecognitionInspection,
  type TrustRegistryOperatorWorkspace,
  type TrustRegistryOperatorWorkspaceOperation,
  type TrustRegistryAuthorizationSnapshotEntry,
  type TrustRegistryOperatorSnapshot,
  type TrustRegistryRecognitionSnapshotEntry,
  type TrustRegistrySummary,
} from "@midnight-ntwrk/trust-registry-cli";
import type {
  TrqpAuthorizationRequest,
  TrqpRecognitionRequest,
  TrustRegistryTrqpSource,
} from "@midnight-ntwrk/trust-registry-trqp-adapter";
import type {
  EpochCommitment,
  RegistryRecord,
  TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";

import type {
  TrustRegistryApiAuthorizationListQuery,
  TrustRegistryApiAuthorizationRole,
  TrustRegistryApiResolveAuthorizationRequest,
  TrustRegistryApiResolveRecognitionRequest,
  TrustRegistryApiRecognitionListQuery,
} from "./schemas.js";

export type TrustRegistryApiSourceMode = "snapshot" | "workspace" | "memory";

export type TrustRegistryApiStateSource = {
  readonly mode: TrustRegistryApiSourceMode;
  loadSnapshot(): Promise<TrustRegistryOperatorSnapshot>;
};

export type TrustRegistryApiMutableStateSource = TrustRegistryApiStateSource & {
  readonly mode: "workspace";
  loadWorkspace(): Promise<TrustRegistryOperatorWorkspace>;
  writeWorkspace(workspace: TrustRegistryOperatorWorkspace): Promise<void>;
};

export type TrustRegistryApiMutationRecord =
  | {
      recordKind: "authorization";
      entry: TrustRegistryAuthorizationSnapshotEntry;
    }
  | {
      recordKind: "recognition";
      entry: TrustRegistryRecognitionSnapshotEntry;
    }
  | {
      recordKind: "epoch";
      epoch: TrustRegistryOperatorSnapshot["currentEpoch"];
    };

export type TrustRegistryApiMutationResult = {
  operation: TrustRegistryOperatorWorkspaceOperation;
  record: TrustRegistryApiMutationRecord;
  workspace: TrustRegistryOperatorWorkspace;
};

const mutationChains = new WeakMap<
  TrustRegistryApiMutableStateSource,
  Promise<unknown>
>();

const latestAuthorizationTimestamp = (
  entry: TrustRegistryAuthorizationSnapshotEntry,
): string =>
  entry.authorization.archivedAt
  ?? entry.authorization.supersededAt
  ?? entry.authorization.revokedAt
  ?? entry.authorization.suspendedAt
  ?? entry.authorization.effectiveUntil
  ?? entry.authorization.issuedAt
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

const sortAuthorizationEntries = (
  entries: readonly TrustRegistryAuthorizationSnapshotEntry[],
): TrustRegistryAuthorizationSnapshotEntry[] =>
  [...entries].sort((left, right) =>
    latestAuthorizationTimestamp(right).localeCompare(
      latestAuthorizationTimestamp(left),
    ),
  );

const sortRecognitionEntries = (
  entries: readonly TrustRegistryRecognitionSnapshotEntry[],
): TrustRegistryRecognitionSnapshotEntry[] =>
  [...entries].sort((left, right) =>
    latestRecognitionTimestamp(right).localeCompare(
      latestRecognitionTimestamp(left),
    ),
  );

const authorizationEntriesForRole = (
  snapshot: TrustRegistryOperatorSnapshot,
  role: TrustRegistryApiAuthorizationRole,
): readonly TrustRegistryAuthorizationSnapshotEntry[] => {
  switch (role) {
    case "issuer":
      return snapshot.issuerEntries;
    case "verifier":
      return snapshot.verifierEntries;
  }
};

const actionToAuthorizationRole = (
  action: string,
): TrustRegistryApiAuthorizationRole | undefined => {
  // The first HTTP slice intentionally exposes only the issuer/verifier
  // TRQP actions already modeled by the adapter package.
  switch (action) {
    case "issue":
      return "issuer";
    case "verify":
      return "verifier";
    default:
      return undefined;
  }
};

export const createSnapshotFileSource = (
  snapshotPath: string,
): TrustRegistryApiStateSource => ({
  mode: "snapshot",
  async loadSnapshot(): Promise<TrustRegistryOperatorSnapshot> {
    return loadSnapshotFromFile(snapshotPath);
  },
});

export const createWorkspaceFileSource = (
  workspacePath: string,
): TrustRegistryApiMutableStateSource => ({
  mode: "workspace",
  async loadSnapshot(): Promise<TrustRegistryOperatorSnapshot> {
    return (await loadWorkspaceFromFile(workspacePath)).snapshot;
  },
  async loadWorkspace(): Promise<TrustRegistryOperatorWorkspace> {
    return loadWorkspaceFromFile(workspacePath);
  },
  async writeWorkspace(workspace: TrustRegistryOperatorWorkspace): Promise<void> {
    await writeWorkspaceToFile(workspacePath, workspace);
  },
});

export const createInMemorySource = (
  snapshot: TrustRegistryOperatorSnapshot,
): TrustRegistryApiStateSource => ({
  mode: "memory",
  async loadSnapshot(): Promise<TrustRegistryOperatorSnapshot> {
    return snapshot;
  },
});

export const isMutableStateSource = (
  source: TrustRegistryApiStateSource,
): source is TrustRegistryApiMutableStateSource =>
  source.mode === "workspace";

const toMutationRecord = (
  record:
    | TrustRegistryAuthorizationSnapshotEntry
    | TrustRegistryRecognitionSnapshotEntry
    | TrustRegistryOperatorSnapshot["currentEpoch"],
): TrustRegistryApiMutationRecord => {
  if ("authorization" in record) {
    return {
      recordKind: "authorization",
      entry: record,
    };
  }
  if ("recognition" in record) {
    return {
      recordKind: "recognition",
      entry: record,
    };
  }

  return {
    recordKind: "epoch",
    epoch: record,
  };
};

export const applyMutationOperation = async (
  source: TrustRegistryApiMutableStateSource,
  operation: TrustRegistryOperatorWorkspaceOperation,
): Promise<TrustRegistryApiMutationResult> => {
  const previous = mutationChains.get(source) ?? Promise.resolve();
  const next = previous.then(async () => {
    const workspace = await source.loadWorkspace();
    const nextWorkspace = applyWorkspaceOperation(workspace, operation);
    await source.writeWorkspace(nextWorkspace);
    const record = resolveWorkspaceOperationRecord(nextWorkspace, operation);

    return {
      operation,
      record: toMutationRecord(record),
      workspace: nextWorkspace,
    };
  });

  mutationChains.set(
    source,
    next.then(
      () => undefined,
      () => undefined,
    ),
  );

  return next;
};

export const loadRegistryRecord = async (
  source: TrustRegistryApiStateSource,
): Promise<RegistryRecord> => (await source.loadSnapshot()).registry;

export const loadRegistrySummary = async (
  source: TrustRegistryApiStateSource,
): Promise<TrustRegistrySummary> =>
  buildSnapshotSummary(await source.loadSnapshot());

export const loadCurrentEpoch = async (
  source: TrustRegistryApiStateSource,
): Promise<EpochCommitment> => (await source.loadSnapshot()).currentEpoch;

export const loadEpochById = async (
  source: TrustRegistryApiStateSource,
  epochId: string,
): Promise<EpochCommitment | null> => {
  const snapshot = await source.loadSnapshot();
  return snapshot.epochs.find((entry) => entry.epochId === epochId) ?? null;
};

export const loadEpochAtTimestamp = async (
  source: TrustRegistryApiStateSource,
  evaluatedAt: string,
): Promise<EpochCommitment | null> =>
  findEpochAtTimestamp(await source.loadSnapshot(), evaluatedAt);

export const listAuthorizationEntries = async (
  source: TrustRegistryApiStateSource,
  role: TrustRegistryApiAuthorizationRole,
  query: TrustRegistryApiAuthorizationListQuery = {},
): Promise<TrustRegistryAuthorizationSnapshotEntry[]> => {
  const snapshot = await source.loadSnapshot();
  const entries = authorizationEntriesForRole(snapshot, role).filter((entry) =>
    query.status === undefined || entry.authorization.status === query.status,
  );

  return sortAuthorizationEntries(entries);
};

export const getAuthorizationEntryById = async (
  source: TrustRegistryApiStateSource,
  role: TrustRegistryApiAuthorizationRole,
  authorizationId: string,
): Promise<TrustRegistryAuthorizationSnapshotEntry | null> => {
  const snapshot = await source.loadSnapshot();
  return (
    authorizationEntriesForRole(snapshot, role).find(
      (entry) => entry.authorization.authorizationId === authorizationId,
    ) ?? null
  );
};

export const resolveAuthorizationEntry = async (
  source: TrustRegistryApiStateSource,
  request: TrustRegistryApiResolveAuthorizationRequest,
): Promise<TrustRegistryAuthorizationSnapshotEntry | null> => {
  const snapshot = await source.loadSnapshot();
  const matches = authorizationEntriesForRole(snapshot, request.role).filter(
    (entry) =>
      entry.authorization.subjectDid === request.subjectDid
      && entry.authorization.resourceId === request.resourceId
      && (
        request.resourceType === undefined
        || entry.authorization.resourceType === request.resourceType
      )
      && (
        request.trustLevel === undefined
        || entry.authorization.trustLevel === request.trustLevel
      ),
  );

  return sortAuthorizationEntries(matches).at(0) ?? null;
};

export const evaluateAuthorizationEntryAtTimestamp = async (
  source: TrustRegistryApiStateSource,
  request: TrustRegistryApiResolveAuthorizationRequest,
  evaluatedAt: string,
): Promise<SnapshotTemporalAuthorizationInspection | null> => {
  const snapshot = await source.loadSnapshot();

  if (request.role === "issuer") {
    return resolveIssuerEntryAtTimestamp(
      snapshot,
      evaluatedAt,
      (entry) =>
        entry.authorization.subjectDid === request.subjectDid
        && entry.authorization.resourceId === request.resourceId
        && (
          request.resourceType === undefined
          || entry.authorization.resourceType === request.resourceType
        )
        && (
          request.trustLevel === undefined
          || entry.authorization.trustLevel === request.trustLevel
        ),
    );
  }

  return resolveVerifierEntryAtTimestamp(
    snapshot,
    evaluatedAt,
    (entry) =>
      entry.authorization.subjectDid === request.subjectDid
      && entry.authorization.resourceId === request.resourceId
      && (
        request.resourceType === undefined
        || entry.authorization.resourceType === request.resourceType
      )
      && (
        request.trustLevel === undefined
        || entry.authorization.trustLevel === request.trustLevel
      ),
  );
};

export const listRecognitionEntries = async (
  source: TrustRegistryApiStateSource,
  query: TrustRegistryApiRecognitionListQuery = {},
): Promise<TrustRegistryRecognitionSnapshotEntry[]> => {
  const snapshot = await source.loadSnapshot();
  const entries = snapshot.recognitionEntries.filter((entry) =>
    query.status === undefined || entry.recognition.status === query.status,
  );

  return sortRecognitionEntries(entries);
};

export const getRecognitionEntryById = async (
  source: TrustRegistryApiStateSource,
  recognitionId: string,
): Promise<TrustRegistryRecognitionSnapshotEntry | null> => {
  const snapshot = await source.loadSnapshot();
  return (
    snapshot.recognitionEntries.find(
      (entry) => entry.recognition.recognitionId === recognitionId,
    ) ?? null
  );
};

export const resolveRecognitionEntry = async (
  source: TrustRegistryApiStateSource,
  request: TrustRegistryApiResolveRecognitionRequest,
): Promise<TrustRegistryRecognitionSnapshotEntry | null> => {
  const snapshot = await source.loadSnapshot();
  const matches = snapshot.recognitionEntries.filter(
    (entry) =>
      entry.recognition.recognizedAuthorityDid === request.recognizedAuthorityDid
      && entry.recognition.scope.resourceId === request.scopeResourceId
      && (
        request.recognizedRegistryId === undefined
        || entry.recognition.recognizedRegistryId === request.recognizedRegistryId
      )
      && (
        request.scopeResourceType === undefined
        || entry.recognition.scope.resourceType === request.scopeResourceType
      )
      && (
        request.trustLevel === undefined
        || entry.recognition.trustLevel === request.trustLevel
      ),
  );

  return sortRecognitionEntries(matches).at(0) ?? null;
};

export const evaluateRecognitionEntryAtTimestamp = async (
  source: TrustRegistryApiStateSource,
  request: TrustRegistryApiResolveRecognitionRequest,
  evaluatedAt: string,
): Promise<SnapshotTemporalRecognitionInspection | null> =>
  resolveRecognitionEntryAtTimestamp(
    await source.loadSnapshot(),
    evaluatedAt,
    (entry) =>
      entry.recognition.recognizedAuthorityDid === request.recognizedAuthorityDid
      && entry.recognition.scope.resourceId === request.scopeResourceId
      && (
        request.recognizedRegistryId === undefined
        || entry.recognition.recognizedRegistryId === request.recognizedRegistryId
      )
      && (
        request.scopeResourceType === undefined
        || entry.recognition.scope.resourceType === request.scopeResourceType
      )
      && (
        request.trustLevel === undefined
        || entry.recognition.trustLevel === request.trustLevel
      ),
  );

export const createTrqpSourceFromStateSource = (
  source: TrustRegistryApiStateSource,
): TrustRegistryTrqpSource => ({
  async getRegistryRecord(authorityId: string): Promise<RegistryRecord | null> {
    const snapshot = await source.loadSnapshot();
    return snapshot.registry.registryDid === authorityId ? snapshot.registry : null;
  },
  async getAuthorizationBundle(
    request: TrqpAuthorizationRequest,
  ): Promise<TrustRegistryEvidenceBundle | null> {
    const snapshot = await source.loadSnapshot();
    if (snapshot.registry.registryDid !== request.authority_id) {
      return null;
    }

    const role = actionToAuthorizationRole(request.action);
    if (role === undefined) {
      return null;
    }

    const entry = await resolveAuthorizationEntry(source, {
      role,
      subjectDid: request.entity_id,
      resourceId: request.resource,
    });
    return entry?.evidence ?? null;
  },
  async getRecognitionBundle(
    request: TrqpRecognitionRequest,
  ): Promise<TrustRegistryEvidenceBundle | null> {
    const snapshot = await source.loadSnapshot();
    if (snapshot.registry.registryDid !== request.authority_id) {
      return null;
    }

    const recognizedRegistryId =
      typeof request.context?.recognized_registry_id === "string"
        ? request.context.recognized_registry_id
        : undefined;

    const entry = await resolveRecognitionEntry(source, {
      recognizedAuthorityDid: request.entity_id,
      recognizedRegistryId,
      scopeResourceId: request.resource,
      ...(request.action.length === 0 ? {} : {
        scopeResourceType: request.action as NonNullable<
          TrustRegistryApiResolveRecognitionRequest["scopeResourceType"]
        >,
      }),
    });

    return entry?.evidence ?? null;
  },
});
