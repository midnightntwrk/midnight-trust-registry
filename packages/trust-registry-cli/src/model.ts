import { z } from "zod";

import {
  AuthorizationRecordSchema,
  EpochCommitmentSchema,
  GovernancePolicyRecordSchema,
  RecognitionRecordSchema,
  RegistryRecordSchema,
  TrustRegistryEvidenceBundleSchema,
  computeAuthorizationStatementLeafHash,
  computeGovernancePolicySnapshotCommitment,
  computeMerkleRootFromProof,
  computeRecognitionStatementLeafHash,
  deriveGovernancePolicySnapshot,
  type AuthorizationRecord,
  type EpochCommitment,
  type GovernancePolicyRecord,
  type RecognitionRecord,
  type RegistryRecord,
  type TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";

const SnapshotEntryLabelSchema = z.string().trim().min(1);
const WorkspaceTargetIdSchema = z.string().trim().min(1);

export const MutableSnapshotTargetSchema = z.enum([
  "issuer",
  "verifier",
  "auditor",
  "recognition",
]);

export type MutableSnapshotTarget = z.infer<typeof MutableSnapshotTargetSchema>;

export const TrustRegistryAuthorizationSnapshotEntrySchema = z.object({
  label: SnapshotEntryLabelSchema,
  authorization: AuthorizationRecordSchema,
  evidence: TrustRegistryEvidenceBundleSchema,
});

export type TrustRegistryAuthorizationSnapshotEntry = z.infer<
  typeof TrustRegistryAuthorizationSnapshotEntrySchema
>;

export const TrustRegistryRecognitionSnapshotEntrySchema = z.object({
  label: SnapshotEntryLabelSchema,
  recognition: RecognitionRecordSchema,
  evidence: TrustRegistryEvidenceBundleSchema,
});

export type TrustRegistryRecognitionSnapshotEntry = z.infer<
  typeof TrustRegistryRecognitionSnapshotEntrySchema
>;

// Snapshot consistency is not an independently authenticated epoch or quorum witness.
const hasConsistentSnapshotProof = (
  bundle: TrustRegistryEvidenceBundle,
  leafHash: string,
  epochs: readonly EpochCommitment[],
  registryId: string,
): boolean => {
  const epoch = epochs.find((candidate) => candidate.epochId === bundle.epoch.epochId);
  if (epoch === undefined
    || JSON.stringify(epoch) !== JSON.stringify(bundle.epoch)
    || bundle.epoch.registryId !== registryId
    || bundle.policy.registryId !== registryId
    || bundle.inclusionProof.leafHash !== leafHash
    || bundle.inclusionProof.root !== bundle.epoch.stateRoot
    || bundle.inclusionProof.path[0] !== bundle.epoch.eventRoot) return false;
  try {
    return computeGovernancePolicySnapshotCommitment(
      deriveGovernancePolicySnapshot(bundle.policy),
    ) === bundle.epoch.policyRoot && computeMerkleRootFromProof(
      leafHash,
      bundle.inclusionProof.path,
      bundle.inclusionProof.leafIndex,
    ) === bundle.epoch.stateRoot;
  } catch {
    return false;
  }
};

export const TrustRegistryOperatorWorkspaceOperationSchema = z.discriminatedUnion(
  "operation",
  [
    z.object({
      operation: z.literal("submit"),
      target: MutableSnapshotTargetSchema,
      label: SnapshotEntryLabelSchema,
    }),
    z.object({
      operation: z.literal("approve"),
      target: MutableSnapshotTargetSchema,
      id: WorkspaceTargetIdSchema,
    }),
    z.object({
      operation: z.literal("activate"),
      target: MutableSnapshotTargetSchema,
      id: WorkspaceTargetIdSchema,
    }),
    z.object({
      operation: z.literal("suspend"),
      target: MutableSnapshotTargetSchema,
      id: WorkspaceTargetIdSchema,
    }),
    z.object({
      operation: z.literal("revoke"),
      target: MutableSnapshotTargetSchema,
      id: WorkspaceTargetIdSchema,
    }),
    z.object({
      operation: z.literal("archive"),
      target: MutableSnapshotTargetSchema,
      id: WorkspaceTargetIdSchema,
    }),
    z.object({
      operation: z.literal("publish-epoch"),
      label: SnapshotEntryLabelSchema.optional(),
    }),
  ],
);

export type TrustRegistryOperatorWorkspaceOperation = z.infer<
  typeof TrustRegistryOperatorWorkspaceOperationSchema
>;

export const TrustRegistryOperatorSnapshotSchema = z.object({
  snapshotVersion: z.literal("1"),
  generatedAt: z.string().datetime({ offset: true }),
  registryLabel: SnapshotEntryLabelSchema,
  registry: RegistryRecordSchema,
  policy: GovernancePolicyRecordSchema,
  currentEpoch: EpochCommitmentSchema,
  epochs: z.array(EpochCommitmentSchema).min(1),
  issuerEntries: z.array(TrustRegistryAuthorizationSnapshotEntrySchema),
  verifierEntries: z.array(TrustRegistryAuthorizationSnapshotEntrySchema),
  auditorEntries: z.array(TrustRegistryAuthorizationSnapshotEntrySchema),
  recognitionEntries: z.array(TrustRegistryRecognitionSnapshotEntrySchema),
  evidenceArchive: z.array(TrustRegistryEvidenceBundleSchema),
  notes: z.array(z.string()).default([]),
}).superRefine((snapshot, ctx) => {
  for (const [role, entries] of [
    ["issuer", snapshot.issuerEntries],
    ["verifier", snapshot.verifierEntries],
    ["auditor", snapshot.auditorEntries],
  ] as const) {
    for (const [index, entry] of entries.entries()) {
      const expectedLeafHash = computeAuthorizationStatementLeafHash(entry.authorization);
      if (entry.authorization.role !== role
        || entry.authorization.registryId !== snapshot.registry.registryId
        || entry.evidence.authorization === undefined
        || entry.evidence.authorization?.authorizationId !== entry.authorization.authorizationId
        || entry.evidence.authorization?.role !== role
        || entry.evidence.registryId !== snapshot.registry.registryId
        || computeAuthorizationStatementLeafHash(entry.evidence.authorization) !== expectedLeafHash
        || !hasConsistentSnapshotProof(
          entry.evidence, expectedLeafHash, snapshot.epochs, snapshot.registry.registryId,
        )) {
        ctx.addIssue({
          code: "custom",
          path: [`${role}Entries`, index],
          message: `${role} entry must contain a matching statement and internally consistent snapshot proof`,
        });
      }
    }
  }
  for (const [index, entry] of snapshot.recognitionEntries.entries()) {
    const expectedLeafHash = computeRecognitionStatementLeafHash(entry.recognition);
    if (entry.recognition.registryId !== snapshot.registry.registryId
      || entry.evidence.recognition === undefined
      || entry.evidence.recognition?.recognitionId !== entry.recognition.recognitionId
      || computeRecognitionStatementLeafHash(entry.evidence.recognition) !== expectedLeafHash
      || entry.evidence.registryId !== snapshot.registry.registryId
      || !hasConsistentSnapshotProof(
        entry.evidence, expectedLeafHash, snapshot.epochs, snapshot.registry.registryId,
      )) {
      ctx.addIssue({
        code: "custom",
        path: ["recognitionEntries", index],
        message: "recognition entry must contain a matching statement and internally consistent snapshot proof",
      });
    }
  }
  const archivedIds = new Set<string>();
  for (const [index, bundle] of snapshot.evidenceArchive.entries()) {
    const authorization = bundle.authorization;
    const recognition = bundle.recognition;
    const recordId = authorization?.authorizationId ?? recognition?.recognitionId;
    const recordKind = authorization?.role ?? "recognition";
    const archiveId = `${recordKind}:${recordId ?? "missing"}:${bundle.epoch.epochId}`;
    const current = authorization === undefined
      ? snapshot.recognitionEntries.find((entry) => entry.recognition.recognitionId === recordId)
      : [
          ...snapshot.issuerEntries,
          ...snapshot.verifierEntries,
          ...snapshot.auditorEntries,
        ].find((entry) => entry.authorization.authorizationId === recordId);
    const sameIdentity = authorization === undefined
      ? current !== undefined && "recognition" in current
        && current.recognition.recognizedAuthorityDid === recognition?.recognizedAuthorityDid
        && current.recognition.recognizedRegistryId === recognition?.recognizedRegistryId
        && current.recognition.scope.resourceType === recognition?.scope.resourceType
        && current.recognition.scope.resourceId === recognition?.scope.resourceId
        && Object.keys(current.recognition.scope.context ?? {}).length === Object.keys(recognition?.scope.context ?? {}).length
        && Object.entries(current.recognition.scope.context ?? {}).every(
          ([key, value]) => recognition?.scope.context?.[key] === value,
        )
      : current !== undefined && "authorization" in current
        && current.authorization.role === authorization.role
        && current.authorization.subjectDid === authorization.subjectDid
        && current.authorization.resourceType === authorization.resourceType
        && current.authorization.resourceId === authorization.resourceId;
    const leafHash = authorization === undefined
      ? recognition === undefined ? null : computeRecognitionStatementLeafHash(recognition)
      : computeAuthorizationStatementLeafHash(authorization);
    if (archivedIds.has(archiveId) || !sameIdentity || leafHash === null
      || !hasConsistentSnapshotProof(bundle, leafHash, snapshot.epochs, snapshot.registry.registryId)) {
      ctx.addIssue({
        code: "custom",
        path: ["evidenceArchive", index],
        message: "archived evidence must have a unique record and epoch with a matching snapshot proof",
      });
    }
    archivedIds.add(archiveId);
  }
});

export type TrustRegistryOperatorSnapshot = z.infer<
  typeof TrustRegistryOperatorSnapshotSchema
>;

export const TrustRegistryOperatorWorkspaceSchema = z.object({
  workspaceVersion: z.literal("1"),
  updatedAt: z.string().datetime({ offset: true }),
  registryLabel: SnapshotEntryLabelSchema,
  operations: z.array(TrustRegistryOperatorWorkspaceOperationSchema),
  snapshot: TrustRegistryOperatorSnapshotSchema,
});

export type TrustRegistryOperatorWorkspace = z.infer<
  typeof TrustRegistryOperatorWorkspaceSchema
>;

export type TrustRegistrySummary = {
  snapshotVersion: TrustRegistryOperatorSnapshot["snapshotVersion"];
  generatedAt: string;
  registryLabel: string;
  registryId: string;
  registryDid: string;
  policyId: string;
  currentEpochId: string;
  epochCount: number;
  issuerCounts: Record<AuthorizationRecord["status"], number>;
  verifierCounts: Record<AuthorizationRecord["status"], number>;
  auditorCounts: Record<AuthorizationRecord["status"], number>;
  recognitionCounts: Record<RecognitionRecord["status"], number>;
};

export const defaultAuthorizationStatusCounts = (): Record<
  AuthorizationRecord["status"],
  number
> => ({
  proposed: 0,
  authorized: 0,
  active: 0,
  suspended: 0,
  revoked: 0,
  superseded: 0,
  archived: 0,
});

export const defaultRecognitionStatusCounts = (): Record<
  RecognitionRecord["status"],
  number
> => ({
  proposed: 0,
  authorized: 0,
  active: 0,
  suspended: 0,
  revoked: 0,
  superseded: 0,
  archived: 0,
});

export const collectAuthorizationRecord = (
  bundle: TrustRegistryEvidenceBundle,
  role: AuthorizationRecord["role"],
): AuthorizationRecord => {
  const record = bundle.authorization;
  if (record === undefined || record.role !== role) {
    throw new Error(`expected ${role} authorization evidence`);
  }

  return AuthorizationRecordSchema.parse(record);
};

export const collectRecognitionRecord = (
  bundle: TrustRegistryEvidenceBundle,
): RecognitionRecord => {
  if (bundle.recognition === undefined) {
    throw new Error("expected recognition evidence");
  }

  return RecognitionRecordSchema.parse(bundle.recognition);
};

export const collectDistinctEpochs = (
  bundles: readonly TrustRegistryEvidenceBundle[],
): EpochCommitment[] => {
  const epochs = new Map<string, EpochCommitment>();
  for (const bundle of bundles) {
    epochs.set(bundle.epoch.epochId, EpochCommitmentSchema.parse(bundle.epoch));
  }

  return Array.from(epochs.values()).sort((left, right) =>
    left.validFrom.localeCompare(right.validFrom),
  );
};

export const buildSummary = (
  snapshot: TrustRegistryOperatorSnapshot,
): TrustRegistrySummary => {
  const issuerCounts = defaultAuthorizationStatusCounts();
  const verifierCounts = defaultAuthorizationStatusCounts();
  const auditorCounts = defaultAuthorizationStatusCounts();
  const recognitionCounts = defaultRecognitionStatusCounts();

  for (const entry of snapshot.issuerEntries) {
    issuerCounts[entry.authorization.status] += 1;
  }

  for (const entry of snapshot.verifierEntries) {
    verifierCounts[entry.authorization.status] += 1;
  }

  for (const entry of snapshot.auditorEntries) {
    auditorCounts[entry.authorization.status] += 1;
  }

  for (const entry of snapshot.recognitionEntries) {
    recognitionCounts[entry.recognition.status] += 1;
  }

  return {
    snapshotVersion: snapshot.snapshotVersion,
    generatedAt: snapshot.generatedAt,
    registryLabel: snapshot.registryLabel,
    registryId: snapshot.registry.registryId,
    registryDid: snapshot.registry.registryDid,
    policyId: snapshot.policy.policyId,
    currentEpochId: snapshot.currentEpoch.epochId,
    epochCount: snapshot.epochs.length,
    issuerCounts,
    verifierCounts,
    auditorCounts,
    recognitionCounts,
  };
};

export const hasCurrentEpoch = (
  snapshot: TrustRegistryOperatorSnapshot,
  epochId: string,
): boolean => snapshot.currentEpoch.epochId === epochId;

export const serializeJson = (value: unknown): string =>
  `${JSON.stringify(value, null, 2)}\n`;

export type SnapshotRegistryState = {
  auditorEntries: readonly TrustRegistryAuthorizationSnapshotEntry[];
  currentEpoch: EpochCommitment;
  epochs: readonly EpochCommitment[];
  issuerEntries: readonly TrustRegistryAuthorizationSnapshotEntry[];
  notes: readonly string[];
  policy: GovernancePolicyRecord;
  recognitionEntries: readonly TrustRegistryRecognitionSnapshotEntry[];
  registry: RegistryRecord;
  verifierEntries: readonly TrustRegistryAuthorizationSnapshotEntry[];
};
