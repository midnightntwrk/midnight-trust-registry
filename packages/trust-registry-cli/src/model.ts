import { z } from "zod";

import {
  AuthorizationRecordSchema,
  EpochCommitmentSchema,
  GovernancePolicyRecordSchema,
  RecognitionRecordSchema,
  RegistryRecordSchema,
  TrustRegistryEvidenceBundleSchema,
  type AuthorizationRecord,
  type EpochCommitment,
  type GovernancePolicyRecord,
  type RecognitionRecord,
  type RegistryRecord,
  type TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";

const SnapshotEntryLabelSchema = z.string().trim().min(1);

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
  recognitionEntries: z.array(TrustRegistryRecognitionSnapshotEntrySchema),
  notes: z.array(z.string()).default([]),
});

export type TrustRegistryOperatorSnapshot = z.infer<
  typeof TrustRegistryOperatorSnapshotSchema
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
  const recognitionCounts = defaultRecognitionStatusCounts();

  for (const entry of snapshot.issuerEntries) {
    issuerCounts[entry.authorization.status] += 1;
  }

  for (const entry of snapshot.verifierEntries) {
    verifierCounts[entry.authorization.status] += 1;
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
  currentEpoch: EpochCommitment;
  epochs: readonly EpochCommitment[];
  issuerEntries: readonly TrustRegistryAuthorizationSnapshotEntry[];
  notes: readonly string[];
  policy: GovernancePolicyRecord;
  recognitionEntries: readonly TrustRegistryRecognitionSnapshotEntry[];
  registry: RegistryRecord;
  verifierEntries: readonly TrustRegistryAuthorizationSnapshotEntry[];
};
