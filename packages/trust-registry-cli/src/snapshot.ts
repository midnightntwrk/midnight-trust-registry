import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import type {
  AuthorizationRecord,
  EpochCommitment,
  RecognitionRecord,
  TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  TrustRegistryOperatorSnapshotSchema,
  buildSummary,
  serializeJson,
  type SnapshotRegistryState,
  type TrustRegistryAuthorizationSnapshotEntry,
  type TrustRegistryOperatorSnapshot,
  type TrustRegistryRecognitionSnapshotEntry,
  type TrustRegistrySummary,
} from "./model.js";

export type SnapshotRecordKind =
  | "registry"
  | "policy"
  | "issuer"
  | "verifier"
  | "recognition"
  | "epoch";

export const loadSnapshotFromFile = async (
  snapshotPath: string,
): Promise<TrustRegistryOperatorSnapshot> => {
  const raw = await readFile(snapshotPath, "utf8");
  return TrustRegistryOperatorSnapshotSchema.parse(JSON.parse(raw));
};

export const writeSnapshotToFile = async (
  snapshotPath: string,
  snapshot: TrustRegistryOperatorSnapshot,
): Promise<void> => {
  await mkdir(dirname(snapshotPath), { recursive: true });
  await writeFile(
    snapshotPath,
    serializeJson(TrustRegistryOperatorSnapshotSchema.parse(snapshot)),
    "utf8",
  );
};

export const listIssuerEntries = (
  snapshot: SnapshotRegistryState,
): readonly TrustRegistryAuthorizationSnapshotEntry[] => snapshot.issuerEntries;

export const listVerifierEntries = (
  snapshot: SnapshotRegistryState,
): readonly TrustRegistryAuthorizationSnapshotEntry[] => snapshot.verifierEntries;

export const listRecognitionEntries = (
  snapshot: SnapshotRegistryState,
): readonly TrustRegistryRecognitionSnapshotEntry[] =>
  snapshot.recognitionEntries;

export const listEpochs = (
  snapshot: SnapshotRegistryState,
): readonly EpochCommitment[] => snapshot.epochs;

export const findIssuerEntry = (
  snapshot: SnapshotRegistryState,
  authorizationId: string,
): TrustRegistryAuthorizationSnapshotEntry => {
  const entry = snapshot.issuerEntries.find(
    (candidate) => candidate.authorization.authorizationId === authorizationId,
  );
  if (entry === undefined) {
    throw new Error(`unknown issuer authorization: ${authorizationId}`);
  }

  return entry;
};

export const findVerifierEntry = (
  snapshot: SnapshotRegistryState,
  authorizationId: string,
): TrustRegistryAuthorizationSnapshotEntry => {
  const entry = snapshot.verifierEntries.find(
    (candidate) => candidate.authorization.authorizationId === authorizationId,
  );
  if (entry === undefined) {
    throw new Error(`unknown verifier authorization: ${authorizationId}`);
  }

  return entry;
};

export const findRecognitionEntry = (
  snapshot: SnapshotRegistryState,
  recognitionId: string,
): TrustRegistryRecognitionSnapshotEntry => {
  const entry = snapshot.recognitionEntries.find(
    (candidate) => candidate.recognition.recognitionId === recognitionId,
  );
  if (entry === undefined) {
    throw new Error(`unknown recognition: ${recognitionId}`);
  }

  return entry;
};

export const findEpoch = (
  snapshot: SnapshotRegistryState,
  epochId?: string,
): EpochCommitment => {
  if (epochId === undefined) {
    return snapshot.currentEpoch;
  }

  const entry = snapshot.epochs.find((candidate) => candidate.epochId === epochId);
  if (entry === undefined) {
    throw new Error(`unknown epoch: ${epochId}`);
  }

  return entry;
};

export const exportEvidenceBundle = (
  snapshot: SnapshotRegistryState,
  kind: Extract<SnapshotRecordKind, "issuer" | "verifier" | "recognition">,
  id: string,
): TrustRegistryEvidenceBundle => {
  switch (kind) {
    case "issuer":
      return findIssuerEntry(snapshot, id).evidence;
    case "verifier":
      return findVerifierEntry(snapshot, id).evidence;
    case "recognition":
      return findRecognitionEntry(snapshot, id).evidence;
  }
};

export const renderSummary = (summary: TrustRegistrySummary): string =>
  [
    `Snapshot: ${summary.registryLabel} (${summary.snapshotVersion})`,
    `Generated: ${summary.generatedAt}`,
    `Registry: ${summary.registryId}`,
    `Registry DID: ${summary.registryDid}`,
    `Policy: ${summary.policyId}`,
    `Current epoch: ${summary.currentEpochId}`,
    `Epochs: ${summary.epochCount}`,
    `Issuers: ${renderStatusCounts(summary.issuerCounts)}`,
    `Verifiers: ${renderStatusCounts(summary.verifierCounts)}`,
    `Recognitions: ${renderStatusCounts(summary.recognitionCounts)}`,
  ].join("\n");

export const renderAuthorizationList = (
  entries: readonly TrustRegistryAuthorizationSnapshotEntry[],
): string =>
  entries
    .map(
      (entry) =>
        `${entry.authorization.authorizationId} | ${entry.authorization.status} | ${entry.authorization.subjectDid} | ${entry.authorization.resourceId}`,
    )
    .join("\n");

export const renderVerifierList = (
  entries: readonly TrustRegistryAuthorizationSnapshotEntry[],
): string =>
  entries
    .map(
      (entry) =>
        `${entry.authorization.authorizationId} | ${entry.authorization.status} | ${entry.authorization.subjectDid} | ${entry.authorization.resourceId}`,
    )
    .join("\n");

export const renderRecognitionList = (
  entries: readonly TrustRegistryRecognitionSnapshotEntry[],
): string =>
  entries
    .map(
      (entry) =>
        `${entry.recognition.recognitionId} | ${entry.recognition.status} | ${entry.recognition.recognizedAuthorityDid} | ${entry.recognition.recognizedRegistryId} | ${entry.recognition.scope.resourceId}`,
    )
    .join("\n");

export const renderEpochList = (
  epochs: readonly EpochCommitment[],
  currentEpochId: string,
): string =>
  epochs
    .map((epoch) =>
      [
        epoch.epochId,
        epoch.validFrom,
        epoch.validUntil,
        epoch.epochId === currentEpochId ? "current" : "historical",
      ].join(" | "),
    )
    .join("\n");

export const renderSnapshotRecord = (
  snapshot: SnapshotRegistryState,
  kind: SnapshotRecordKind,
  id?: string,
): RegistryInspectableRecord => {
  switch (kind) {
    case "registry":
      return snapshot.registry;
    case "policy":
      return snapshot.policy;
    case "issuer":
      if (id === undefined) {
        throw new Error("--id is required for issuer inspection");
      }
      return findIssuerEntry(snapshot, id);
    case "verifier":
      if (id === undefined) {
        throw new Error("--id is required for verifier inspection");
      }
      return findVerifierEntry(snapshot, id);
    case "recognition":
      if (id === undefined) {
        throw new Error("--id is required for recognition inspection");
      }
      return findRecognitionEntry(snapshot, id);
    case "epoch":
      return findEpoch(snapshot, id);
  }
};

export type RegistryInspectableRecord =
  | SnapshotRegistryState["registry"]
  | SnapshotRegistryState["policy"]
  | EpochCommitment
  | TrustRegistryAuthorizationSnapshotEntry
  | TrustRegistryRecognitionSnapshotEntry;

export const buildSnapshotSummary = (
  snapshot: TrustRegistryOperatorSnapshot,
): TrustRegistrySummary => buildSummary(snapshot);

const renderStatusCounts = (
  counts: Record<
    AuthorizationRecord["status"] | RecognitionRecord["status"],
    number
  >,
): string =>
  [
    `${counts.proposed} proposed`,
    `${counts.authorized} authorized`,
    `${counts.active} active`,
    `${counts.suspended} suspended`,
    `${counts.revoked} revoked`,
    `${counts.superseded} superseded`,
    `${counts.archived} archived`,
  ].join(", ");
