import { mkdir, open, readFile, rename, rm, unlink, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dirname, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  LocalTrustRegistryIntegrationHarness,
  createAuditorScenarioFixture,
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
  type AuditorScenarioFixture,
  type IssuerScenarioFixture,
  type RecognitionScenarioFixture,
  type VerifierScenarioFixture,
  bytes32Commitment,
} from "@midnightntwrk/trust-registry-integration";
import { createScopedIdentifier, type EpochCommitment, type TrustRegistryEvidenceBundle } from "@midnightntwrk/trust-registry-domain";

import {
  TrustRegistryOperatorWorkspaceSchema,
  collectAuthorizationRecord,
  collectDistinctEpochs,
  collectRecognitionRecord,
  serializeJson,
  type TrustRegistryAuthorizationSnapshotEntry,
  type TrustRegistryOperatorSnapshot,
  type TrustRegistryOperatorWorkspace,
  type TrustRegistryOperatorWorkspaceOperation,
  type TrustRegistryRecognitionSnapshotEntry,
} from "./model.js";

type TrackedIssuerFixture = {
  fixture: IssuerScenarioFixture;
  label: string;
};

type TrackedVerifierFixture = {
  fixture: VerifierScenarioFixture;
  label: string;
};

type TrackedAuditorFixture = {
  fixture: AuditorScenarioFixture;
  label: string;
};

type TrackedRecognitionFixture = {
  fixture: RecognitionScenarioFixture;
  label: string;
};

type TrackedFixtures = {
  auditors: Map<string, TrackedAuditorFixture>;
  issuers: Map<string, TrackedIssuerFixture>;
  recognitions: Map<string, TrackedRecognitionFixture>;
  verifiers: Map<string, TrackedVerifierFixture>;
};

export type SimulatorSnapshotFixtures = {
  label: string;
  issuers?: readonly TrackedIssuerFixture[];
  verifiers?: readonly TrackedVerifierFixture[];
  auditors?: readonly TrackedAuditorFixture[];
  recognitions?: readonly TrackedRecognitionFixture[];
};

const assertNever = (value: never): never => {
  throw new Error(`unexpected mutable target: ${String(value)}`);
};

const createTrackedFixtures = (): TrackedFixtures => ({
  auditors: new Map<string, TrackedAuditorFixture>(),
  issuers: new Map<string, TrackedIssuerFixture>(),
  recognitions: new Map<string, TrackedRecognitionFixture>(),
  verifiers: new Map<string, TrackedVerifierFixture>(),
});

const writeWorkspaceJson = async (
  workspacePath: string,
  workspace: TrustRegistryOperatorWorkspace,
): Promise<void> => {
  await mkdir(dirname(workspacePath), { recursive: true });
  const temporaryPath = `${workspacePath}.${randomUUID()}.tmp`;
  try {
    await writeFile(
      temporaryPath,
      serializeJson(TrustRegistryOperatorWorkspaceSchema.parse(workspace)),
      { encoding: "utf8", flag: "wx" },
    );
    await rename(temporaryPath, workspacePath);
  } finally {
    await rm(temporaryPath, { force: true });
  }
};

const loadWorkspaceJson = async (
  workspacePath: string,
): Promise<TrustRegistryOperatorWorkspace> => {
  const raw = await readFile(workspacePath, "utf8");
  const parsed: unknown = JSON.parse(raw);
  if (parsed !== null && typeof parsed === "object" && "workspaceVersion" in parsed
    && (parsed.workspaceVersion === "1" || parsed.workspaceVersion === "2")) {
    throw new Error(`Workspace version ${parsed.workspaceVersion} is unsupported; recreate the pre-release workspace before mutation`);
  }
  return TrustRegistryOperatorWorkspaceSchema.parse(parsed);
};

export class WorkspaceMutationLockedError extends Error {
  constructor() {
    super("Operator workspace is locked by another writer; stale locks require operator recovery");
    this.name = "WorkspaceMutationLockedError";
  }
}

export const withExclusiveWorkspaceWrite = async <T>(
  workspacePath: string,
  operation: () => Promise<T>,
): Promise<T> => {
  const lockPath = `${resolve(workspacePath)}.lock`;
  await mkdir(dirname(lockPath), { recursive: true });
  let lock;
  try {
    lock = await open(lockPath, "wx", 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new WorkspaceMutationLockedError();
    }
    throw error;
  }
  try {
    return await operation();
  } finally {
    await lock.close();
    await unlink(lockPath);
  }
};

const currentOrHistoricalIssuerEvidence = async (
  harness: LocalTrustRegistryIntegrationHarness,
  fixture: IssuerScenarioFixture,
): Promise<TrustRegistryEvidenceBundle> => {
  if (await harness.readIssuerAuthorizationStatus(fixture) === "active") {
    return await harness.evaluateCurrentIssuerDecision(fixture);
  }

  return await harness.buildIssuerHistoricalEvidence(fixture);
};

const currentOrHistoricalVerifierEvidence = async (
  harness: LocalTrustRegistryIntegrationHarness,
  fixture: VerifierScenarioFixture,
): Promise<TrustRegistryEvidenceBundle> => {
  if (await harness.readVerifierAuthorizationStatus(fixture) === "active") {
    return await harness.evaluateCurrentVerifierDecision(fixture);
  }

  return await harness.buildVerifierHistoricalEvidence(fixture);
};

const currentOrHistoricalAuditorEvidence = async (
  harness: LocalTrustRegistryIntegrationHarness,
  fixture: AuditorScenarioFixture,
): Promise<TrustRegistryEvidenceBundle> => {
  const historical = await harness.buildAuditorHistoricalEvidence(fixture);
  return historical.authorization?.status === "active"
    ? await harness.evaluateCurrentAuditorDecision(fixture)
    : historical;
};

const currentOrHistoricalRecognitionEvidence = async (
  harness: LocalTrustRegistryIntegrationHarness,
  fixture: RecognitionScenarioFixture,
): Promise<TrustRegistryEvidenceBundle> => {
  if (await harness.readRecognitionStatus(fixture) === "active") {
    return await harness.evaluateCurrentRecognitionDecision(fixture);
  }

  return await harness.buildRecognitionHistoricalEvidence(fixture);
};

const issuerEntryFromFixture = async (
  harness: LocalTrustRegistryIntegrationHarness,
  tracked: TrackedIssuerFixture,
): Promise<TrustRegistryAuthorizationSnapshotEntry> => {
  const evidence = await currentOrHistoricalIssuerEvidence(harness, tracked.fixture);
  return {
    label: tracked.label,
    authorization: collectAuthorizationRecord(evidence, "issuer"),
    evidence,
  };
};

const verifierEntryFromFixture = async (
  harness: LocalTrustRegistryIntegrationHarness,
  tracked: TrackedVerifierFixture,
): Promise<TrustRegistryAuthorizationSnapshotEntry> => {
  const evidence = await currentOrHistoricalVerifierEvidence(harness, tracked.fixture);
  return {
    label: tracked.label,
    authorization: collectAuthorizationRecord(evidence, "verifier"),
    evidence,
  };
};

const auditorEntryFromFixture = async (
  harness: LocalTrustRegistryIntegrationHarness,
  tracked: TrackedAuditorFixture,
): Promise<TrustRegistryAuthorizationSnapshotEntry> => {
  const evidence = await currentOrHistoricalAuditorEvidence(harness, tracked.fixture);
  return {
    label: tracked.label,
    authorization: collectAuthorizationRecord(evidence, "auditor"),
    evidence,
  };
};

const recognitionEntryFromFixture = async (
  harness: LocalTrustRegistryIntegrationHarness,
  tracked: TrackedRecognitionFixture,
): Promise<TrustRegistryRecognitionSnapshotEntry> => {
  const evidence = await currentOrHistoricalRecognitionEvidence(harness, tracked.fixture);
  return {
    label: tracked.label,
    recognition: collectRecognitionRecord(evidence),
    evidence,
  };
};

const buildSnapshotFromTrackedFixtures = async (
  label: string,
  operationCount: number,
  harness: LocalTrustRegistryIntegrationHarness,
  trackedFixtures: TrackedFixtures,
  notes: readonly string[] = [
    "Operator workspace snapshot derived from governed CLI operations.",
    `Replayed operations: ${operationCount.toString()}.`,
  ],
  publishedRegistryEpoch?: EpochCommitment,
): Promise<TrustRegistryOperatorSnapshot> => {
  const registryEpoch = publishedRegistryEpoch ?? await harness.publishRegistryEpoch("workspace-current");
  const issuerEntries: TrustRegistryAuthorizationSnapshotEntry[] = [];
  for (const tracked of trackedFixtures.issuers.values()) {
    issuerEntries.push(await issuerEntryFromFixture(harness, tracked));
  }
  issuerEntries.sort((left, right) =>
    left.authorization.authorizationId.localeCompare(right.authorization.authorizationId));
  const verifierEntries: TrustRegistryAuthorizationSnapshotEntry[] = [];
  for (const tracked of trackedFixtures.verifiers.values()) {
    verifierEntries.push(await verifierEntryFromFixture(harness, tracked));
  }
  verifierEntries.sort((left, right) =>
    left.authorization.authorizationId.localeCompare(right.authorization.authorizationId));
  const auditorEntries: TrustRegistryAuthorizationSnapshotEntry[] = [];
  for (const tracked of trackedFixtures.auditors.values()) {
    auditorEntries.push(await auditorEntryFromFixture(harness, tracked));
  }
  auditorEntries.sort((left, right) =>
    left.authorization.authorizationId.localeCompare(right.authorization.authorizationId));
  const recognitionEntries: TrustRegistryRecognitionSnapshotEntry[] = [];
  for (const tracked of trackedFixtures.recognitions.values()) {
    recognitionEntries.push(await recognitionEntryFromFixture(harness, tracked));
  }
  recognitionEntries.sort((left, right) =>
    left.recognition.recognitionId.localeCompare(right.recognition.recognitionId));

  const epochsById = new Map<string, TrustRegistryOperatorSnapshot["currentEpoch"]>([
    [registryEpoch.epochId, registryEpoch],
  ]);
  for (const epoch of collectDistinctEpochs([
    ...issuerEntries.map((entry) => entry.evidence),
    ...verifierEntries.map((entry) => entry.evidence),
    ...auditorEntries.map((entry) => entry.evidence),
    ...recognitionEntries.map((entry) => entry.evidence),
  ])) {
    epochsById.set(epoch.epochId, epoch);
  }
  const epochs = Array.from(epochsById.values()).sort((left, right) =>
    left.validFrom.localeCompare(right.validFrom),
  );
  const ledgerCurrentEpochId = (await harness.simulator.getCurrentEpochCommitment()).epochId;
  const currentEpoch = epochs.find((epoch) =>
    Buffer.from(bytes32Commitment(epoch.epochId)).equals(Buffer.from(ledgerCurrentEpochId)));
  if (currentEpoch === undefined) {
    throw new Error("Current Compact epoch is missing from the projected snapshot");
  }

  return {
    snapshotVersion: "1",
    generatedAt: currentEpoch.validUntil,
    registryLabel: label,
    registry: harness.registryRecord,
    policy: harness.policyRecord,
    currentEpoch,
    epochs,
    issuerEntries,
    verifierEntries,
    auditorEntries,
    recognitionEntries,
    evidenceArchive: [],
    notes: [...notes],
  };
};

/** Publishes a simulator epoch and projects the same governed state into the API snapshot model. */
export const publishSimulatorSnapshot = async (
  harness: LocalTrustRegistryIntegrationHarness,
  fixtures: SimulatorSnapshotFixtures,
  previous?: TrustRegistryOperatorSnapshot,
  publishedRegistryEpoch?: EpochCommitment,
): Promise<TrustRegistryOperatorSnapshot> => {
  if (publishedRegistryEpoch !== undefined) {
    if (publishedRegistryEpoch.registryId !== harness.registryId) {
      throw new Error("Published registry epoch belongs to another registry");
    }
    await harness.getEpochPublicationWitness(publishedRegistryEpoch.epochId);
    if (!isDeepStrictEqual(
      publishedRegistryEpoch,
      await harness.getPublishedEpochCommitment(publishedRegistryEpoch.epochId),
    )) {
      throw new Error("Published registry epoch does not match the Compact ledger commitment");
    }
    const ledger = await harness.simulator.getLedger();
    if (!Buffer.from((await harness.simulator.getCurrentEpochCommitment()).epochId)
      .equals(Buffer.from(bytes32Commitment(publishedRegistryEpoch.epochId)))) {
      throw new Error("Published registry epoch is not the current Compact epoch");
    }
    const statusSequences: bigint[] = [];
    for (const { fixture } of fixtures.issuers ?? []) {
      statusSequences.push((await harness.simulator.getIssuerAuthorization(fixture.authorizationIdCommitment)).lastStatusSequence);
    }
    for (const { fixture } of fixtures.verifiers ?? []) {
      statusSequences.push((await harness.simulator.getVerifierAuthorization(fixture.authorizationIdCommitment)).lastStatusSequence);
    }
    for (const { fixture } of fixtures.auditors ?? []) {
      statusSequences.push((await harness.simulator.getAuditorAuthorization(fixture.authorizationIdCommitment)).lastStatusSequence);
    }
    for (const { fixture } of fixtures.recognitions ?? []) {
      statusSequences.push((await harness.simulator.getRecognition(fixture.recognitionIdCommitment)).lastStatusSequence);
    }
    for (const sequence of statusSequences) {
      const epochId = createScopedIdentifier("epoch", harness.registryId, `seq-${sequence.toString()}`);
      if (!ledger.epochCommitmentIds.member(bytes32Commitment(epochId))) {
        throw new Error("Snapshot projection requires grant evidence before the signed registry epoch");
      }
    }
  }
  const tracked = createTrackedFixtures();
  for (const entry of fixtures.issuers ?? []) {
    if (tracked.issuers.has(entry.fixture.authorizationId)) throw new Error("Duplicate issuer fixture");
    tracked.issuers.set(entry.fixture.authorizationId, entry);
  }
  for (const entry of fixtures.verifiers ?? []) {
    if (tracked.verifiers.has(entry.fixture.authorizationId)) throw new Error("Duplicate verifier fixture");
    tracked.verifiers.set(entry.fixture.authorizationId, entry);
  }
  for (const entry of fixtures.auditors ?? []) {
    if (tracked.auditors.has(entry.fixture.authorizationId)) throw new Error("Duplicate auditor fixture");
    tracked.auditors.set(entry.fixture.authorizationId, entry);
  }
  for (const entry of fixtures.recognitions ?? []) {
    if (tracked.recognitions.has(entry.fixture.recognitionId)) throw new Error("Duplicate recognition fixture");
    tracked.recognitions.set(entry.fixture.recognitionId, entry);
  }
  const next = await buildSnapshotFromTrackedFixtures(fixtures.label, 0, harness, tracked, [
    "Snapshot projected from the supplied Compact simulator state.",
  ], publishedRegistryEpoch);
  if (publishedRegistryEpoch !== undefined && next.currentEpoch.epochId !== publishedRegistryEpoch.epochId) {
    throw new Error("Snapshot projection changed the latest governed epoch");
  }
  if (previous !== undefined && previous.registry.registryId !== next.registry.registryId) {
    throw new Error("Cannot retain evidence from another registry");
  }
  return previous === undefined ? next : retainHistoricalEvidence(previous, next);
};

const snapshotBundles = (
  snapshot: TrustRegistryOperatorSnapshot,
): TrustRegistryEvidenceBundle[] => [
  ...snapshot.issuerEntries.map((entry) => entry.evidence),
  ...snapshot.verifierEntries.map((entry) => entry.evidence),
  ...snapshot.auditorEntries.map((entry) => entry.evidence),
  ...snapshot.recognitionEntries.map((entry) => entry.evidence),
];

const archiveKey = (bundle: TrustRegistryEvidenceBundle): string =>
  `${bundle.authorization?.role ?? "recognition"}:${bundle.authorization?.authorizationId ?? bundle.recognition?.recognitionId}:${bundle.epoch.epochId}`;

const retainHistoricalEvidence = (
  previous: TrustRegistryOperatorSnapshot,
  next: TrustRegistryOperatorSnapshot,
): TrustRegistryOperatorSnapshot => {
  const nextCurrent = new Set(snapshotBundles(next).map(archiveKey));
  const archive = new Map(previous.evidenceArchive.map((bundle) => [archiveKey(bundle), bundle]));
  for (const bundle of snapshotBundles(previous)) {
    const key = archiveKey(bundle);
    if (!nextCurrent.has(key)) archive.set(key, bundle);
  }
  const epochs = new Map(previous.epochs.map((epoch) => [epoch.epochId, epoch]));
  for (const epoch of next.epochs) epochs.set(epoch.epochId, epoch);
  return {
    ...next,
    epochs: Array.from(epochs.values()).sort((left, right) =>
      left.validFrom.localeCompare(right.validFrom) || left.epochId.localeCompare(right.epochId)),
    evidenceArchive: Array.from(archive.values()),
  };
};

const requireIssuerFixture = (
  trackedFixtures: TrackedFixtures,
  authorizationId: string,
): IssuerScenarioFixture => {
  const fixture = trackedFixtures.issuers.get(authorizationId);
  if (fixture === undefined) {
    throw new Error(`unknown issuer authorization: ${authorizationId}`);
  }

  return fixture.fixture;
};

const requireVerifierFixture = (
  trackedFixtures: TrackedFixtures,
  authorizationId: string,
): VerifierScenarioFixture => {
  const fixture = trackedFixtures.verifiers.get(authorizationId);
  if (fixture === undefined) {
    throw new Error(`unknown verifier authorization: ${authorizationId}`);
  }

  return fixture.fixture;
};

const requireAuditorFixture = (
  trackedFixtures: TrackedFixtures,
  authorizationId: string,
): AuditorScenarioFixture => {
  const fixture = trackedFixtures.auditors.get(authorizationId);
  if (fixture === undefined) {
    throw new Error(`unknown auditor authorization: ${authorizationId}`);
  }
  return fixture.fixture;
};

const requireRecognitionFixture = (
  trackedFixtures: TrackedFixtures,
  recognitionId: string,
): RecognitionScenarioFixture => {
  const fixture = trackedFixtures.recognitions.get(recognitionId);
  if (fixture === undefined) {
    throw new Error(`unknown recognition: ${recognitionId}`);
  }

  return fixture.fixture;
};

const applyMutableOperation = async (
  harness: LocalTrustRegistryIntegrationHarness,
  trackedFixtures: TrackedFixtures,
  operation: TrustRegistryOperatorWorkspaceOperation,
): Promise<void> => {
  switch (operation.operation) {
    case "submit": {
      switch (operation.target) {
        case "issuer": {
          const fixture = createIssuerScenarioFixture(operation.label);
          if (trackedFixtures.issuers.has(fixture.authorizationId)) {
            throw new Error(`issuer label already submitted: ${operation.label}`);
          }
          await harness.proposeIssuer(fixture);
          trackedFixtures.issuers.set(fixture.authorizationId, {
            label: operation.label,
            fixture,
          });
          return;
        }
        case "verifier": {
          const fixture = createVerifierScenarioFixture(operation.label);
          if (trackedFixtures.verifiers.has(fixture.authorizationId)) {
            throw new Error(`verifier label already submitted: ${operation.label}`);
          }
          await harness.proposeVerifier(fixture);
          trackedFixtures.verifiers.set(fixture.authorizationId, {
            label: operation.label,
            fixture,
          });
          return;
        }
        case "auditor": {
          const fixture = createAuditorScenarioFixture(operation.label);
          if (trackedFixtures.auditors.has(fixture.authorizationId)) {
            throw new Error(`auditor label already submitted: ${operation.label}`);
          }
          await harness.proposeAuditor(fixture);
          trackedFixtures.auditors.set(fixture.authorizationId, {
            label: operation.label,
            fixture,
          });
          return;
        }
        case "recognition": {
          const fixture = createRecognitionScenarioFixture(operation.label);
          if (trackedFixtures.recognitions.has(fixture.recognitionId)) {
            throw new Error(`recognition label already submitted: ${operation.label}`);
          }
          await harness.proposeRecognition(fixture);
          trackedFixtures.recognitions.set(fixture.recognitionId, {
            label: operation.label,
            fixture,
          });
          return;
        }
        default:
          return assertNever(operation.target);
      }
    }
    case "approve": {
      switch (operation.target) {
        case "issuer":
          await harness.approveIssuer(requireIssuerFixture(trackedFixtures, operation.id));
          return;
        case "verifier":
          await harness.approveVerifier(requireVerifierFixture(trackedFixtures, operation.id));
          return;
        case "auditor":
          await harness.approveAuditor(requireAuditorFixture(trackedFixtures, operation.id));
          return;
        case "recognition":
          await harness.approveRecognition(
            requireRecognitionFixture(trackedFixtures, operation.id),
          );
          return;
        default:
          return assertNever(operation.target);
      }
    }
    case "activate": {
      switch (operation.target) {
        case "issuer":
          await harness.activateIssuer(requireIssuerFixture(trackedFixtures, operation.id));
          return;
        case "verifier":
          await harness.activateVerifier(requireVerifierFixture(trackedFixtures, operation.id));
          return;
        case "auditor":
          await harness.activateAuditor(requireAuditorFixture(trackedFixtures, operation.id));
          return;
        case "recognition":
          await harness.activateRecognition(
            requireRecognitionFixture(trackedFixtures, operation.id),
          );
          return;
        default:
          return assertNever(operation.target);
      }
    }
    case "suspend": {
      switch (operation.target) {
        case "issuer":
          await harness.suspendIssuer(requireIssuerFixture(trackedFixtures, operation.id));
          return;
        case "verifier":
          await harness.suspendVerifier(requireVerifierFixture(trackedFixtures, operation.id));
          return;
        case "auditor":
          await harness.suspendAuditor(requireAuditorFixture(trackedFixtures, operation.id));
          return;
        case "recognition":
          await harness.suspendRecognition(
            requireRecognitionFixture(trackedFixtures, operation.id),
          );
          return;
        default:
          return assertNever(operation.target);
      }
    }
    case "revoke": {
      switch (operation.target) {
        case "issuer":
          await harness.revokeIssuer(requireIssuerFixture(trackedFixtures, operation.id));
          return;
        case "verifier":
          await harness.revokeVerifier(requireVerifierFixture(trackedFixtures, operation.id));
          return;
        case "auditor":
          await harness.revokeAuditor(requireAuditorFixture(trackedFixtures, operation.id));
          return;
        case "recognition":
          await harness.revokeRecognition(
            requireRecognitionFixture(trackedFixtures, operation.id),
          );
          return;
        default:
          return assertNever(operation.target);
      }
    }
    case "archive": {
      switch (operation.target) {
        case "issuer":
          await harness.archiveIssuer(requireIssuerFixture(trackedFixtures, operation.id));
          return;
        case "verifier":
          await harness.archiveVerifier(requireVerifierFixture(trackedFixtures, operation.id));
          return;
        case "auditor":
          await harness.archiveAuditor(requireAuditorFixture(trackedFixtures, operation.id));
          return;
        case "recognition":
          await harness.archiveRecognition(
            requireRecognitionFixture(trackedFixtures, operation.id),
          );
          return;
        default:
          return assertNever(operation.target);
      }
    }
    case "publish-epoch":
      await harness.publishRegistryEpoch(operation.label ?? "workspace-current");
      return;
  }
};

const replayWorkspace = async (
  label: string,
  operations: readonly TrustRegistryOperatorWorkspaceOperation[],
): Promise<{
  harness: LocalTrustRegistryIntegrationHarness;
  trackedFixtures: TrackedFixtures;
}> => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const trackedFixtures = createTrackedFixtures();

  for (const operation of operations) {
    await applyMutableOperation(harness, trackedFixtures, operation);
  }

  return {
    harness,
    trackedFixtures,
  };
};

export const createOperatorWorkspace = async (
  input: { label?: string } = {},
): Promise<TrustRegistryOperatorWorkspace> => {
  const label = input.label ?? "midnight";
  const { harness, trackedFixtures } = await replayWorkspace(label, []);
  const snapshot = await buildSnapshotFromTrackedFixtures(label, 0, harness, trackedFixtures);

  return TrustRegistryOperatorWorkspaceSchema.parse({
    workspaceVersion: "3",
    updatedAt: snapshot.generatedAt,
    registryLabel: label,
    operations: [],
    consumedMutationNonces: {},
    mutationNonceClock: null,
    snapshot,
  });
};

export const loadWorkspaceFromFile = async (
  workspacePath: string,
): Promise<TrustRegistryOperatorWorkspace> => loadWorkspaceJson(workspacePath);

export const ensureWorkspaceInstanceId = async (workspacePath: string): Promise<string> =>
  withExclusiveWorkspaceWrite(workspacePath, async () => {
    const workspace = await loadWorkspaceJson(workspacePath);
    if (workspace.workspaceInstanceId !== undefined) return workspace.workspaceInstanceId;
    const workspaceInstanceId = randomUUID();
    await writeWorkspaceJson(workspacePath, { ...workspace, workspaceInstanceId });
    return workspaceInstanceId;
  });

export const writeWorkspaceToFile = async (
  workspacePath: string,
  workspace: TrustRegistryOperatorWorkspace,
): Promise<void> => writeWorkspaceJson(workspacePath, workspace);

export const applyWorkspaceOperation = async (
  workspace: TrustRegistryOperatorWorkspace,
  operation: TrustRegistryOperatorWorkspaceOperation,
): Promise<TrustRegistryOperatorWorkspace> => {
  const operations = [...workspace.operations, operation];
  const { harness, trackedFixtures } = await replayWorkspace(workspace.registryLabel, operations);
  const snapshot = retainHistoricalEvidence(workspace.snapshot, await buildSnapshotFromTrackedFixtures(
    workspace.registryLabel,
    operations.length,
    harness,
    trackedFixtures,
  ));

  return TrustRegistryOperatorWorkspaceSchema.parse({
    workspaceVersion: "3",
    ...(workspace.workspaceInstanceId === undefined ? {} : { workspaceInstanceId: workspace.workspaceInstanceId }),
    updatedAt: snapshot.generatedAt,
    registryLabel: workspace.registryLabel,
    operations,
    consumedMutationNonces: workspace.consumedMutationNonces,
    mutationNonceClock: workspace.mutationNonceClock,
    snapshot,
  });
};

export const resolveWorkspaceOperationRecord = (
  workspace: TrustRegistryOperatorWorkspace,
  operation: TrustRegistryOperatorWorkspaceOperation,
):
  | TrustRegistryAuthorizationSnapshotEntry
  | TrustRegistryRecognitionSnapshotEntry
  | TrustRegistryOperatorSnapshot["currentEpoch"] => {
  switch (operation.operation) {
    case "publish-epoch":
      return workspace.snapshot.currentEpoch;
    case "submit":
    case "approve":
    case "activate":
    case "suspend":
    case "revoke":
    case "archive":
      switch (operation.target) {
        case "issuer": {
          const entry = workspace.snapshot.issuerEntries.find(
            (candidate) =>
              candidate.authorization.authorizationId ===
              (operation.operation === "submit"
                ? createIssuerScenarioFixture(operation.label).authorizationId
                : operation.id),
          );
          if (entry === undefined) {
            throw new Error("expected issuer entry after workspace update");
          }
          return entry;
        }
        case "verifier": {
          const expectedAuthorizationId =
            operation.operation === "submit"
              ? createVerifierScenarioFixture(operation.label).authorizationId
              : operation.id;
          const entry = workspace.snapshot.verifierEntries.find(
            (candidate) => candidate.authorization.authorizationId === expectedAuthorizationId,
          );
          if (entry === undefined) {
            throw new Error("expected verifier entry after workspace update");
          }
          return entry;
        }
        case "auditor": {
          const expectedAuthorizationId = operation.operation === "submit"
            ? createAuditorScenarioFixture(operation.label).authorizationId
            : operation.id;
          const entry = workspace.snapshot.auditorEntries.find(
            (candidate) => candidate.authorization.authorizationId === expectedAuthorizationId,
          );
          if (entry === undefined) {
            throw new Error("expected auditor entry after workspace update");
          }
          return entry;
        }
        case "recognition": {
          const expectedRecognitionId =
            operation.operation === "submit"
              ? createRecognitionScenarioFixture(operation.label).recognitionId
              : operation.id;
          const entry = workspace.snapshot.recognitionEntries.find(
            (candidate) => candidate.recognition.recognitionId === expectedRecognitionId,
          );
          if (entry === undefined) {
            throw new Error("expected recognition entry after workspace update");
          }
          return entry;
        }
        default:
          return assertNever(operation.target);
      }
  }
};
