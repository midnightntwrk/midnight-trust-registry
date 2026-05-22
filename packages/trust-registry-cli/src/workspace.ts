import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import {
  LocalTrustRegistryIntegrationHarness,
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
  type IssuerScenarioFixture,
  type RecognitionScenarioFixture,
  type VerifierScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";
import type { TrustRegistryEvidenceBundle } from "@midnight-ntwrk/trust-registry-domain";

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

type TrackedRecognitionFixture = {
  fixture: RecognitionScenarioFixture;
  label: string;
};

type TrackedFixtures = {
  issuers: Map<string, TrackedIssuerFixture>;
  recognitions: Map<string, TrackedRecognitionFixture>;
  verifiers: Map<string, TrackedVerifierFixture>;
};

const createTrackedFixtures = (): TrackedFixtures => ({
  issuers: new Map<string, TrackedIssuerFixture>(),
  recognitions: new Map<string, TrackedRecognitionFixture>(),
  verifiers: new Map<string, TrackedVerifierFixture>(),
});

const writeWorkspaceJson = async (
  workspacePath: string,
  workspace: TrustRegistryOperatorWorkspace,
): Promise<void> => {
  await mkdir(dirname(workspacePath), { recursive: true });
  await writeFile(
    workspacePath,
    serializeJson(TrustRegistryOperatorWorkspaceSchema.parse(workspace)),
    "utf8",
  );
};

const loadWorkspaceJson = async (
  workspacePath: string,
): Promise<TrustRegistryOperatorWorkspace> => {
  const raw = await readFile(workspacePath, "utf8");
  return TrustRegistryOperatorWorkspaceSchema.parse(JSON.parse(raw));
};

const currentOrHistoricalIssuerEvidence = (
  harness: LocalTrustRegistryIntegrationHarness,
  fixture: IssuerScenarioFixture,
): TrustRegistryEvidenceBundle => {
  try {
    return harness.evaluateCurrentIssuerDecision(fixture);
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/not active/i.test(message)) {
      return harness.buildIssuerHistoricalEvidence(fixture);
    }
    throw error;
  }
};

const currentOrHistoricalVerifierEvidence = (
  harness: LocalTrustRegistryIntegrationHarness,
  fixture: VerifierScenarioFixture,
): TrustRegistryEvidenceBundle => {
  try {
    return harness.evaluateCurrentVerifierDecision(fixture);
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/not active/i.test(message)) {
      return harness.buildVerifierHistoricalEvidence(fixture);
    }
    throw error;
  }
};

const currentOrHistoricalRecognitionEvidence = (
  harness: LocalTrustRegistryIntegrationHarness,
  fixture: RecognitionScenarioFixture,
): TrustRegistryEvidenceBundle => {
  try {
    return harness.evaluateCurrentRecognitionDecision(fixture);
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/not active/i.test(message)) {
      return harness.buildRecognitionHistoricalEvidence(fixture);
    }
    throw error;
  }
};

const issuerEntryFromFixture = (
  harness: LocalTrustRegistryIntegrationHarness,
  tracked: TrackedIssuerFixture,
): TrustRegistryAuthorizationSnapshotEntry => {
  const evidence = currentOrHistoricalIssuerEvidence(harness, tracked.fixture);
  return {
    label: tracked.label,
    authorization: collectAuthorizationRecord(evidence, "issuer"),
    evidence,
  };
};

const verifierEntryFromFixture = (
  harness: LocalTrustRegistryIntegrationHarness,
  tracked: TrackedVerifierFixture,
): TrustRegistryAuthorizationSnapshotEntry => {
  const evidence = currentOrHistoricalVerifierEvidence(harness, tracked.fixture);
  return {
    label: tracked.label,
    authorization: collectAuthorizationRecord(evidence, "verifier"),
    evidence,
  };
};

const recognitionEntryFromFixture = (
  harness: LocalTrustRegistryIntegrationHarness,
  tracked: TrackedRecognitionFixture,
): TrustRegistryRecognitionSnapshotEntry => {
  const evidence = currentOrHistoricalRecognitionEvidence(harness, tracked.fixture);
  return {
    label: tracked.label,
    recognition: collectRecognitionRecord(evidence),
    evidence,
  };
};

const buildSnapshotFromTrackedFixtures = (
  label: string,
  operationCount: number,
  harness: LocalTrustRegistryIntegrationHarness,
  trackedFixtures: TrackedFixtures,
): TrustRegistryOperatorSnapshot => {
  const registryEpoch = harness.publishRegistryEpoch("workspace-current");
  const issuerEntries = Array.from(trackedFixtures.issuers.values())
    .map((tracked) => issuerEntryFromFixture(harness, tracked))
    .sort((left, right) =>
      left.authorization.authorizationId.localeCompare(right.authorization.authorizationId),
    );
  const verifierEntries = Array.from(trackedFixtures.verifiers.values())
    .map((tracked) => verifierEntryFromFixture(harness, tracked))
    .sort((left, right) =>
      left.authorization.authorizationId.localeCompare(right.authorization.authorizationId),
    );
  const recognitionEntries = Array.from(trackedFixtures.recognitions.values())
    .map((tracked) => recognitionEntryFromFixture(harness, tracked))
    .sort((left, right) =>
      left.recognition.recognitionId.localeCompare(right.recognition.recognitionId),
    );

  const epochsById = new Map<string, TrustRegistryOperatorSnapshot["currentEpoch"]>([
    [registryEpoch.epochId, registryEpoch],
  ]);
  for (const epoch of collectDistinctEpochs([
    ...issuerEntries.map((entry) => entry.evidence),
    ...verifierEntries.map((entry) => entry.evidence),
    ...recognitionEntries.map((entry) => entry.evidence),
  ])) {
    epochsById.set(epoch.epochId, epoch);
  }
  const epochs = Array.from(epochsById.values()).sort((left, right) =>
    left.validFrom.localeCompare(right.validFrom),
  );
  const currentEpoch = epochs.at(-1) ?? registryEpoch;

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
    recognitionEntries,
    notes: [
      "Operator workspace snapshot derived from governed CLI operations.",
      `Replayed operations: ${operationCount.toString()}.`,
    ],
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

const applyMutableOperation = (
  harness: LocalTrustRegistryIntegrationHarness,
  trackedFixtures: TrackedFixtures,
  operation: TrustRegistryOperatorWorkspaceOperation,
): void => {
  switch (operation.operation) {
    case "submit": {
      switch (operation.target) {
        case "issuer": {
          const fixture = createIssuerScenarioFixture(operation.label);
          if (trackedFixtures.issuers.has(fixture.authorizationId)) {
            throw new Error(`issuer label already submitted: ${operation.label}`);
          }
          harness.proposeIssuer(fixture);
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
          harness.proposeVerifier(fixture);
          trackedFixtures.verifiers.set(fixture.authorizationId, {
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
          harness.proposeRecognition(fixture);
          trackedFixtures.recognitions.set(fixture.recognitionId, {
            label: operation.label,
            fixture,
          });
          return;
        }
      }
      return;
    }
    case "approve": {
      switch (operation.target) {
        case "issuer":
          harness.approveIssuer(requireIssuerFixture(trackedFixtures, operation.id));
          return;
        case "verifier":
          harness.approveVerifier(requireVerifierFixture(trackedFixtures, operation.id));
          return;
        case "recognition":
          harness.approveRecognition(
            requireRecognitionFixture(trackedFixtures, operation.id),
          );
          return;
      }
      return;
    }
    case "activate": {
      switch (operation.target) {
        case "issuer":
          harness.activateIssuer(requireIssuerFixture(trackedFixtures, operation.id));
          return;
        case "verifier":
          harness.activateVerifier(requireVerifierFixture(trackedFixtures, operation.id));
          return;
        case "recognition":
          harness.activateRecognition(
            requireRecognitionFixture(trackedFixtures, operation.id),
          );
          return;
      }
      return;
    }
    case "suspend": {
      switch (operation.target) {
        case "issuer":
          harness.suspendIssuer(requireIssuerFixture(trackedFixtures, operation.id));
          return;
        case "verifier":
          harness.suspendVerifier(requireVerifierFixture(trackedFixtures, operation.id));
          return;
        case "recognition":
          harness.suspendRecognition(
            requireRecognitionFixture(trackedFixtures, operation.id),
          );
          return;
      }
      return;
    }
    case "revoke": {
      switch (operation.target) {
        case "issuer":
          harness.revokeIssuer(requireIssuerFixture(trackedFixtures, operation.id));
          return;
        case "verifier":
          harness.revokeVerifier(requireVerifierFixture(trackedFixtures, operation.id));
          return;
        case "recognition":
          harness.revokeRecognition(
            requireRecognitionFixture(trackedFixtures, operation.id),
          );
          return;
      }
      return;
    }
    case "archive": {
      switch (operation.target) {
        case "issuer":
          harness.archiveIssuer(requireIssuerFixture(trackedFixtures, operation.id));
          return;
        case "verifier":
          harness.archiveVerifier(requireVerifierFixture(trackedFixtures, operation.id));
          return;
        case "recognition":
          harness.archiveRecognition(
            requireRecognitionFixture(trackedFixtures, operation.id),
          );
          return;
      }
      return;
    }
    case "publish-epoch":
      harness.publishRegistryEpoch(operation.label ?? "workspace-current");
      return;
  }
};

const replayWorkspace = (
  label: string,
  operations: readonly TrustRegistryOperatorWorkspaceOperation[],
): {
  harness: LocalTrustRegistryIntegrationHarness;
  trackedFixtures: TrackedFixtures;
} => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const trackedFixtures = createTrackedFixtures();

  for (const operation of operations) {
    applyMutableOperation(harness, trackedFixtures, operation);
  }

  return {
    harness,
    trackedFixtures,
  };
};

export const createOperatorWorkspace = (
  input: { label?: string } = {},
): TrustRegistryOperatorWorkspace => {
  const label = input.label ?? "kanon";
  const { harness, trackedFixtures } = replayWorkspace(label, []);
  const snapshot = buildSnapshotFromTrackedFixtures(label, 0, harness, trackedFixtures);

  return TrustRegistryOperatorWorkspaceSchema.parse({
    workspaceVersion: "1",
    updatedAt: snapshot.generatedAt,
    registryLabel: label,
    operations: [],
    snapshot,
  });
};

export const loadWorkspaceFromFile = async (
  workspacePath: string,
): Promise<TrustRegistryOperatorWorkspace> => loadWorkspaceJson(workspacePath);

export const writeWorkspaceToFile = async (
  workspacePath: string,
  workspace: TrustRegistryOperatorWorkspace,
): Promise<void> => writeWorkspaceJson(workspacePath, workspace);

export const applyWorkspaceOperation = (
  workspace: TrustRegistryOperatorWorkspace,
  operation: TrustRegistryOperatorWorkspaceOperation,
): TrustRegistryOperatorWorkspace => {
  const operations = [...workspace.operations, operation];
  const { harness, trackedFixtures } = replayWorkspace(workspace.registryLabel, operations);
  const snapshot = buildSnapshotFromTrackedFixtures(
    workspace.registryLabel,
    operations.length,
    harness,
    trackedFixtures,
  );

  return TrustRegistryOperatorWorkspaceSchema.parse({
    workspaceVersion: "1",
    updatedAt: snapshot.generatedAt,
    registryLabel: workspace.registryLabel,
    operations,
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
      }
  }
};
