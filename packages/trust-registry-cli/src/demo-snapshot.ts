import {
  LocalTrustRegistryIntegrationHarness,
  createIssuerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";
import type { TrustRegistryEvidenceBundle } from "@midnight-ntwrk/trust-registry-domain";

import {
  TrustRegistryOperatorSnapshotSchema,
  collectAuthorizationRecord,
  collectDistinctEpochs,
  collectRecognitionRecord,
  type TrustRegistryOperatorSnapshot,
} from "./model.js";

const ACTIVE_ISSUER_LABEL = "passport";
const HISTORICAL_ISSUER_LABEL = "degree";
const ACTIVE_VERIFIER_LABEL = "age-gate";
const HISTORICAL_VERIFIER_LABEL = "employment";
const ACTIVE_RECOGNITION_LABEL = "gaia-x";
const HISTORICAL_RECOGNITION_LABEL = "eidas";

export type DemoSnapshotOptions = {
  label?: string;
};

const currentIssuerEntry = (
  label: string,
  evidence: TrustRegistryEvidenceBundle,
) => ({
  label,
  authorization: collectAuthorizationRecord(evidence, "issuer"),
  evidence,
});

const currentVerifierEntry = (
  label: string,
  evidence: TrustRegistryEvidenceBundle,
) => ({
  label,
  authorization: collectAuthorizationRecord(evidence, "verifier"),
  evidence,
});

const currentRecognitionEntry = (
  label: string,
  evidence: TrustRegistryEvidenceBundle,
) => ({
  label,
  recognition: collectRecognitionRecord(evidence),
  evidence,
});

export const createDemoSnapshot = (
  input: DemoSnapshotOptions = {},
): TrustRegistryOperatorSnapshot => {
  const label = input.label ?? "kanon";
  const harness = new LocalTrustRegistryIntegrationHarness(label);

  const activeIssuer = createIssuerScenarioFixture(ACTIVE_ISSUER_LABEL);
  const historicalIssuer = createIssuerScenarioFixture(HISTORICAL_ISSUER_LABEL);
  const activeVerifier = createVerifierScenarioFixture(ACTIVE_VERIFIER_LABEL);
  const historicalVerifier = createVerifierScenarioFixture(HISTORICAL_VERIFIER_LABEL);
  const activeRecognition = createRecognitionScenarioFixture(ACTIVE_RECOGNITION_LABEL);
  const historicalRecognition = createRecognitionScenarioFixture(
    HISTORICAL_RECOGNITION_LABEL,
  );

  harness.authorizeIssuer(activeIssuer);
  harness.authorizeIssuer(historicalIssuer);
  harness.suspendIssuer(historicalIssuer);
  harness.revokeIssuer(historicalIssuer);
  harness.archiveIssuer(historicalIssuer);

  harness.authorizeVerifier(activeVerifier);
  harness.authorizeVerifier(historicalVerifier);
  harness.suspendVerifier(historicalVerifier);
  harness.revokeVerifier(historicalVerifier);
  harness.archiveVerifier(historicalVerifier);

  harness.authorizeRecognition(activeRecognition);
  harness.authorizeRecognition(historicalRecognition);
  harness.suspendRecognition(historicalRecognition);
  harness.revokeRecognition(historicalRecognition);
  harness.archiveRecognition(historicalRecognition);

  const issuerEntries = [
    currentIssuerEntry(
      ACTIVE_ISSUER_LABEL,
      harness.evaluateCurrentIssuerDecision(activeIssuer),
    ),
    currentIssuerEntry(
      HISTORICAL_ISSUER_LABEL,
      harness.buildIssuerHistoricalEvidence(historicalIssuer),
    ),
  ];
  const verifierEntries = [
    currentVerifierEntry(
      ACTIVE_VERIFIER_LABEL,
      harness.evaluateCurrentVerifierDecision(activeVerifier),
    ),
    currentVerifierEntry(
      HISTORICAL_VERIFIER_LABEL,
      harness.buildVerifierHistoricalEvidence(historicalVerifier),
    ),
  ];
  const recognitionEntries = [
    currentRecognitionEntry(
      ACTIVE_RECOGNITION_LABEL,
      harness.evaluateCurrentRecognitionDecision(activeRecognition),
    ),
    currentRecognitionEntry(
      HISTORICAL_RECOGNITION_LABEL,
      harness.buildRecognitionHistoricalEvidence(historicalRecognition),
    ),
  ];

  const bundles = [
    ...issuerEntries.map((entry) => entry.evidence),
    ...verifierEntries.map((entry) => entry.evidence),
    ...recognitionEntries.map((entry) => entry.evidence),
  ];
  const epochs = collectDistinctEpochs(bundles);
  const currentEpoch = epochs.at(-1);
  if (currentEpoch === undefined) {
    throw new Error("expected at least one published epoch in demo snapshot");
  }

  return TrustRegistryOperatorSnapshotSchema.parse({
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
      "Simulator-first operator snapshot for local trust-registry inspection.",
      "Active entries are current decisions; archived entries preserve historical evidence.",
    ],
  });
};
