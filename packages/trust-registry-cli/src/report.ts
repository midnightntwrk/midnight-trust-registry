import type {
  EpochCommitment,
  GovernancePolicyRecord,
  RegistryRecord,
} from "@midnight-ntwrk/trust-registry-domain";

import type {
  TrustRegistryAuthorizationSnapshotEntry,
  TrustRegistryOperatorSnapshot,
  TrustRegistryRecognitionSnapshotEntry,
} from "./model.js";
import {
  buildSnapshotSummary,
  findEpoch,
  findIssuerEntry,
  findRecognitionEntry,
  findVerifierEntry,
  renderStatusCounts,
} from "./snapshot.js";

export type AuditReportKind =
  | "full"
  | "registry"
  | "policy"
  | "issuer"
  | "verifier"
  | "recognition"
  | "epoch";

type TimelineEntry = readonly [label: string, value: string | undefined];

const joinSections = (sections: readonly string[]): string =>
  `${sections.filter((section) => section.trim().length > 0).join("\n\n")}\n`;

const renderLines = (lines: readonly string[]): string => lines.join("\n");

const renderTimeline = (entries: readonly TimelineEntry[]): string =>
  entries
    .filter((entry) => entry[1] !== undefined)
    .map(([label, value]) => `  - ${label}: ${value}`)
    .join("\n");

const renderList = (entries: readonly string[]): string =>
  entries.map((entry) => `  - ${entry}`).join("\n");

const renderIndentedBlocks = (entries: readonly string[]): string =>
  entries.map((entry) => `  - ${entry.replace(/\n/g, "\n    ")}`).join("\n");

const renderHeader = (
  snapshot: TrustRegistryOperatorSnapshot,
  title: string,
): string => {
  const summary = buildSnapshotSummary(snapshot);

  return renderLines([
    title,
    `Registry: ${summary.registryId}`,
    `Registry DID: ${summary.registryDid}`,
    `Generated: ${summary.generatedAt}`,
    `Snapshot version: ${summary.snapshotVersion}`,
    `Current epoch: ${summary.currentEpochId}`,
  ]);
};

const renderRegistrySection = (registry: RegistryRecord): string =>
  joinSections([
    "Registry",
    renderLines([
      `Name: ${registry.name}`,
      `Registry ID: ${registry.registryId}`,
      `Registry DID: ${registry.registryDid}`,
      `Status: ${registry.status}`,
      `Description: ${registry.description}`,
      `Policy URI: ${registry.policyUri}`,
      `Service endpoint: ${registry.serviceEndpoint}`,
      `Logo URI: ${registry.logoUri}`,
      "Controllers:",
      renderList(registry.controllerDids),
      "Maintainers:",
      renderList(registry.maintainerDids),
      "Timeline:",
      renderTimeline([
        ["createdAt", registry.createdAt],
        ["updatedAt", registry.updatedAt],
        ["suspendedAt", registry.suspendedAt],
        ["revokedAt", registry.revokedAt],
        ["supersededAt", registry.supersededAt],
        ["archivedAt", registry.archivedAt],
      ]),
    ]),
  ]);

const renderPolicySection = (policy: GovernancePolicyRecord): string =>
  joinSections([
    "Policy",
    renderLines([
      `Policy ID: ${policy.policyId}`,
      `Registry ID: ${policy.registryId}`,
      `Version: ${policy.version}`,
      `Status: ${policy.status}`,
      `Policy URI: ${policy.policyUri}`,
      "Decision rules:",
      renderList(policy.decisionRules),
      "Dispute rules:",
      renderList(policy.disputeRules),
      "Retention rules:",
      renderList(policy.retentionRules),
      "Emergency rules:",
      renderList(policy.emergencyRules),
      "Policy templates:",
      renderIndentedBlocks(
        policy.policyTemplates.map(
          (template) =>
            `${template.family}: ${template.name}\n` +
            `threshold=${template.requiredMaintainerThreshold}; ` +
            `roles=${template.applicableRoles.join(", ")}; ` +
            `actions=${template.applicableActionKinds.join(", ")}`,
        ),
      ),
      "Decision bindings:",
      renderIndentedBlocks(
        policy.decisionBindings.map(
          (binding) =>
            `${binding.family}: ${binding.bindingId}\n` +
            `template=${binding.templateId}; ` +
            `scopes=${binding.actionScopes.join(", ")}`,
        ),
      ),
      "Timeline:",
      renderTimeline([
        ["effectiveFrom", policy.effectiveFrom],
        ["effectiveUntil", policy.effectiveUntil],
        ["supersededAt", policy.supersededAt],
        ["archivedAt", policy.archivedAt],
      ]),
    ]),
  ]);

const renderAuthorizationEntry = (
  title: string,
  entry: TrustRegistryAuthorizationSnapshotEntry,
): string =>
  joinSections([
    title,
    renderLines([
      `Label: ${entry.label}`,
      `Authorization ID: ${entry.authorization.authorizationId}`,
      `Role: ${entry.authorization.role}`,
      `Status: ${entry.authorization.status}`,
      `Subject DID: ${entry.authorization.subjectDid}`,
      `Resource: ${entry.authorization.resourceId} (${entry.authorization.resourceType})`,
      `Trust level: ${entry.authorization.trustLevel}`,
      `Policy ID: ${entry.authorization.policyId}`,
      `Evidence bundle ID: ${entry.evidence.bundleId}`,
      `Bundle epoch: ${entry.evidence.epoch.epochId}`,
      "Timeline:",
      renderTimeline([
        ["proposedAt", entry.authorization.proposedAt],
        ["authorizedAt", entry.authorization.authorizedAt],
        ["activeFrom", entry.authorization.activeFrom],
        ["issuedAt", entry.authorization.issuedAt],
        ["effectiveUntil", entry.authorization.effectiveUntil],
        ["suspendedAt", entry.authorization.suspendedAt],
        ["revokedAt", entry.authorization.revokedAt],
        ["supersededAt", entry.authorization.supersededAt],
        ["archivedAt", entry.authorization.archivedAt],
      ]),
    ]),
  ]);

const renderRecognitionEntry = (
  title: string,
  entry: TrustRegistryRecognitionSnapshotEntry,
): string =>
  joinSections([
    title,
    renderLines([
      `Label: ${entry.label}`,
      `Recognition ID: ${entry.recognition.recognitionId}`,
      `Status: ${entry.recognition.status}`,
      `Recognized authority DID: ${entry.recognition.recognizedAuthorityDid}`,
      `Recognized registry ID: ${entry.recognition.recognizedRegistryId}`,
      `Scope: ${entry.recognition.scope.resourceId} (${entry.recognition.scope.resourceType})`,
      `Trust level: ${entry.recognition.trustLevel}`,
      `Policy ID: ${entry.recognition.policyId}`,
      `Evidence bundle ID: ${entry.evidence.bundleId}`,
      `Bundle epoch: ${entry.evidence.epoch.epochId}`,
      "Timeline:",
      renderTimeline([
        ["proposedAt", entry.recognition.proposedAt],
        ["authorizedAt", entry.recognition.authorizedAt],
        ["effectiveFrom", entry.recognition.effectiveFrom],
        ["effectiveUntil", entry.recognition.effectiveUntil],
        ["suspendedAt", entry.recognition.suspendedAt],
        ["revokedAt", entry.recognition.revokedAt],
        ["supersededAt", entry.recognition.supersededAt],
        ["archivedAt", entry.recognition.archivedAt],
      ]),
    ]),
  ]);

const renderEpochEntry = (
  epoch: EpochCommitment,
  currentEpochId: string,
): string =>
  joinSections([
    `Epoch ${epoch.epochId}`,
    renderLines([
      `State: ${epoch.epochId === currentEpochId ? "current" : "historical"}`,
      `Registry ID: ${epoch.registryId}`,
      `State root: ${epoch.stateRoot}`,
      `Event root: ${epoch.eventRoot}`,
      `Policy root: ${epoch.policyRoot}`,
      "Timeline:",
      renderTimeline([
        ["validFrom", epoch.validFrom],
        ["validUntil", epoch.validUntil],
      ]),
      "Maintainer signatures:",
      renderList(
        epoch.maintainerSignatures.map(
          (signature) =>
            `${signature.keyId} (${signature.algorithm}) ${signature.signature}`,
        ),
      ),
    ]),
  ]);

const renderSummarySection = (
  snapshot: TrustRegistryOperatorSnapshot,
): string => {
  const summary = buildSnapshotSummary(snapshot);

  return joinSections([
    "Summary",
    renderLines([
      `Issuers: ${renderStatusCounts(summary.issuerCounts)}`,
      `Verifiers: ${renderStatusCounts(summary.verifierCounts)}`,
      `Recognitions: ${renderStatusCounts(summary.recognitionCounts)}`,
      `Epoch count: ${summary.epochCount}`,
    ]),
  ]);
};

const renderNotesSection = (notes: readonly string[]): string =>
  notes.length === 0
    ? ""
    : joinSections(["Notes", renderList(notes.map((note) => note.trim()))]);

const renderAuthorizationCollection = (
  title: string,
  entries: readonly TrustRegistryAuthorizationSnapshotEntry[],
): string =>
  joinSections([
    title,
    ...entries.map((entry) =>
      renderAuthorizationEntry(`- ${entry.authorization.authorizationId}`, entry),
    ),
  ]);

const renderRecognitionCollection = (
  title: string,
  entries: readonly TrustRegistryRecognitionSnapshotEntry[],
): string =>
  joinSections([
    title,
    ...entries.map((entry) =>
      renderRecognitionEntry(`- ${entry.recognition.recognitionId}`, entry),
    ),
  ]);

const renderEpochCollection = (
  title: string,
  epochs: readonly EpochCommitment[],
  currentEpochId: string,
): string =>
  joinSections([
    title,
    ...epochs.map((epoch) => renderEpochEntry(epoch, currentEpochId)),
  ]);

export const renderAuditReport = (
  snapshot: TrustRegistryOperatorSnapshot,
  kind: AuditReportKind,
  id?: string,
): string => {
  switch (kind) {
    case "full":
      return joinSections([
        renderHeader(snapshot, "Trust Registry Audit Report"),
        renderSummarySection(snapshot),
        renderNotesSection(snapshot.notes),
        renderRegistrySection(snapshot.registry),
        renderPolicySection(snapshot.policy),
        renderAuthorizationCollection("Issuer Authorizations", snapshot.issuerEntries),
        renderAuthorizationCollection(
          "Verifier Authorizations",
          snapshot.verifierEntries,
        ),
        renderRecognitionCollection(
          "Recognitions",
          snapshot.recognitionEntries,
        ),
        renderEpochCollection(
          "Epoch History",
          snapshot.epochs,
          snapshot.currentEpoch.epochId,
        ),
      ]);
    case "registry":
      return joinSections([
        renderHeader(snapshot, "Trust Registry Registry Audit"),
        renderRegistrySection(snapshot.registry),
      ]);
    case "policy":
      return joinSections([
        renderHeader(snapshot, "Trust Registry Policy Audit"),
        renderPolicySection(snapshot.policy),
      ]);
    case "issuer": {
      if (id === undefined) {
        return joinSections([
          renderHeader(snapshot, "Trust Registry Issuer Authorization Audit"),
          renderAuthorizationCollection(
            "Issuer Authorizations",
            snapshot.issuerEntries,
          ),
        ]);
      }

      return joinSections([
        renderHeader(snapshot, "Trust Registry Issuer Authorization Audit"),
        renderAuthorizationEntry("Issuer Authorization", findIssuerEntry(snapshot, id)),
      ]);
    }
    case "verifier": {
      if (id === undefined) {
        return joinSections([
          renderHeader(snapshot, "Trust Registry Verifier Authorization Audit"),
          renderAuthorizationCollection(
            "Verifier Authorizations",
            snapshot.verifierEntries,
          ),
        ]);
      }

      return joinSections([
        renderHeader(snapshot, "Trust Registry Verifier Authorization Audit"),
        renderAuthorizationEntry(
          "Verifier Authorization",
          findVerifierEntry(snapshot, id),
        ),
      ]);
    }
    case "recognition": {
      if (id === undefined) {
        return joinSections([
          renderHeader(snapshot, "Trust Registry Recognition Audit"),
          renderRecognitionCollection("Recognitions", snapshot.recognitionEntries),
        ]);
      }

      return joinSections([
        renderHeader(snapshot, "Trust Registry Recognition Audit"),
        renderRecognitionEntry("Recognition", findRecognitionEntry(snapshot, id)),
      ]);
    }
    case "epoch": {
      if (id === undefined) {
        return joinSections([
          renderHeader(snapshot, "Trust Registry Epoch Audit"),
          renderEpochCollection(
            "Epoch History",
            snapshot.epochs,
            snapshot.currentEpoch.epochId,
          ),
        ]);
      }

      return joinSections([
        renderHeader(snapshot, "Trust Registry Epoch Audit"),
        renderEpochEntry(findEpoch(snapshot, id), snapshot.currentEpoch.epochId),
      ]);
    }
  }
};
