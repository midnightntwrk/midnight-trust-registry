import { Buffer } from "node:buffer";

import {
  computeIssuerAuthorizationScopeKey,
  computeVerifierAuthorizationScopeKey,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  AuthorizationStatus,
  IssuerResourceType,
  type Ledger,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import type {
  FinalizedRegistryDecisionSnapshot,
  TrustedDecisionEvidenceReaders,
} from "@midnight-ntwrk/trust-registry-client";
import {
  sha256Hex,
  type DecisionEvidenceSelection,
} from "@midnight-ntwrk/trust-registry-domain";

type Selection = Omit<DecisionEvidenceSelection, "evaluationTime">;

/** The host must authenticate this whole view at one finalized ledger point. */
export type FinalizedCompactDecisionView = {
  ledger: Ledger;
  acceptedEpoch: FinalizedRegistryDecisionSnapshot["acceptedEpoch"];
  publication: FinalizedRegistryDecisionSnapshot["publication"];
  evaluationTime: string;
};

const bytes = (value: string): Uint8Array => Buffer.from(sha256Hex(value).slice(2), "hex");
const same = (left: Uint8Array, right: Uint8Array): boolean =>
  Buffer.from(left).equals(Buffer.from(right));
const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;

const issuerResourceType = (value: string): IssuerResourceType | null => {
  switch (value) {
    case "credential-family": return IssuerResourceType.credentialFamily;
    case "schema": return IssuerResourceType.schema;
    case "schema-version": return IssuerResourceType.schemaVersion;
    case "credential-definition": return IssuerResourceType.credentialDefinition;
    case "status-method-requirement": return IssuerResourceType.statusMethodRequirement;
    default: return null;
  }
};

const readCurrentGrant = (
  ledger: Ledger,
  selection: Selection,
  authorizationId: string,
): FinalizedRegistryDecisionSnapshot["decisionPoint"]["currentGrant"] | null => {
  const id = bytes(authorizationId);
  const subject = bytes(selection.subjectDid);
  const resource = bytes(selection.resourceId);
  const sequence = ledger.governanceActionCount.toString();
  if (selection.role === "issuer") {
    if (!ledger.issuerAuthorizationRecords.member(id)) return null;
    const record = ledger.issuerAuthorizationRecords.lookup(id);
    const expectedType = issuerResourceType(selection.resourceType);
    if (expectedType === null || !same(record.authorizationId, id) || record.resourceType !== expectedType
      || !same(record.subjectDidCommitment, subject) || !same(record.resourceId, resource)) return null;
    const scopeKey = computeIssuerAuthorizationScopeKey(subject, record.resourceType, record.resourceId);
    if (!ledger.currentIssuerAuthorizationIdsByScopeKey.member(scopeKey)
      || !same(ledger.currentIssuerAuthorizationIdsByScopeKey.lookup(scopeKey), id)) return null;
    return { authorizationId, lifecycleEventRoot: hex(record.lifecycleEventHash),
      status: AuthorizationStatus[record.status], observedAtSequence: sequence };
  }
  if (selection.resourceType !== "request-profile" || !ledger.verifierAuthorizationRecords.member(id)) return null;
  const record = ledger.verifierAuthorizationRecords.lookup(id);
  if (!same(record.authorizationId, id) || !same(record.subjectDidCommitment, subject)
    || !same(record.requestResourceId, resource)) return null;
  const scopeKey = computeVerifierAuthorizationScopeKey(
    subject, record.requestResourceId, record.allowedAttributeSetCommitment,
    record.allowedPredicateSetCommitment, record.disclosureLevelCommitment,
  );
  if (!ledger.currentVerifierAuthorizationIdsByScopeKey.member(scopeKey)
    || !same(ledger.currentVerifierAuthorizationIdsByScopeKey.lookup(scopeKey), id)) return null;
  return { authorizationId, lifecycleEventRoot: hex(record.lifecycleEventHash),
    status: AuthorizationStatus[record.status], observedAtSequence: sequence };
};

/** Projects checked Compact state; it never creates a finality or DID-state claim. */
export function createCompactLedgerDecisionReaders(input: {
  readFinalizedView(selection: Selection, epochIdHint: string): Promise<FinalizedCompactDecisionView | null>;
  readFinalizedDidState: TrustedDecisionEvidenceReaders["readCurrentFinalizedDidState"];
}): TrustedDecisionEvidenceReaders {
  return {
    async readCurrentFinalizedRegistryDecision(selection, epochIdHint, authorizationIdHint) {
      if (authorizationIdHint === undefined) throw new Error("Decision authorization ID is required");
      const view = await input.readFinalizedView(selection, epochIdHint);
      if (view === null) return null;
      const { ledger, acceptedEpoch, publication } = view;
      const epochId = bytes(epochIdHint);
      if (acceptedEpoch.registryId !== selection.registryId
        || acceptedEpoch.networkId !== selection.networkId
        || acceptedEpoch.contractAddress !== selection.contractAddress
        || acceptedEpoch.epochId !== epochIdHint
        || !same(ledger.registryId, bytes(selection.registryId))
        || !same(publication.registryIdCommitment, ledger.registryId)
        || !same(publication.epochIdCommitment, epochId)
        || !ledger.epochCommitmentRecords.member(epochId)) {
        throw new Error("Finalized Compact decision identity or epoch mismatch");
      }
      const epoch = ledger.epochCommitmentRecords.lookup(epochId);
      if (!same(epoch.epochId, epochId)
        || hex(epoch.stateRoot) !== acceptedEpoch.stateRoot
        || hex(epoch.eventRoot) !== acceptedEpoch.eventRoot
        || hex(epoch.policyRoot) !== acceptedEpoch.policyRoot
        || hex(epoch.publicationPolicyCommitment) !== acceptedEpoch.publicationPolicyCommitment
        || hex(epoch.publicationEventHash) !== acceptedEpoch.publicationEventHash
        || epoch.publishedAtSequence.toString() !== acceptedEpoch.publicationSequence
        || epoch.validFromSequence.toString() !== acceptedEpoch.validFromSequence
        || epoch.validUntilSequence.toString() !== acceptedEpoch.validUntilSequence
        || !same(epoch.maintainerKeyId, publication.firstSignerKeyIdCommitment)) {
        throw new Error("Accepted epoch does not match finalized Compact ledger");
      }
      const currentGrant = readCurrentGrant(ledger, selection, authorizationIdHint);
      if (currentGrant === null) return null;
      const sequence = ledger.governanceActionCount.toString();
      return {
        acceptedEpoch,
        publication,
        decisionPoint: {
          sequence,
          evaluationTime: view.evaluationTime,
          currentPolicy: { root: hex(ledger.governancePolicyCommitment), observedAtSequence: sequence },
          currentGrant,
        },
      };
    },
    readCurrentFinalizedDidState: input.readFinalizedDidState,
  };
}
