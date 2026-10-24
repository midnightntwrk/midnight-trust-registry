import { Buffer } from "node:buffer";

import {
  TrustRegistryOperatorSnapshotSchema,
  type TrustRegistryOperatorSnapshot,
} from "@midnight-ntwrk/trust-registry-cli";
import {
  bytes32Commitment,
  verifyTrustRegistryEvidenceBundle,
  type SequenceToTimestamp,
} from "@midnight-ntwrk/trust-registry-client";
import {
  computeAuditorAuthorizationScopeKey,
  computeIssuerAuthorizationScopeKey,
  computeRecognitionScopeKey,
  computeVerifierAuthorizationScopeKey,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  AuthorizationStatus,
  IssuerResourceType,
  type Ledger,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import {
  canonicalizeJson,
  computeGovernancePolicySnapshotCommitment,
  deriveGovernancePolicySnapshot,
} from "@midnight-ntwrk/trust-registry-domain";
import { resolveCompactHistoricalEpochAnchor } from "@midnight-ntwrk/trust-registry-integration";

const hex = (bytes: Uint8Array): string => `0x${Buffer.from(bytes).toString("hex")}`;
const commitment = (value: string): string => hex(bytes32Commitment(value));

const issuerResourceTypes: Readonly<Record<string, string>> = {
  credentialFamily: "credential-family",
  schema: "schema",
  schemaVersion: "schema-version",
  credentialDefinition: "credential-definition",
  statusMethodRequirement: "status-method-requirement",
};

type AuthorizationEntry = TrustRegistryOperatorSnapshot["issuerEntries"][number];
type RecognitionEntry = TrustRegistryOperatorSnapshot["recognitionEntries"][number];

function assertExactMap<T>(
  label: string,
  entries: readonly T[],
  idOf: (entry: T) => string,
  records: {
    size(): bigint;
    [Symbol.iterator](): Iterator<[Uint8Array, unknown]>;
  },
  assertRecord: (entry: T, record: unknown, key: string) => void,
): void {
  const indexed = new Map<string, T>();
  for (const entry of entries) {
    const id = commitment(idOf(entry));
    if (indexed.has(id)) throw new Error(`Duplicate ${label} candidate identifier`);
    indexed.set(id, entry);
  }
  if (records.size() !== BigInt(indexed.size)) {
    throw new Error(`${label} candidate does not cover the finalized ledger map`);
  }
  const seen = new Set<string>();
  for (const [keyBytes, record] of records) {
    const key = hex(keyBytes);
    const entry = indexed.get(key);
    if (entry === undefined || seen.has(key)) {
      throw new Error(`${label} finalized ledger map has an absent or duplicate candidate`);
    }
    seen.add(key);
    assertRecord(entry, record, key);
  }
  if (seen.size !== indexed.size) throw new Error(`${label} finalized ledger iteration was incomplete`);
}

function assertCurrentScopeIndex<T extends { proposedAtSequence: bigint }>(
  label: string,
  records: Iterable<[Uint8Array, T]>,
  index: { size(): bigint; [Symbol.iterator](): Iterator<[Uint8Array, Uint8Array]> },
  scopeKeyOf: (record: T) => Uint8Array,
): void {
  const latest = new Map<string, { id: string; sequence: bigint }>();
  for (const [id, record] of records) {
    const key = hex(scopeKeyOf(record));
    const previous = latest.get(key);
    if (previous?.sequence === record.proposedAtSequence) {
      throw new Error(`${label} finalized scope has ambiguous proposal sequence`);
    }
    if (previous === undefined || record.proposedAtSequence > previous.sequence) {
      latest.set(key, { id: hex(id), sequence: record.proposedAtSequence });
    }
  }
  if (index.size() !== BigInt(latest.size)) {
    throw new Error(`${label} finalized current-scope index is incomplete`);
  }
  const seen = new Set<string>();
  for (const [keyBytes, idBytes] of index) {
    const key = hex(keyBytes);
    if (seen.has(key) || latest.get(key)?.id !== hex(idBytes)) {
      throw new Error(`${label} finalized current-scope index differs from records`);
    }
    seen.add(key);
  }
  if (seen.size !== latest.size) {
    throw new Error(`${label} finalized current-scope index iteration was incomplete`);
  }
}

function assertAuthorizationFields(
  role: "issuer" | "verifier" | "auditor",
  entry: AuthorizationEntry,
  record: {
    authorizationId: Uint8Array;
    subjectDidCommitment: Uint8Array;
    policyId: Uint8Array;
    trustLevel: Uint8Array;
    evidenceHash: Uint8Array;
    lifecycleEventHash: Uint8Array;
    status: AuthorizationStatus;
    resourceId?: Uint8Array;
    requestResourceId?: Uint8Array;
    resourceType?: IssuerResourceType;
    statusPolicyBindingCommitment?: Uint8Array;
  },
  key: string,
  expectedPolicyCommitment: string,
): void {
  const claim = entry.authorization;
  const resource = role === "issuer" ? record.resourceId : record.requestResourceId;
  const fields = [
    ["role", claim.role === role],
    ["authorizationId", hex(record.authorizationId) === key],
    ["subjectDid", hex(record.subjectDidCommitment) === commitment(claim.subjectDid)],
    ["resourceId", resource !== undefined && hex(resource) === commitment(claim.resourceId)],
    ["policyCommitment", hex(record.policyId) === expectedPolicyCommitment],
    ["trustLevel", hex(record.trustLevel) === commitment(claim.trustLevel)],
    ["evidenceHash", hex(record.evidenceHash) === claim.evidenceHash],
    ["lifecycleEventRoot", hex(record.lifecycleEventHash) === claim.lifecycleEventRoot],
    ["status", AuthorizationStatus[record.status] === claim.status],
  ] as const;
  for (const [name, matches] of fields) {
    if (!matches) throw new Error(`${role} candidate ${name} differs from finalized Compact state`);
  }
  if (role === "issuer" && (record.resourceType === undefined
    || issuerResourceTypes[IssuerResourceType[record.resourceType]] !== claim.resourceType
    || record.statusPolicyBindingCommitment === undefined
    || hex(record.statusPolicyBindingCommitment) !== claim.statusPolicyBindingCommitment)) {
    throw new Error("Issuer candidate scope differs from finalized Compact state");
  }
}

function policyCommitmentAtSequence(ledger: Ledger, sequence: bigint): string {
  let selectedVersion = 0n;
  let selectedEffectiveFrom = -1n;
  let selectedCommitment: string | undefined;
  for (const [version, value] of ledger.governancePolicyCommitmentsByVersion) {
    if (version < 1n || version > ledger.governancePolicyVersion
      || !ledger.governancePolicyEffectiveFromByVersion.member(version)) {
      throw new Error("Finalized policy revision history is incomplete");
    }
    const effectiveFrom = ledger.governancePolicyEffectiveFromByVersion.lookup(version);
    if (effectiveFrom <= sequence && (effectiveFrom > selectedEffectiveFrom
      || effectiveFrom === selectedEffectiveFrom && version > selectedVersion)) {
      selectedVersion = version;
      selectedEffectiveFrom = effectiveFrom;
      selectedCommitment = hex(value);
    }
  }
  if (selectedCommitment === undefined) {
    throw new Error("No finalized policy revision was effective at the proposal sequence");
  }
  return selectedCommitment;
}

export function assertCompletePolicyRevisionHistory(
  ledger: Pick<Ledger, "governancePolicyVersion" | "governanceActionCount"
    | "governancePolicyCommitmentsByVersion" | "governancePolicyVersionsByCommitment"
    | "governancePolicyEffectiveFromByVersion">,
): void {
  const version = ledger.governancePolicyVersion;
  if (version < 1n || ledger.governancePolicyCommitmentsByVersion.size() !== version
    || ledger.governancePolicyEffectiveFromByVersion.size() !== version
    || ledger.governancePolicyVersionsByCommitment.size() !== version) {
    throw new Error("Finalized policy revision history is incomplete");
  }
  let previousEffectiveFrom = -1n;
  for (let current = 1n; current <= version; current += 1n) {
    if (!ledger.governancePolicyCommitmentsByVersion.member(current)
      || !ledger.governancePolicyEffectiveFromByVersion.member(current)) {
      throw new Error("Finalized policy revision history is incomplete");
    }
    const commitmentBytes = ledger.governancePolicyCommitmentsByVersion.lookup(current);
    const effectiveFrom = ledger.governancePolicyEffectiveFromByVersion.lookup(current);
    if (!ledger.governancePolicyVersionsByCommitment.member(commitmentBytes)
      || ledger.governancePolicyVersionsByCommitment.lookup(commitmentBytes) !== current
      || effectiveFrom > ledger.governanceActionCount
      || (current === 1n ? effectiveFrom !== 0n : effectiveFrom <= previousEffectiveFrom)) {
      throw new Error("Finalized policy revision history is inconsistent");
    }
    previousEffectiveFrom = effectiveFrom;
  }
}

/**
 * Checks candidate projection coverage and represented fields at one caller-authenticated ledger view.
 * This does not authenticate finality, off-chain metadata, scope preimages, or historical bundle signatures.
 */
export function assertLocalLedgerProjectionMatchesSnapshot(
  snapshot: TrustRegistryOperatorSnapshot,
  ledger: Ledger,
): void {
  if (!ledger.initialized || ledger.contractVersion !== 1n
    || hex(ledger.registryId) !== commitment(snapshot.registry.registryId)
    || hex(ledger.registryDidCommitment) !== commitment(snapshot.registry.registryDid)
    || snapshot.policy.registryId !== snapshot.registry.registryId
    || ledger.governancePolicyVersion !== BigInt(snapshot.policy.version.slice(1))
    || hex(ledger.governancePolicyCommitment) !== computeGovernancePolicySnapshotCommitment(
      deriveGovernancePolicySnapshot(snapshot.policy),
    )) {
    throw new Error("Candidate registry or policy differs from finalized Compact state");
  }
  assertCompletePolicyRevisionHistory(ledger);
  if (!ledger.governancePolicyCommitmentsByVersion.member(ledger.governancePolicyVersion)
    || hex(ledger.governancePolicyCommitmentsByVersion.lookup(ledger.governancePolicyVersion))
      !== hex(ledger.governancePolicyCommitment)) {
    throw new Error("Finalized current policy is missing from its revision history");
  }

  assertExactMap("epoch", snapshot.epochs, (epoch) => epoch.epochId,
    ledger.epochCommitmentRecords, (epoch, value, key) => {
      const record = value as ReturnType<typeof ledger.epochCommitmentRecords.lookup>;
      if (hex(record.epochId) !== key || hex(record.stateRoot) !== epoch.stateRoot
        || hex(record.eventRoot) !== epoch.eventRoot || hex(record.policyRoot) !== epoch.policyRoot) {
        throw new Error("Candidate epoch differs from finalized Compact state");
      }
    });
  if (hex(ledger.latestEpochCommitmentId) !== commitment(snapshot.currentEpoch.epochId)
    || !snapshot.epochs.some((epoch) => canonicalizeJson(epoch) === canonicalizeJson(snapshot.currentEpoch))) {
    throw new Error("Candidate current epoch is not the finalized latest epoch");
  }

  assertExactMap("issuer", snapshot.issuerEntries,
    (entry) => entry.authorization.authorizationId, ledger.issuerAuthorizationRecords,
    (entry, value, key) => assertAuthorizationFields("issuer", entry,
      value as ReturnType<typeof ledger.issuerAuthorizationRecords.lookup>, key,
      policyCommitmentAtSequence(ledger,
        (value as ReturnType<typeof ledger.issuerAuthorizationRecords.lookup>).proposedAtSequence)));
  assertExactMap("verifier", snapshot.verifierEntries,
    (entry) => entry.authorization.authorizationId, ledger.verifierAuthorizationRecords,
    (entry, value, key) => assertAuthorizationFields("verifier", entry,
      value as ReturnType<typeof ledger.verifierAuthorizationRecords.lookup>, key,
      policyCommitmentAtSequence(ledger,
        (value as ReturnType<typeof ledger.verifierAuthorizationRecords.lookup>).proposedAtSequence)));
  assertExactMap("auditor", snapshot.auditorEntries,
    (entry) => entry.authorization.authorizationId, ledger.auditorAuthorizationRecords,
    (entry, value, key) => assertAuthorizationFields("auditor", entry,
      value as ReturnType<typeof ledger.auditorAuthorizationRecords.lookup>, key,
      policyCommitmentAtSequence(ledger,
        (value as ReturnType<typeof ledger.auditorAuthorizationRecords.lookup>).proposedAtSequence)));
  assertExactMap("recognition", snapshot.recognitionEntries,
    (entry) => entry.recognition.recognitionId, ledger.recognitionRecords,
    (entry, value, key) => {
      const record = value as ReturnType<typeof ledger.recognitionRecords.lookup>;
      const claim = (entry as RecognitionEntry).recognition;
      if (hex(record.recognitionId) !== key
        || hex(record.recognizedAuthorityDidCommitment) !== commitment(claim.recognizedAuthorityDid)
        || hex(record.recognizedRegistryId) !== commitment(claim.recognizedRegistryId)
        || hex(record.scopeResourceType) !== commitment(claim.scope.resourceType)
        || hex(record.scopeResourceId) !== commitment(claim.scope.resourceId)
        || hex(record.policyId) !== policyCommitmentAtSequence(ledger, record.proposedAtSequence)
        || hex(record.trustLevel) !== commitment(claim.trustLevel)
        || hex(record.evidenceHash) !== claim.evidenceHash
        || hex(record.lifecycleEventHash) !== claim.lifecycleEventRoot
        || AuthorizationStatus[record.status] !== claim.status) {
        throw new Error("Recognition candidate record differs from finalized Compact state");
      }
    });
  assertCurrentScopeIndex("issuer", ledger.issuerAuthorizationRecords,
    ledger.currentIssuerAuthorizationIdsByScopeKey,
    (record) => computeIssuerAuthorizationScopeKey(
      record.subjectDidCommitment, record.resourceType, record.resourceId));
  assertCurrentScopeIndex("verifier", ledger.verifierAuthorizationRecords,
    ledger.currentVerifierAuthorizationIdsByScopeKey,
    (record) => computeVerifierAuthorizationScopeKey(
      record.subjectDidCommitment, record.requestResourceId,
      record.allowedAttributeSetCommitment, record.allowedPredicateSetCommitment,
      record.disclosureLevelCommitment));
  assertCurrentScopeIndex("auditor", ledger.auditorAuthorizationRecords,
    ledger.currentAuditorAuthorizationIdsByScopeKey,
    (record) => computeAuditorAuthorizationScopeKey(
      record.subjectDidCommitment, record.requestResourceId,
      record.allowedAttributeSetCommitment, record.allowedPredicateSetCommitment,
      record.disclosureLevelCommitment));
  assertCurrentScopeIndex("recognition", ledger.recognitionRecords,
    ledger.currentRecognitionIdsByScopeKey,
    (record) => computeRecognitionScopeKey(
      record.recognizedAuthorityDidCommitment, record.recognizedRegistryId,
      record.scopeResourceType, record.scopeResourceId));
}

/** The ledger must already be authenticated at the selected finalized checkpoint. */
export function assertLocalLedgerEvidenceMatchesSnapshot(input: {
  snapshot: TrustRegistryOperatorSnapshot;
  ledger: Ledger;
  expectedNetworkId: "undeployed";
  contractAddress: Uint8Array;
  sequenceToTimestamp: SequenceToTimestamp;
}): void {
  const snapshot = TrustRegistryOperatorSnapshotSchema.parse(input.snapshot);
  assertLocalLedgerProjectionMatchesSnapshot(snapshot, input.ledger);
  const bundles = [
    ...snapshot.issuerEntries.map((entry) => entry.evidence),
    ...snapshot.verifierEntries.map((entry) => entry.evidence),
    ...snapshot.auditorEntries.map((entry) => entry.evidence),
    ...snapshot.recognitionEntries.map((entry) => entry.evidence),
    ...snapshot.evidenceArchive,
  ];
  for (const entry of [...snapshot.issuerEntries, ...snapshot.verifierEntries, ...snapshot.auditorEntries]) {
    if (entry.authorization.policyId !== entry.evidence.policy.policyId) {
      throw new Error("Authorization candidate policy ID differs from its evidence bundle");
    }
  }
  for (const entry of snapshot.recognitionEntries) {
    if (entry.recognition.policyId !== entry.evidence.policy.policyId) {
      throw new Error("Recognition candidate policy ID differs from its evidence bundle");
    }
  }
  const representedEpochs = new Set(bundles.map((bundle) => bundle.epoch.epochId));
  if (snapshot.epochs.some((epoch) => !representedEpochs.has(epoch.epochId))) {
    throw new Error("Candidate epoch has no authenticated evidence bundle");
  }
  for (const bundle of bundles) {
    const epoch = snapshot.epochs.find((candidate) => candidate.epochId === bundle.epoch.epochId);
    if (epoch === undefined || canonicalizeJson(epoch) !== canonicalizeJson(bundle.epoch)) {
      throw new Error("Candidate epoch metadata differs from its evidence bundle");
    }
    const anchor = resolveCompactHistoricalEpochAnchor({
      ledger: input.ledger,
      registryId: snapshot.registry.registryId,
      epochId: bundle.epoch.epochId,
      policyVersion: bundle.policy.version,
      expectedNetworkId: input.expectedNetworkId,
      contractAddress: input.contractAddress,
      sequenceToTimestamp: input.sequenceToTimestamp,
    });
    verifyTrustRegistryEvidenceBundle(bundle, {
      ...anchor,
      expectedRegistryId: snapshot.registry.registryId,
    });
  }
}
