import { Buffer } from "node:buffer";

import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import {
  computeCreateEpochCommitmentPayloadHash,
  decodeCanonicalJubjubSignatureHex,
  encodeCompactActionKind,
  verifyPolicyBoundMaintainerAction,
} from "@midnight-ntwrk/trust-registry-contract";
import type { EpochCommitmentRecord } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import {
  TrustRegistryEvidenceBundleSchema,
  computeAuthorizationStatementLeafHash,
  computeGovernancePolicySnapshotCommitment,
  assertIssuerStatusPolicyBindingMatchesAuthorization,
  computeMerkleRootFromProof,
  computeRecognitionStatementLeafHash,
  deriveGovernancePolicySnapshot,
  type AuthorizationRecord,
  type TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  bytes32Commitment,
  defaultSequenceToTimestamp,
  sameBytes32,
  type SequenceToTimestamp,
} from "./utils.js";

const EPOCH_PUBLISH_ACTION_KIND = encodeCompactActionKind("tr:epoch:publish");

/**
 * Caller-authenticated epoch context. These values are not authenticated by
 * the free bundle verifier: resolve them from a format-one registry ledger or
 * another independently trusted source before treating its result as trust.
 */
export type EpochAnchorVerificationContext = {
  epochRecord: EpochCommitmentRecord;
  maintainerPublicKey: JubjubPoint;
  registryIdCommitment: Uint8Array;
  sequenceToTimestamp?: SequenceToTimestamp;
  policySupersededAt?: string;
};

export type BundleVerificationOptions = {
  expectedRegistryId?: string;
  expectedSubjectDid?: string;
  expectedResourceId?: string;
  expectedRecognizedRegistryId?: string;
  expectedRole?: AuthorizationRecord["role"];
  expectedTrustLevel?: string;
  evaluationTime?: string;
  requireActive?: boolean;
} & EpochAnchorVerificationContext;

const assertCommonBundleExpectations = (
  bundle: TrustRegistryEvidenceBundle,
  options: BundleVerificationOptions,
): void => {
  if (
    options.expectedRegistryId !== undefined
    && bundle.registryId !== options.expectedRegistryId
  ) {
    throw new Error(
      `Trust registry mismatch: expected ${options.expectedRegistryId}, got ${bundle.registryId}`,
    );
  }
  if (
    options.expectedSubjectDid !== undefined
    && bundle.subjectDid !== options.expectedSubjectDid
  ) {
    throw new Error(
      `Subject DID mismatch: expected ${options.expectedSubjectDid}, got ${bundle.subjectDid}`,
    );
  }
  if (
    options.expectedTrustLevel !== undefined
    && bundle.authorization?.trustLevel !== undefined
    && bundle.authorization.trustLevel !== options.expectedTrustLevel
  ) {
    throw new Error(
      `Authorization trust level mismatch: expected ${options.expectedTrustLevel}, got ${bundle.authorization.trustLevel}`,
    );
  }
  if (
    options.expectedTrustLevel !== undefined
    && bundle.recognition?.trustLevel !== undefined
    && bundle.recognition.trustLevel !== options.expectedTrustLevel
  ) {
    throw new Error(
      `Recognition trust level mismatch: expected ${options.expectedTrustLevel}, got ${bundle.recognition.trustLevel}`,
    );
  }
};

const assertEpochAnchor = (
  bundle: TrustRegistryEvidenceBundle,
  options: BundleVerificationOptions,
): void => {
  const sequenceToTimestamp =
    options.sequenceToTimestamp ?? defaultSequenceToTimestamp;
  const { epochRecord } = options;
  const expectedEpochIdCommitment = bytes32Commitment(bundle.epoch.epochId);

  if (!sameBytes32(expectedEpochIdCommitment, epochRecord.epochId)) {
    throw new Error("Epoch id mismatch");
  }
  if (bundle.epoch.stateRoot !== `0x${Buffer.from(epochRecord.stateRoot).toString("hex")}`) {
    throw new Error("Epoch state root mismatch");
  }
  if (bundle.epoch.eventRoot !== `0x${Buffer.from(epochRecord.eventRoot).toString("hex")}`) {
    throw new Error("Epoch event root mismatch");
  }
  if (bundle.epoch.policyRoot !== `0x${Buffer.from(epochRecord.policyRoot).toString("hex")}`) {
    throw new Error("Epoch policy root mismatch");
  }
  if (bundle.epoch.validFrom !== sequenceToTimestamp(epochRecord.validFromSequence)) {
    throw new Error("Epoch validFrom mismatch");
  }
  if (bundle.epoch.validUntil !== sequenceToTimestamp(epochRecord.validUntilSequence)) {
    throw new Error("Epoch validUntil mismatch");
  }

  const evaluationTime = Date.parse(options.evaluationTime ?? bundle.generatedAt);
  if (!Number.isFinite(evaluationTime)) {
    throw new Error("Evaluation time is invalid");
  }
  if (evaluationTime < Date.parse(bundle.epoch.validFrom)) {
    throw new Error("Epoch is not yet valid for this evidence bundle");
  }
  if (evaluationTime > Date.parse(bundle.epoch.validUntil)) {
    throw new Error("Epoch is stale for this evidence bundle");
  }

  const maintainerSignature = bundle.epoch.maintainerSignatures[0]!;
  if (maintainerSignature.algorithm !== "jubjub-schnorr") {
    throw new Error("Epoch maintainer signature algorithm is unsupported");
  }
  let signature: ReturnType<typeof decodeCanonicalJubjubSignatureHex>;
  try {
    signature = decodeCanonicalJubjubSignatureHex(maintainerSignature.signature);
  } catch (error) {
    throw new Error("Epoch maintainer signature encoding is invalid", { cause: error });
  }
  const payloadHash = computeCreateEpochCommitmentPayloadHash(
    epochRecord.epochId,
    epochRecord.stateRoot,
    epochRecord.eventRoot,
    epochRecord.policyRoot,
    epochRecord.validFromSequence,
    epochRecord.validUntilSequence,
  );
  if (
    !(epochRecord.publicationPolicyCommitment instanceof Uint8Array)
    || epochRecord.publicationPolicyCommitment.length !== 32
    || epochRecord.publicationPolicyCommitment.every((byte) => byte === 0)
  ) {
    throw new Error("Epoch publication policy commitment is missing or malformed");
  }
  if (
    !(options.registryIdCommitment instanceof Uint8Array)
    || options.registryIdCommitment.length !== 32
  ) {
    throw new Error("Registry ID commitment is missing or malformed");
  }

  let validSignature = false;
  try {
    validSignature = verifyPolicyBoundMaintainerAction(
      options.maintainerPublicKey,
      options.registryIdCommitment,
      epochRecord.publicationPolicyCommitment,
      EPOCH_PUBLISH_ACTION_KIND,
      payloadHash,
      epochRecord.publishedAtSequence,
      signature,
    );
  } catch {
    // Unexpected verification failures must not authenticate the epoch.
  }
  if (!validSignature) {
    throw new Error("Epoch maintainer signature is invalid");
  }
};

const assertPolicyAnchor = (
  bundle: TrustRegistryEvidenceBundle,
  options: BundleVerificationOptions,
): void => {
  const snapshot = deriveGovernancePolicySnapshot(bundle.policy);
  const expectedPolicyRoot = computeGovernancePolicySnapshotCommitment(snapshot);
  if (bundle.epoch.policyRoot !== expectedPolicyRoot) {
    throw new Error("Policy root does not match the bundle policy");
  }
  const evaluationTime = Date.parse(options.evaluationTime ?? bundle.generatedAt);
  if (
    options.policySupersededAt !== undefined
    && !Number.isFinite(Date.parse(options.policySupersededAt))
  ) {
    throw new Error("Policy supersession time is invalid");
  }
  if (evaluationTime < Date.parse(snapshot.effectiveFrom)) {
    throw new Error("Policy snapshot is not yet effective");
  }
  if (
    (snapshot.effectiveUntil !== null
      && evaluationTime >= Date.parse(snapshot.effectiveUntil))
    || (options.policySupersededAt !== undefined
      && evaluationTime >= Date.parse(options.policySupersededAt))
  ) {
    throw new Error("Policy snapshot is superseded at the evaluation time");
  }
};

const assertInclusionProof = (
  bundle: TrustRegistryEvidenceBundle,
): void => {
  const expectedLeafHash =
    bundle.authorization !== undefined
      ? computeAuthorizationStatementLeafHash(bundle.authorization)
      : computeRecognitionStatementLeafHash(bundle.recognition!);

  if (bundle.inclusionProof.proofType !== "merkle-inclusion") {
    throw new Error(
      `Unsupported inclusion proof type: ${bundle.inclusionProof.proofType}`,
    );
  }
  if (bundle.inclusionProof.leafHash !== expectedLeafHash) {
    throw new Error("Inclusion proof leaf hash does not match the statement");
  }
  if (bundle.inclusionProof.root !== bundle.epoch.stateRoot) {
    throw new Error("Inclusion proof root does not match the anchored state root");
  }
  if (bundle.inclusionProof.path[0] !== bundle.epoch.eventRoot) {
    throw new Error(
      "Inclusion proof event sibling does not match the anchored event root",
    );
  }

  const computedStateRoot = computeMerkleRootFromProof(
    expectedLeafHash,
    bundle.inclusionProof.path,
    bundle.inclusionProof.leafIndex,
  );
  if (computedStateRoot !== bundle.inclusionProof.root) {
    throw new Error(
      "Inclusion proof root does not match the reconstructed state root",
    );
  }
};

const assertIssuerStatusPolicyBinding = (
  bundle: TrustRegistryEvidenceBundle,
): void => {
  if (bundle.authorization?.role !== "issuer") return;
  if (bundle.statusPolicyBinding === undefined) {
    throw new Error("Issuer status policy binding preimage is missing");
  }
  if (bundle.authorization.statusPolicyBindingCommitment === undefined) {
    throw new Error("Issuer status policy binding commitment is missing");
  }
  assertIssuerStatusPolicyBindingMatchesAuthorization(
    bundle.statusPolicyBinding,
    bundle.registryId,
    bundle.authorization.authorizationId,
    bundle.authorization.statusPolicyBindingCommitment,
  );
  if (
    bundle.referencedStatusRegistryId !== undefined
    || bundle.referencedStatusPolicyUri !== undefined
  ) {
    throw new Error("Unanchored issuer status metadata is not accepted");
  }
};

/** Verifies consistency with the caller's anchor, not that anchor's provenance. */
export const verifyTrustRegistryEvidenceBundle = (
  bundleInput: TrustRegistryEvidenceBundle,
  options: BundleVerificationOptions,
): TrustRegistryEvidenceBundle => {
  const bundle = TrustRegistryEvidenceBundleSchema.parse(bundleInput);
  assertCommonBundleExpectations(bundle, options);
  if (
    options.expectedRole !== undefined
    && bundle.authorization?.role !== options.expectedRole
  ) {
    throw new Error(
      `Authorization role mismatch: expected ${options.expectedRole}, got ${bundle.authorization?.role ?? "none"}`,
    );
  }
  assertEpochAnchor(bundle, options);
  assertPolicyAnchor(bundle, options);
  assertInclusionProof(bundle);
  assertIssuerStatusPolicyBinding(bundle);

  return bundle;
};

export const verifyIssuerAuthorizationBundle = (
  bundleInput: TrustRegistryEvidenceBundle,
  options: BundleVerificationOptions,
): TrustRegistryEvidenceBundle => {
  const bundle = verifyTrustRegistryEvidenceBundle(bundleInput, options);
  const authorization = bundle.authorization;

  if (authorization === undefined || authorization.role !== "issuer") {
    throw new Error("Evidence bundle does not contain issuer authorization");
  }
  if ((options.requireActive ?? true) && authorization.status !== "active") {
    throw new Error("Issuer authorization is not active");
  }
  if (
    options.expectedResourceId !== undefined
    && authorization.resourceId !== options.expectedResourceId
  ) {
    throw new Error(
      `Issuer authorization resource mismatch: expected ${options.expectedResourceId}, got ${authorization.resourceId}`,
    );
  }

  return bundle;
};

export const verifyVerifierAuthorizationBundle = (
  bundleInput: TrustRegistryEvidenceBundle,
  options: BundleVerificationOptions,
): TrustRegistryEvidenceBundle => {
  const bundle = verifyTrustRegistryEvidenceBundle(bundleInput, options);
  const authorization = bundle.authorization;

  if (authorization === undefined || authorization.role !== "verifier") {
    throw new Error("Evidence bundle does not contain verifier authorization");
  }
  if ((options.requireActive ?? true) && authorization.status !== "active") {
    throw new Error("Verifier authorization is not active");
  }
  if (
    options.expectedResourceId !== undefined
    && authorization.resourceId !== options.expectedResourceId
  ) {
    throw new Error(
      `Verifier authorization resource mismatch: expected ${options.expectedResourceId}, got ${authorization.resourceId}`,
    );
  }

  return bundle;
};

export const verifyAuditorAuthorizationBundle = (
  bundleInput: TrustRegistryEvidenceBundle,
  options: BundleVerificationOptions,
): TrustRegistryEvidenceBundle => {
  const bundle = verifyTrustRegistryEvidenceBundle(bundleInput, options);
  const authorization = bundle.authorization;

  if (authorization === undefined || authorization.role !== "auditor") {
    throw new Error("Evidence bundle does not contain auditor authorization");
  }
  if ((options.requireActive ?? true) && authorization.status !== "active") {
    throw new Error("Auditor authorization is not active");
  }
  if (
    options.expectedResourceId !== undefined
    && authorization.resourceId !== options.expectedResourceId
  ) {
    throw new Error(
      `Auditor authorization resource mismatch: expected ${options.expectedResourceId}, got ${authorization.resourceId}`,
    );
  }

  return bundle;
};

export const verifyRecognitionBundle = (
  bundleInput: TrustRegistryEvidenceBundle,
  options: BundleVerificationOptions,
): TrustRegistryEvidenceBundle => {
  const bundle = verifyTrustRegistryEvidenceBundle(bundleInput, options);
  const recognition = bundle.recognition;

  if (recognition === undefined) {
    throw new Error("Evidence bundle does not contain recognition");
  }
  if ((options.requireActive ?? true) && recognition.status !== "active") {
    throw new Error("Recognition is not active");
  }
  if (
    options.expectedResourceId !== undefined
    && recognition.scope.resourceId !== options.expectedResourceId
  ) {
    throw new Error(
      `Recognition scope mismatch: expected ${options.expectedResourceId}, got ${recognition.scope.resourceId}`,
    );
  }
  if (
    options.expectedRecognizedRegistryId !== undefined
    && recognition.recognizedRegistryId !== options.expectedRecognizedRegistryId
  ) {
    throw new Error(
      `Recognition registry mismatch: expected ${options.expectedRecognizedRegistryId}, got ${recognition.recognizedRegistryId}`,
    );
  }

  return bundle;
};
