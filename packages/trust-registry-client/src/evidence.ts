import { Buffer } from "node:buffer";

import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import {
  computeCreateEpochCommitmentPayloadHash,
  decodeJubjubSignature,
  labelToBytes32,
  verifyMaintainerAction,
} from "@midnight-ntwrk/trust-registry-contract";
import type { EpochCommitmentRecord } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
import {
  TrustRegistryEvidenceBundleSchema,
  type AuthorizationRecord,
  type RecognitionRecord,
  type TrustRegistryEvidenceBundle,
  sha256Hex,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  bytes32Commitment,
  defaultSequenceToTimestamp,
  sameBytes32,
  type SequenceToTimestamp,
} from "./utils.js";

const EPOCH_PUBLISH_ACTION_KIND = labelToBytes32("tr:epoch:publish");

export type EpochAnchorVerificationContext = {
  epochRecord: EpochCommitmentRecord;
  maintainerPublicKey: JubjubPoint;
  registryIdCommitment: Uint8Array;
  sequenceToTimestamp?: SequenceToTimestamp;
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

const bundleLeafHash = (authorization: AuthorizationRecord): string =>
  sha256Hex(
    JSON.stringify({
      authorizationId: authorization.authorizationId,
      status: authorization.status,
      subjectDid: authorization.subjectDid,
      resourceId: authorization.resourceId,
    }),
  );

const recognitionLeafHash = (recognition: RecognitionRecord): string =>
  sha256Hex(
    JSON.stringify({
      recognitionId: recognition.recognitionId,
      status: recognition.status,
      recognizedAuthorityDid: recognition.recognizedAuthorityDid,
      recognizedRegistryId: recognition.recognizedRegistryId,
      scope: recognition.scope,
    }),
  );

const computeBundleStateRoot = (
  bundle: TrustRegistryEvidenceBundle,
): string => {
  const statementId =
    bundle.authorization?.authorizationId ?? bundle.recognition?.recognitionId;
  const statementStatus =
    bundle.authorization?.status ?? bundle.recognition?.status;
  const lifecycleEventRoot =
    bundle.authorization?.lifecycleEventRoot
    ?? bundle.recognition?.lifecycleEventRoot;

  return sha256Hex(
    JSON.stringify({
      registryId: bundle.registryId,
      statementId,
      status: statementStatus,
      lifecycleEventRoot,
    }),
  );
};

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
  if (evaluationTime < Date.parse(bundle.epoch.validFrom)) {
    throw new Error("Epoch is not yet valid for this evidence bundle");
  }
  if (evaluationTime > Date.parse(bundle.epoch.validUntil)) {
    throw new Error("Epoch is stale for this evidence bundle");
  }

  const maintainerSignature = bundle.epoch.maintainerSignatures.at(0);
  if (maintainerSignature === undefined) {
    throw new Error("Epoch commitment must include at least one maintainer signature");
  }
  const signature = decodeJubjubSignature(
    Buffer.from(maintainerSignature.signature.replace(/^0x/, ""), "hex"),
  );
  const payloadHash = computeCreateEpochCommitmentPayloadHash(
    epochRecord.epochId,
    epochRecord.stateRoot,
    epochRecord.eventRoot,
    epochRecord.policyRoot,
    epochRecord.validFromSequence,
    epochRecord.validUntilSequence,
  );

  if (
    !verifyMaintainerAction(
      options.maintainerPublicKey,
      options.registryIdCommitment,
      EPOCH_PUBLISH_ACTION_KIND,
      payloadHash,
      epochRecord.publishedAtSequence,
      signature,
    )
  ) {
    throw new Error("Epoch maintainer signature is invalid");
  }
};

const assertInclusionProof = (
  bundle: TrustRegistryEvidenceBundle,
): void => {
  const expectedLeafHash =
    bundle.authorization !== undefined
      ? bundleLeafHash(bundle.authorization)
      : recognitionLeafHash(bundle.recognition!);

  if (bundle.inclusionProof.root !== bundle.epoch.eventRoot) {
    throw new Error("Inclusion proof root does not match the anchored event root");
  }
  if (bundle.inclusionProof.leafHash !== expectedLeafHash) {
    throw new Error("Inclusion proof leaf hash does not match the statement");
  }
  const expectedStateRoot = computeBundleStateRoot(bundle);
  if (bundle.epoch.stateRoot !== expectedStateRoot) {
    throw new Error("Bundle state root does not match the anchored statement state");
  }
  if (bundle.inclusionProof.path[0] !== expectedStateRoot) {
    throw new Error("Inclusion proof path does not match the anchored state root");
  }
};

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
  assertInclusionProof(bundle);

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
