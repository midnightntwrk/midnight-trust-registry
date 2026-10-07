import {
  MAX_FIELD,
  type JubjubPoint,
} from "@midnight-ntwrk/compact-runtime";
import {
  computeJubjubDigestChallenge,
  decodeJubjubSignature,
  deriveJubjubPublicKey,
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  JUBJUB_ORDER,
  JUBJUB_SIGNATURE_LENGTH_BYTES,
  normalizeScalar,
  seedBytesToJubjubSecretScalar,
  signJubjubDigestFromSeed,
  TWO_248,
  type JubjubDigest,
  type JubjubSchnorrSignature,
  verifyJubjubDigest,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";

import {
  type IssuerResourceType,
  pureCircuits,
} from "./managed/trust-registry/contract/index.js";

export {
  computeJubjubDigestChallenge,
  decodeJubjubSignature,
  deriveJubjubPublicKey,
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  JUBJUB_ORDER,
  JUBJUB_SIGNATURE_LENGTH_BYTES,
  normalizeScalar,
  seedBytesToJubjubSecretScalar,
  TWO_248,
};

export type TrustRegistryActionDigest = JubjubDigest;
export type TrustRegistryJubjubSignature = JubjubSchnorrSignature;

const isCanonicalJubjubSignature = (signature: TrustRegistryJubjubSignature): boolean =>
  signature !== null
  && signature !== undefined
  && typeof signature.response === "bigint"
  && signature.announcement !== null
  && signature.announcement !== undefined
  && typeof signature.announcement.x === "bigint"
  && typeof signature.announcement.y === "bigint"
  && signature.response >= 0n
  && signature.response < JUBJUB_ORDER
  && signature.announcement.x >= 0n
  && signature.announcement.x <= MAX_FIELD
  && signature.announcement.y >= 0n
  && signature.announcement.y <= MAX_FIELD;

export const decodeCanonicalJubjubSignatureHex = (value: string): TrustRegistryJubjubSignature => {
  if (
    value.length !== 2 + JUBJUB_SIGNATURE_LENGTH_BYTES * 2
    || !/^0x[0-9a-f]+$/u.test(value)
  ) {
    throw new Error("Jubjub signature encoding is invalid");
  }
  try {
    const signature = decodeJubjubSignature(Buffer.from(value.slice(2), "hex"));
    if (isCanonicalJubjubSignature(signature)) return signature;
  } catch {
    // Decode failures and noncanonical encodings share one public error.
  }
  throw new Error("Jubjub signature encoding is invalid");
};

const ensure32Bytes = (value: Uint8Array): Buffer => {
  const buffer = Buffer.from(value);
  if (buffer.length === 32) return buffer;
  if (buffer.length > 32) return buffer.subarray(0, 32);
  return Buffer.concat([buffer, Buffer.alloc(32 - buffer.length)]);
};

const require32Bytes = (value: Uint8Array, label: string): Buffer => {
  if (value.length !== 32) throw new RangeError(`${label} must be 32 bytes`);
  return Buffer.from(value);
};

/** Binds the evidence commitment and verifier key id to a distinct Compact Schnorr domain. */
export const applicationEvidenceSignatureDigest = (
  keyIdCommitment: Uint8Array,
  commitment: Uint8Array,
): TrustRegistryActionDigest =>
  pureCircuits.applicationEvidenceSignatureDigest(
    require32Bytes(keyIdCommitment, "Evidence verifier key id commitment"),
    require32Bytes(commitment, "Application evidence commitment"),
  ) as TrustRegistryActionDigest;

export const signApplicationEvidenceCommitmentFromSeed = (
  seed: Uint8Array,
  keyIdCommitment: Uint8Array,
  commitment: Uint8Array,
): TrustRegistryJubjubSignature =>
  signJubjubDigestFromSeed(
    require32Bytes(seed, "Evidence verifier seed"),
    applicationEvidenceSignatureDigest(keyIdCommitment, commitment),
  );

/** Verifies a signature only; the caller must separately authorize the DID assertion key. */
export const verifyApplicationEvidenceCommitmentSignature = (
  publicKey: JubjubPoint,
  keyIdCommitment: Uint8Array,
  commitment: Uint8Array,
  signature: TrustRegistryJubjubSignature,
): boolean => {
  if (!isCanonicalJubjubSignature(signature)) return false;
  const digest = applicationEvidenceSignatureDigest(keyIdCommitment, commitment);
  try {
    return verifyJubjubDigest(publicKey, digest, signature);
  } catch {
    return false;
  }
};

export const computePolicyBoundActionPayloadHash = (
  policyCommitment: Uint8Array,
  actionPayloadHash: Uint8Array,
): Uint8Array =>
  pureCircuits.policyBoundActionPayloadHash(
    require32Bytes(policyCommitment, "Policy commitment"),
    require32Bytes(actionPayloadHash, "Action payload hash"),
  );

export const computePolicyBoundMaintainerActionDigest = (
  registryId: Uint8Array,
  policyCommitment: Uint8Array,
  actionKind: Uint8Array,
  actionPayloadHash: Uint8Array,
  actionSequence: bigint,
): TrustRegistryActionDigest =>
  pureCircuits.policyBoundMaintainerActionDigest(
    require32Bytes(registryId, "Registry id"),
    require32Bytes(policyCommitment, "Policy commitment"),
    require32Bytes(actionKind, "Action kind"),
    require32Bytes(actionPayloadHash, "Action payload hash"),
    actionSequence,
  ) as TrustRegistryActionDigest;

export const computeIssuerAuthorizationScopeKey = (
  subjectDidCommitment: Uint8Array,
  resourceType: IssuerResourceType,
  resourceId: Uint8Array,
): Uint8Array =>
  pureCircuits.issuerAuthorizationScopeKey(
    ensure32Bytes(subjectDidCommitment),
    resourceType,
    ensure32Bytes(resourceId),
  );

export const computeCreateIssuerAuthorizationPayloadHash = (
  authorizationId: Uint8Array,
  subjectDidCommitment: Uint8Array,
  resourceType: IssuerResourceType,
  resourceId: Uint8Array,
  policyId: Uint8Array,
  statusPolicyBindingCommitment: Uint8Array,
  trustLevel: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.createIssuerAuthorizationPayloadHash(
    ensure32Bytes(authorizationId),
    ensure32Bytes(subjectDidCommitment),
    resourceType,
    ensure32Bytes(resourceId),
    ensure32Bytes(policyId),
    ensure32Bytes(statusPolicyBindingCommitment),
    ensure32Bytes(trustLevel),
    ensure32Bytes(evidenceHash),
  );

export const computeUpdateIssuerAuthorizationPayloadHash = (
  authorizationId: Uint8Array,
  previousLifecycleEventHash: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.updateIssuerAuthorizationPayloadHash(
    ensure32Bytes(authorizationId),
    ensure32Bytes(previousLifecycleEventHash),
    ensure32Bytes(evidenceHash),
  );

export const computeVerifierAuthorizationScopeKey = (
  subjectDidCommitment: Uint8Array,
  requestProfileId: Uint8Array,
  allowedAttributeSetCommitment: Uint8Array,
  allowedPredicateSetCommitment: Uint8Array,
  disclosureLevelCommitment: Uint8Array,
): Uint8Array =>
  pureCircuits.verifierAuthorizationScopeKey(
    ensure32Bytes(subjectDidCommitment),
    ensure32Bytes(requestProfileId),
    ensure32Bytes(allowedAttributeSetCommitment),
    ensure32Bytes(allowedPredicateSetCommitment),
    ensure32Bytes(disclosureLevelCommitment),
  );

export const computeAuditorAuthorizationScopeKey = (
  subjectDidCommitment: Uint8Array,
  requestProfileId: Uint8Array,
  allowedAttributeSetCommitment: Uint8Array,
  allowedPredicateSetCommitment: Uint8Array,
  disclosureLevelCommitment: Uint8Array,
): Uint8Array =>
  pureCircuits.auditorAuthorizationScopeKey(
    ensure32Bytes(subjectDidCommitment),
    ensure32Bytes(requestProfileId),
    ensure32Bytes(allowedAttributeSetCommitment),
    ensure32Bytes(allowedPredicateSetCommitment),
    ensure32Bytes(disclosureLevelCommitment),
  );

export const computeRecognitionScopeKey = (
  recognizedAuthorityDidCommitment: Uint8Array,
  recognizedRegistryId: Uint8Array,
  scopeResourceType: Uint8Array,
  scopeResourceId: Uint8Array,
): Uint8Array =>
  pureCircuits.recognitionScopeKey(
    ensure32Bytes(recognizedAuthorityDidCommitment),
    ensure32Bytes(recognizedRegistryId),
    ensure32Bytes(scopeResourceType),
    ensure32Bytes(scopeResourceId),
  );

export const computeCreateVerifierAuthorizationPayloadHash = (
  authorizationId: Uint8Array,
  subjectDidCommitment: Uint8Array,
  requestProfileId: Uint8Array,
  allowedAttributeSetCommitment: Uint8Array,
  allowedPredicateSetCommitment: Uint8Array,
  disclosureLevelCommitment: Uint8Array,
  policyId: Uint8Array,
  trustLevel: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.createVerifierAuthorizationPayloadHash(
    ensure32Bytes(authorizationId),
    ensure32Bytes(subjectDidCommitment),
    ensure32Bytes(requestProfileId),
    ensure32Bytes(allowedAttributeSetCommitment),
    ensure32Bytes(allowedPredicateSetCommitment),
    ensure32Bytes(disclosureLevelCommitment),
    ensure32Bytes(policyId),
    ensure32Bytes(trustLevel),
    ensure32Bytes(evidenceHash),
  );

export const computeCreateRecognitionPayloadHash = (
  recognitionId: Uint8Array,
  recognizedAuthorityDidCommitment: Uint8Array,
  recognizedRegistryId: Uint8Array,
  scopeResourceType: Uint8Array,
  scopeResourceId: Uint8Array,
  policyId: Uint8Array,
  trustLevel: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.createRecognitionPayloadHash(
    ensure32Bytes(recognitionId),
    ensure32Bytes(recognizedAuthorityDidCommitment),
    ensure32Bytes(recognizedRegistryId),
    ensure32Bytes(scopeResourceType),
    ensure32Bytes(scopeResourceId),
    ensure32Bytes(policyId),
    ensure32Bytes(trustLevel),
    ensure32Bytes(evidenceHash),
  );

export const computeCreateAuditorAuthorizationPayloadHash = (
  authorizationId: Uint8Array,
  subjectDidCommitment: Uint8Array,
  requestProfileId: Uint8Array,
  allowedAttributeSetCommitment: Uint8Array,
  allowedPredicateSetCommitment: Uint8Array,
  disclosureLevelCommitment: Uint8Array,
  policyId: Uint8Array,
  trustLevel: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.createAuditorAuthorizationPayloadHash(
    ensure32Bytes(authorizationId),
    ensure32Bytes(subjectDidCommitment),
    ensure32Bytes(requestProfileId),
    ensure32Bytes(allowedAttributeSetCommitment),
    ensure32Bytes(allowedPredicateSetCommitment),
    ensure32Bytes(disclosureLevelCommitment),
    ensure32Bytes(policyId),
    ensure32Bytes(trustLevel),
    ensure32Bytes(evidenceHash),
  );

export const computeCreateEpochCommitmentPayloadHash = (
  epochId: Uint8Array,
  stateRoot: Uint8Array,
  eventRoot: Uint8Array,
  policyRoot: Uint8Array,
  validFromSequence: bigint,
  validUntilSequence: bigint,
): Uint8Array =>
  pureCircuits.createEpochCommitmentPayloadHash(
    ensure32Bytes(epochId),
    ensure32Bytes(stateRoot),
    ensure32Bytes(eventRoot),
    ensure32Bytes(policyRoot),
    validFromSequence,
    validUntilSequence,
  );

export const computeCreateMaintainerMembershipPayloadHash = (
  maintainerId: Uint8Array,
  maintainerDidCommitment: Uint8Array,
  keyId: Uint8Array,
  publicKey: JubjubPoint,
  policyId: Uint8Array,
  trustLevel: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.createMaintainerMembershipPayloadHash(
    ensure32Bytes(maintainerId),
    ensure32Bytes(maintainerDidCommitment),
    ensure32Bytes(keyId),
    publicKey,
    ensure32Bytes(policyId),
    ensure32Bytes(trustLevel),
    ensure32Bytes(evidenceHash),
  );

export const computeUpdateVerifierAuthorizationPayloadHash = (
  authorizationId: Uint8Array,
  previousLifecycleEventHash: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.updateVerifierAuthorizationPayloadHash(
    ensure32Bytes(authorizationId),
    ensure32Bytes(previousLifecycleEventHash),
    ensure32Bytes(evidenceHash),
  );

export const computeUpdateRecognitionPayloadHash = (
  recognitionId: Uint8Array,
  previousLifecycleEventHash: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.updateRecognitionPayloadHash(
    ensure32Bytes(recognitionId),
    ensure32Bytes(previousLifecycleEventHash),
    ensure32Bytes(evidenceHash),
  );

export const computeUpdateAuditorAuthorizationPayloadHash = (
  authorizationId: Uint8Array,
  previousLifecycleEventHash: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.updateAuditorAuthorizationPayloadHash(
    ensure32Bytes(authorizationId),
    ensure32Bytes(previousLifecycleEventHash),
    ensure32Bytes(evidenceHash),
  );

export const computeUpdateMaintainerMembershipPayloadHash = (
  maintainerId: Uint8Array,
  previousLifecycleEventHash: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.updateMaintainerMembershipPayloadHash(
    ensure32Bytes(maintainerId),
    ensure32Bytes(previousLifecycleEventHash),
    ensure32Bytes(evidenceHash),
  );

export const computeUpdateMaintainerThresholdPolicyPayloadHash = (
  previousPolicyCommitment: Uint8Array,
  nextPolicyCommitment: Uint8Array,
  nextPolicyVersion: bigint,
  defaultThreshold: bigint,
  emergencyThreshold: bigint,
  archivalThreshold: bigint,
): Uint8Array =>
  pureCircuits.updateMaintainerThresholdPolicyPayloadHash(
    ensure32Bytes(previousPolicyCommitment),
    ensure32Bytes(nextPolicyCommitment),
    nextPolicyVersion,
    defaultThreshold,
    emergencyThreshold,
    archivalThreshold,
  );

const signMaintainerActionDigestFromSeed = (
  seedBytes: Uint8Array,
  digest: TrustRegistryActionDigest,
): TrustRegistryJubjubSignature =>
  signJubjubDigestFromSeed(ensure32Bytes(seedBytes), digest);

export const signPolicyBoundMaintainerActionFromSeed = (
  seedBytes: Uint8Array,
  registryId: Uint8Array,
  policyCommitment: Uint8Array,
  actionKind: Uint8Array,
  actionPayloadHash: Uint8Array,
  actionSequence: bigint,
): TrustRegistryJubjubSignature =>
  signMaintainerActionDigestFromSeed(
    seedBytes,
    computePolicyBoundMaintainerActionDigest(
      registryId,
      policyCommitment,
      actionKind,
      actionPayloadHash,
      actionSequence,
    ),
  );

const verifyMaintainerActionDigest = (
  publicKey: JubjubPoint,
  digest: TrustRegistryActionDigest,
  signature: TrustRegistryJubjubSignature,
): boolean => {
  if (!isCanonicalJubjubSignature(signature)) return false;
  try {
    return verifyJubjubDigest(publicKey, digest, signature);
  } catch {
    return false;
  }
};

export const verifyPolicyBoundMaintainerAction = (
  publicKey: JubjubPoint,
  registryId: Uint8Array,
  policyCommitment: Uint8Array,
  actionKind: Uint8Array,
  actionPayloadHash: Uint8Array,
  actionSequence: bigint,
  signature: TrustRegistryJubjubSignature,
): boolean =>
  verifyMaintainerActionDigest(
    publicKey,
    computePolicyBoundMaintainerActionDigest(
      registryId,
      policyCommitment,
      actionKind,
      actionPayloadHash,
      actionSequence,
    ),
    signature,
  );
