import {
  MAX_FIELD,
  ecMul,
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

/** Compact action-kind literals use exact zero-padded bytes, never fixture hashing. */
export const encodeCompactActionKind = (kind: string): Uint8Array => {
  if (!/^tr:[\x21-\x7e]+$/u.test(kind)) throw new Error("Action kind must be printable ASCII with a tr: prefix");
  const encoded = new TextEncoder().encode(kind);
  if (encoded.length > 32) throw new Error("Action kind exceeds Compact Bytes<32>");
  const bytes = new Uint8Array(32);
  bytes.set(encoded);
  return bytes;
};

const isNonIdentityJubjubPoint = (point: JubjubPoint): boolean => {
  if (point === null || point === undefined
    || typeof point.x !== "bigint" || typeof point.y !== "bigint"
    || point.x < 0n || point.x > MAX_FIELD
    || point.y < 0n || point.y > MAX_FIELD
    || (point.x === 0n && point.y === 1n)) return false;
  try {
    ecMul(point, 1n);
    return true;
  } catch {
    return false;
  }
};

const isCanonicalJubjubSignature = (signature: TrustRegistryJubjubSignature): boolean =>
  signature !== null
  && signature !== undefined
  && typeof signature.response === "bigint"
  && signature.response >= 0n
  && signature.response < JUBJUB_ORDER
  && isNonIdentityJubjubPoint(signature.announcement);

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
  if (!isNonIdentityJubjubPoint(publicKey) || !isCanonicalJubjubSignature(signature)) return false;
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
    require32Bytes(subjectDidCommitment, "Subject DID commitment"),
    resourceType,
    require32Bytes(resourceId, "Resource id"),
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
    require32Bytes(authorizationId, "Authorization id"),
    require32Bytes(subjectDidCommitment, "Subject DID commitment"),
    resourceType,
    require32Bytes(resourceId, "Resource id"),
    require32Bytes(policyId, "Policy id"),
    require32Bytes(statusPolicyBindingCommitment, "Status policy binding commitment"),
    require32Bytes(trustLevel, "Trust level"),
    require32Bytes(evidenceHash, "Evidence hash"),
  );

export const computeUpdateIssuerAuthorizationPayloadHash = (
  authorizationId: Uint8Array,
  previousLifecycleEventHash: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.updateIssuerAuthorizationPayloadHash(
    require32Bytes(authorizationId, "Authorization id"),
    require32Bytes(previousLifecycleEventHash, "Previous lifecycle event hash"),
    require32Bytes(evidenceHash, "Evidence hash"),
  );

export const computeVerifierAuthorizationScopeKey = (
  subjectDidCommitment: Uint8Array,
  requestResourceId: Uint8Array,
  allowedAttributeSetCommitment: Uint8Array,
  allowedPredicateSetCommitment: Uint8Array,
  disclosureLevelCommitment: Uint8Array,
): Uint8Array =>
  pureCircuits.verifierAuthorizationScopeKey(
    require32Bytes(subjectDidCommitment, "Subject DID commitment"),
    require32Bytes(requestResourceId, "Request resource id"),
    require32Bytes(allowedAttributeSetCommitment, "Allowed attribute set commitment"),
    require32Bytes(allowedPredicateSetCommitment, "Allowed predicate set commitment"),
    require32Bytes(disclosureLevelCommitment, "Disclosure level commitment"),
  );

export const computeAuditorAuthorizationScopeKey = (
  subjectDidCommitment: Uint8Array,
  requestResourceId: Uint8Array,
  allowedAttributeSetCommitment: Uint8Array,
  allowedPredicateSetCommitment: Uint8Array,
  disclosureLevelCommitment: Uint8Array,
): Uint8Array =>
  pureCircuits.auditorAuthorizationScopeKey(
    require32Bytes(subjectDidCommitment, "Subject DID commitment"),
    require32Bytes(requestResourceId, "Request resource id"),
    require32Bytes(allowedAttributeSetCommitment, "Allowed attribute set commitment"),
    require32Bytes(allowedPredicateSetCommitment, "Allowed predicate set commitment"),
    require32Bytes(disclosureLevelCommitment, "Disclosure level commitment"),
  );

export const computeRecognitionScopeKey = (
  recognizedAuthorityDidCommitment: Uint8Array,
  recognizedRegistryId: Uint8Array,
  scopeResourceType: Uint8Array,
  scopeResourceId: Uint8Array,
): Uint8Array =>
  pureCircuits.recognitionScopeKey(
    require32Bytes(recognizedAuthorityDidCommitment, "Recognized authority DID commitment"),
    require32Bytes(recognizedRegistryId, "Recognized registry id"),
    require32Bytes(scopeResourceType, "Scope resource type"),
    require32Bytes(scopeResourceId, "Scope resource id"),
  );

export const computeCreateVerifierAuthorizationPayloadHash = (
  authorizationId: Uint8Array,
  subjectDidCommitment: Uint8Array,
  requestResourceId: Uint8Array,
  allowedAttributeSetCommitment: Uint8Array,
  allowedPredicateSetCommitment: Uint8Array,
  disclosureLevelCommitment: Uint8Array,
  policyId: Uint8Array,
  trustLevel: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.createVerifierAuthorizationPayloadHash(
    require32Bytes(authorizationId, "Authorization id"),
    require32Bytes(subjectDidCommitment, "Subject DID commitment"),
    require32Bytes(requestResourceId, "Request resource id"),
    require32Bytes(allowedAttributeSetCommitment, "Allowed attribute set commitment"),
    require32Bytes(allowedPredicateSetCommitment, "Allowed predicate set commitment"),
    require32Bytes(disclosureLevelCommitment, "Disclosure level commitment"),
    require32Bytes(policyId, "Policy id"),
    require32Bytes(trustLevel, "Trust level"),
    require32Bytes(evidenceHash, "Evidence hash"),
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
    require32Bytes(recognitionId, "Recognition id"),
    require32Bytes(recognizedAuthorityDidCommitment, "Recognized authority DID commitment"),
    require32Bytes(recognizedRegistryId, "Recognized registry id"),
    require32Bytes(scopeResourceType, "Scope resource type"),
    require32Bytes(scopeResourceId, "Scope resource id"),
    require32Bytes(policyId, "Policy id"),
    require32Bytes(trustLevel, "Trust level"),
    require32Bytes(evidenceHash, "Evidence hash"),
  );

export const computeCreateAuditorAuthorizationPayloadHash = (
  authorizationId: Uint8Array,
  subjectDidCommitment: Uint8Array,
  requestResourceId: Uint8Array,
  allowedAttributeSetCommitment: Uint8Array,
  allowedPredicateSetCommitment: Uint8Array,
  disclosureLevelCommitment: Uint8Array,
  policyId: Uint8Array,
  trustLevel: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.createAuditorAuthorizationPayloadHash(
    require32Bytes(authorizationId, "Authorization id"),
    require32Bytes(subjectDidCommitment, "Subject DID commitment"),
    require32Bytes(requestResourceId, "Request resource id"),
    require32Bytes(allowedAttributeSetCommitment, "Allowed attribute set commitment"),
    require32Bytes(allowedPredicateSetCommitment, "Allowed predicate set commitment"),
    require32Bytes(disclosureLevelCommitment, "Disclosure level commitment"),
    require32Bytes(policyId, "Policy id"),
    require32Bytes(trustLevel, "Trust level"),
    require32Bytes(evidenceHash, "Evidence hash"),
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
    require32Bytes(epochId, "Epoch id"),
    require32Bytes(stateRoot, "State root"),
    require32Bytes(eventRoot, "Event root"),
    require32Bytes(policyRoot, "Policy root"),
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
    require32Bytes(maintainerId, "Maintainer id"),
    require32Bytes(maintainerDidCommitment, "Maintainer DID commitment"),
    require32Bytes(keyId, "Key id"),
    publicKey,
    require32Bytes(policyId, "Policy id"),
    require32Bytes(trustLevel, "Trust level"),
    require32Bytes(evidenceHash, "Evidence hash"),
  );

export const computeUpdateVerifierAuthorizationPayloadHash = (
  authorizationId: Uint8Array,
  previousLifecycleEventHash: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.updateVerifierAuthorizationPayloadHash(
    require32Bytes(authorizationId, "Authorization id"),
    require32Bytes(previousLifecycleEventHash, "Previous lifecycle event hash"),
    require32Bytes(evidenceHash, "Evidence hash"),
  );

export const computeUpdateRecognitionPayloadHash = (
  recognitionId: Uint8Array,
  previousLifecycleEventHash: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.updateRecognitionPayloadHash(
    require32Bytes(recognitionId, "Recognition id"),
    require32Bytes(previousLifecycleEventHash, "Previous lifecycle event hash"),
    require32Bytes(evidenceHash, "Evidence hash"),
  );

export const computeUpdateAuditorAuthorizationPayloadHash = (
  authorizationId: Uint8Array,
  previousLifecycleEventHash: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.updateAuditorAuthorizationPayloadHash(
    require32Bytes(authorizationId, "Authorization id"),
    require32Bytes(previousLifecycleEventHash, "Previous lifecycle event hash"),
    require32Bytes(evidenceHash, "Evidence hash"),
  );

export const computeUpdateMaintainerMembershipPayloadHash = (
  maintainerId: Uint8Array,
  previousLifecycleEventHash: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.updateMaintainerMembershipPayloadHash(
    require32Bytes(maintainerId, "Maintainer id"),
    require32Bytes(previousLifecycleEventHash, "Previous lifecycle event hash"),
    require32Bytes(evidenceHash, "Evidence hash"),
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
    require32Bytes(previousPolicyCommitment, "Previous policy commitment"),
    require32Bytes(nextPolicyCommitment, "Next policy commitment"),
    nextPolicyVersion,
    defaultThreshold,
    emergencyThreshold,
    archivalThreshold,
  );

const signMaintainerActionDigestFromSeed = (
  seedBytes: Uint8Array,
  digest: TrustRegistryActionDigest,
): TrustRegistryJubjubSignature =>
  signJubjubDigestFromSeed(require32Bytes(seedBytes, "Maintainer seed"), digest);

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
  if (!isNonIdentityJubjubPoint(publicKey) || !isCanonicalJubjubSignature(signature)) return false;
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
