import {
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
  signJubjubDigest,
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

const ensure32Bytes = (value: Uint8Array): Buffer => {
  const buffer = Buffer.from(value);
  if (buffer.length === 32) return buffer;
  if (buffer.length > 32) return buffer.subarray(0, 32);
  return Buffer.concat([buffer, Buffer.alloc(32 - buffer.length)]);
};

export const computeMaintainerActionDigest = (
  registryId: Uint8Array,
  actionKind: Uint8Array,
  actionPayloadHash: Uint8Array,
  actionSequence: bigint,
): TrustRegistryActionDigest =>
  pureCircuits.maintainerActionDigest(
    ensure32Bytes(registryId),
    ensure32Bytes(actionKind),
    ensure32Bytes(actionPayloadHash),
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
  trustLevel: Uint8Array,
  evidenceHash: Uint8Array,
): Uint8Array =>
  pureCircuits.createIssuerAuthorizationPayloadHash(
    ensure32Bytes(authorizationId),
    ensure32Bytes(subjectDidCommitment),
    resourceType,
    ensure32Bytes(resourceId),
    ensure32Bytes(policyId),
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

export const signMaintainerActionDigest = (
  secretScalar: bigint,
  digest: TrustRegistryActionDigest,
  nonceSeed?: Uint8Array,
): TrustRegistryJubjubSignature => signJubjubDigest(secretScalar, digest, nonceSeed);

export const signMaintainerActionDigestFromSeed = (
  seedBytes: Uint8Array,
  digest: TrustRegistryActionDigest,
): TrustRegistryJubjubSignature =>
  signJubjubDigestFromSeed(ensure32Bytes(seedBytes), digest);

export const signMaintainerActionFromSeed = (
  seedBytes: Uint8Array,
  registryId: Uint8Array,
  actionKind: Uint8Array,
  actionPayloadHash: Uint8Array,
  actionSequence: bigint,
): TrustRegistryJubjubSignature =>
  signMaintainerActionDigestFromSeed(
    seedBytes,
    computeMaintainerActionDigest(
      registryId,
      actionKind,
      actionPayloadHash,
      actionSequence,
    ),
  );

export const verifyMaintainerActionDigest = (
  publicKey: JubjubPoint,
  digest: TrustRegistryActionDigest,
  signature: TrustRegistryJubjubSignature,
): boolean => verifyJubjubDigest(publicKey, digest, signature);

export const verifyMaintainerAction = (
  publicKey: JubjubPoint,
  registryId: Uint8Array,
  actionKind: Uint8Array,
  actionPayloadHash: Uint8Array,
  actionSequence: bigint,
  signature: TrustRegistryJubjubSignature,
): boolean =>
  verifyMaintainerActionDigest(
    publicKey,
    computeMaintainerActionDigest(
      registryId,
      actionKind,
      actionPayloadHash,
      actionSequence,
    ),
    signature,
  );
