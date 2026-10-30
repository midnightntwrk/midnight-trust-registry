import { ecAdd, ecMul, type JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import {
  compareMaintainerKeyIds,
  computeCreateEpochCommitmentPayloadHash,
  decodeCanonicalJubjubSignatureHex,
  encodeCompactActionKind,
  JUBJUB_ORDER,
  pureCircuits,
  verifyDeploymentBoundMaintainerAction,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  AcceptedDecisionEpochSchema,
  DecisionEvidenceEpochSchema,
} from "@midnight-ntwrk/trust-registry-domain";

import { bytes32Commitment, bytes32Hex, hashHexToBytes32, sameBytes32 } from "./utils.js";

const PUBLISH = encodeCompactActionKind("tr:epoch:publish");
const ZERO = new Uint8Array(32);
const HASH = /^0x[0-9a-f]{64}$/u;

export type ActivePublicationMaintainer = {
  keyId: string;
  keyIdCommitment: Uint8Array;
  publicKey: JubjubPoint;
};

const requireBytes32 = (value: Uint8Array, name: string): void => {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error(`${name} must be bytes32`);
  }
};

const requirePrimeOrderKey = (key: JubjubPoint): void => {
  try {
    if (key.x === 0n && key.y === 1n) throw new Error();
    const check = ecAdd(ecMul(key, JUBJUB_ORDER - 1n), key);
    if (check.x === 0n && check.y === 1n) return;
  } catch {
    // Invalid and low-order points fail closed just like the Compact key guard.
  }
  throw new Error("Publication maintainer key must have prime order");
};

/** Verifies signed epoch preimages against caller-authenticated publication and active-key context. */
export const assertDecisionEpochPublicationSignatures = (
  epochInput: unknown,
  publicationEventHash: string,
  acceptedInput: unknown,
  context: {
    registryIdCommitment: Uint8Array;
    networkIdCommitment: Uint8Array;
    contractAddress: Uint8Array;
    epochIdCommitment: Uint8Array;
    firstSignerKeyIdCommitment: Uint8Array;
    activeMaintainersAtPublication: readonly ActivePublicationMaintainer[];
  },
): void => {
  const epoch = DecisionEvidenceEpochSchema.parse(epochInput);
  const accepted = AcceptedDecisionEpochSchema.parse(acceptedInput);
  if (!HASH.test(publicationEventHash) || publicationEventHash !== accepted.publicationEventHash) {
    throw new Error("Epoch publication event is not accepted");
  }
  for (const [name, value] of [
    ["Registry id commitment", context.registryIdCommitment],
    ["Network id commitment", context.networkIdCommitment],
    ["Contract address", context.contractAddress],
    ["Epoch id commitment", context.epochIdCommitment],
    ["First signer key commitment", context.firstSignerKeyIdCommitment],
  ] as const) requireBytes32(value, name);
  if (context.networkIdCommitment.every((byte) => byte === 0)
    || context.contractAddress.every((byte) => byte === 0)) {
    throw new Error("Epoch publication deployment context must be nonzero");
  }
  if (!sameBytes32(context.networkIdCommitment, bytes32Commitment(accepted.networkId))
    || !sameBytes32(context.contractAddress, hashHexToBytes32(accepted.contractAddress))) {
    throw new Error("Epoch publication deployment context does not match the accepted record");
  }
  if (
    !sameBytes32(context.registryIdCommitment, bytes32Commitment(accepted.registryId))
    || !sameBytes32(context.epochIdCommitment, bytes32Commitment(accepted.epochId))
    || epoch.registryId !== accepted.registryId
    || epoch.epochId !== accepted.epochId
    || epoch.stateRoot !== accepted.stateRoot
    || epoch.eventRoot !== accepted.eventRoot
    || epoch.policyRoot !== accepted.policyRoot
    || epoch.publicationPolicyCommitment !== accepted.publicationPolicyCommitment
    || epoch.publicationSequence !== accepted.publicationSequence
    || epoch.validFromSequence !== accepted.validFromSequence
    || epoch.validUntilSequence !== accepted.validUntilSequence
    || epoch.validFrom !== accepted.validFrom
    || epoch.validUntil !== accepted.validUntil
    || epoch.quorum.requiredSignatures !== accepted.requiredSignatures
  ) {
    throw new Error("Epoch publication preimage does not match the accepted record");
  }
  if (
    BigInt(epoch.validFromSequence) > BigInt(epoch.publicationSequence)
    || BigInt(epoch.validUntilSequence) <= BigInt(epoch.validFromSequence)
    || epoch.quorum.signatures.length < accepted.requiredSignatures
  ) {
    throw new Error("Epoch publication quorum or sequence window is invalid");
  }
  const payload = computeCreateEpochCommitmentPayloadHash(
    context.epochIdCommitment,
    hashHexToBytes32(epoch.stateRoot),
    hashHexToBytes32(epoch.eventRoot),
    hashHexToBytes32(epoch.policyRoot),
    BigInt(epoch.validFromSequence),
    BigInt(epoch.validUntilSequence),
  );
  const policyCommitment = hashHexToBytes32(epoch.publicationPolicyCommitment);
  const active = new Map(context.activeMaintainersAtPublication.map((key) => [key.keyId, key]));
  if (active.size !== context.activeMaintainersAtPublication.length) {
    throw new Error("Publication maintainer context has duplicate keys");
  }
  const seen = new Set<string>();
  const signerKeyIds: Uint8Array[] = [];
  for (const signer of epoch.quorum.signatures) {
    const authorized = active.get(signer.keyId);
    if (authorized === undefined || seen.has(signer.keyId)) {
      throw new Error("Epoch publication signer is not a distinct active maintainer");
    }
    seen.add(signer.keyId);
    requireBytes32(authorized.keyIdCommitment, "Maintainer key commitment");
    if (!sameBytes32(authorized.keyIdCommitment, bytes32Commitment(signer.keyId))) {
      throw new Error("Epoch publication signer DID method does not match its ledger key commitment");
    }
    if (signerKeyIds.length > 0
      && compareMaintainerKeyIds(signerKeyIds[signerKeyIds.length - 1]!, authorized.keyIdCommitment) >= 0) {
      throw new Error("Epoch publication signer keys must be sorted");
    }
    signerKeyIds.push(authorized.keyIdCommitment);
  }
  if (!sameBytes32(signerKeyIds[0]!, context.firstSignerKeyIdCommitment)) {
    throw new Error("Epoch publication first signer does not match the accepted record");
  }
  const [first, second = ZERO, third = ZERO, fourth = ZERO, fifth = ZERO] = signerKeyIds;
  const signerSetHash = pureCircuits.maintainerSignerSetHash(
    BigInt(signerKeyIds.length), first!, second, third, fourth, fifth,
  );
  const computedEventHash = pureCircuits.governanceEventHash(
    context.registryIdCommitment,
    context.networkIdCommitment,
    context.contractAddress,
    policyCommitment,
    signerSetHash,
    PUBLISH,
    payload,
    BigInt(epoch.publicationSequence),
  );
  if (bytes32Hex(computedEventHash) !== publicationEventHash) {
    throw new Error("Epoch publication signer set does not match the accepted event");
  }
  for (const signer of epoch.quorum.signatures) {
    const publicKey = active.get(signer.keyId)!.publicKey;
    requirePrimeOrderKey(publicKey);
    const signature = decodeCanonicalJubjubSignatureHex(signer.signature);
    if (!verifyDeploymentBoundMaintainerAction(
      publicKey,
      context.registryIdCommitment,
      context.networkIdCommitment,
      context.contractAddress,
      policyCommitment,
      PUBLISH,
      payload,
      BigInt(epoch.publicationSequence),
      signature,
    )) {
      throw new Error("Epoch publication maintainer signature is invalid");
    }
  }
};
