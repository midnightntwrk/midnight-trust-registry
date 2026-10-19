import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";
import {
  compareMaintainerKeyIds,
  computeCreateEpochCommitmentPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
  encodeJubjubSignature,
  pureCircuits,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";

import { assertDecisionEpochPublicationSignatures } from "../decision-epoch-signatures.js";
import { bytes32Commitment, bytes32Hex, hashHexToBytes32 } from "../utils.js";

const A = `0x${"a".repeat(64)}`;
const B = `0x${"b".repeat(64)}`;
const C = `0x${"c".repeat(64)}`;
const E = `0x${"e".repeat(64)}`;
const REGISTRY = "registry:midnight:university";
const EPOCH = "epoch:0001";
const DID1 = `did:midnight:devnet:${"1".repeat(64)}`;
const DID2 = `did:midnight:devnet:${"2".repeat(64)}`;
const PUBLISH = encodeCompactActionKind("tr:epoch:publish");
const signatureHex = (value: ReturnType<typeof signDeploymentBoundMaintainerActionFromSeed>) =>
  `0x${Buffer.from(encodeJubjubSignature(value)).toString("hex")}`;

function fixture() {
  const registryIdCommitment = bytes32Commitment(REGISTRY);
  const networkIdCommitment = bytes32Commitment("devnet");
  const contractAddress = hashHexToBytes32(A);
  const epochIdCommitment = bytes32Commitment(EPOCH);
  const policyCommitment = hashHexToBytes32(E);
  const keys = [
    { keyId: `${DID1}#key-1`, seed: new Uint8Array(32).fill(13) },
    { keyId: `${DID2}#key-1`, seed: new Uint8Array(32).fill(17) },
  ].sort((left, right) => compareMaintainerKeyIds(
    bytes32Commitment(left.keyId), bytes32Commitment(right.keyId),
  ));
  const activeMaintainersAtPublication = keys.map(({ keyId, seed }) => ({
    keyId,
    keyIdCommitment: bytes32Commitment(keyId),
    publicKey: deriveJubjubPublicKeyFromSeed(seed),
  }));
  const payload = computeCreateEpochCommitmentPayloadHash(
    epochIdCommitment,
    hashHexToBytes32(A),
    hashHexToBytes32(B),
    hashHexToBytes32(C),
    10n,
    20n,
  );
  const signatures = keys.map(({ keyId, seed }) => ({
    keyId,
    algorithm: "jubjub-schnorr" as const,
    signature: signatureHex(signDeploymentBoundMaintainerActionFromSeed(
      seed, registryIdCommitment, networkIdCommitment, contractAddress,
      policyCommitment, PUBLISH, payload, 10n,
    )),
  }));
  const signerSetHash = pureCircuits.maintainerSignerSetHash(
    2n,
    activeMaintainersAtPublication[0]!.keyIdCommitment,
    activeMaintainersAtPublication[1]!.keyIdCommitment,
    new Uint8Array(32), new Uint8Array(32), new Uint8Array(32),
  );
  const publicationEventHash = bytes32Hex(pureCircuits.governanceEventHash(
    registryIdCommitment, bytes32Commitment("devnet"), hashHexToBytes32(A),
    policyCommitment, signerSetHash, PUBLISH, payload, 10n,
  ));
  const epoch = {
    epochId: EPOCH,
    registryId: REGISTRY,
    stateRoot: A,
    eventRoot: B,
    policyRoot: C,
    publicationPolicyCommitment: E,
    publicationSequence: "10",
    validFromSequence: "10",
    validUntilSequence: "20",
    validFrom: "2026-05-20T02:00:00Z",
    validUntil: "2026-05-20T03:00:00Z",
    quorum: { requiredSignatures: 2, signatures },
  };
  const accepted = {
    registryId: REGISTRY,
    registryDid: `did:midnight:devnet:${"3".repeat(64)}`,
    networkId: "devnet",
    contractAddress: A,
    transactionHash: B,
    blockHash: C,
    epochId: EPOCH,
    stateRoot: A,
    eventRoot: B,
    policyRoot: C,
    publicationPolicyCommitment: E,
    publicationSequence: "10",
    validFromSequence: "10",
    validUntilSequence: "20",
    publicationEventHash,
    validFrom: epoch.validFrom,
    validUntil: epoch.validUntil,
    requiredSignatures: 2,
  };
  const context = {
    registryIdCommitment,
    networkIdCommitment,
    contractAddress,
    epochIdCommitment,
    firstSignerKeyIdCommitment: activeMaintainersAtPublication[0]!.keyIdCommitment,
    activeMaintainersAtPublication,
  };
  return { epoch, accepted, context, payload, publicationEventHash };
}

describe("decision epoch publication signatures", () => {
  it("verifies the complete two-signer set and anchored Compact event", () => {
    const { epoch, accepted, context, publicationEventHash } = fixture();
    expect(() => assertDecisionEpochPublicationSignatures(
      epoch, publicationEventHash, accepted, context,
    )).not.toThrow();
  });

  it("rejects a publication signed for another deployment", () => {
    const { epoch, accepted, context, payload, publicationEventHash } = fixture();
    expect(() => assertDecisionEpochPublicationSignatures(epoch, publicationEventHash, accepted, {
      ...context, networkIdCommitment: bytes32Commitment("mainnet"),
    })).toThrow(/deployment context does not match/u);
    expect(() => assertDecisionEpochPublicationSignatures(epoch, publicationEventHash, accepted, {
      ...context, contractAddress: hashHexToBytes32(B),
    })).toThrow(/deployment context does not match/u);
    const otherDeploymentSignature = signatureHex(signDeploymentBoundMaintainerActionFromSeed(
      new Uint8Array(32).fill(13), context.registryIdCommitment,
      bytes32Commitment("mainnet"), context.contractAddress,
      hashHexToBytes32(E), PUBLISH, payload, 10n,
    ));
    expect(() => assertDecisionEpochPublicationSignatures({
      ...epoch,
      quorum: { ...epoch.quorum, signatures: [
        { ...epoch.quorum.signatures[0]!, signature: otherDeploymentSignature },
        epoch.quorum.signatures[1]!,
      ] },
    }, publicationEventHash, accepted, context)).toThrow(/maintainer signature is invalid/u);
  });

  it("rejects bad signatures, repeated or missing signers, and unsafe keys", () => {
    const { epoch, accepted, context, publicationEventHash } = fixture();
    const signature = epoch.quorum.signatures[1]!.signature;
    const tampered = `${signature.slice(0, -1)}${signature.endsWith("0") ? "1" : "0"}`;
    expect(() => assertDecisionEpochPublicationSignatures({
      ...epoch, quorum: { ...epoch.quorum, signatures: [epoch.quorum.signatures[0], { ...epoch.quorum.signatures[1], signature: tampered }] },
    }, publicationEventHash, accepted, context)).toThrow();
    expect(() => assertDecisionEpochPublicationSignatures({
      ...epoch, quorum: { ...epoch.quorum, signatures: [epoch.quorum.signatures[0], epoch.quorum.signatures[0]] },
    }, publicationEventHash, accepted, context)).toThrow(/distinct active maintainer/u);
    expect(() => assertDecisionEpochPublicationSignatures(epoch, publicationEventHash, accepted, {
      ...context, activeMaintainersAtPublication: context.activeMaintainersAtPublication.slice(0, 1),
    })).toThrow(/distinct active maintainer/u);
    expect(() => assertDecisionEpochPublicationSignatures(epoch, publicationEventHash, accepted, {
      ...context, activeMaintainersAtPublication: [
        { ...context.activeMaintainersAtPublication[0]!, keyIdCommitment: bytes32Commitment(`${DID1}#substituted`) },
        context.activeMaintainersAtPublication[1]!,
      ],
    })).toThrow(/DID method does not match/u);
    expect(() => assertDecisionEpochPublicationSignatures(epoch, publicationEventHash, accepted, {
      ...context, activeMaintainersAtPublication: [
        { ...context.activeMaintainersAtPublication[0]!, publicKey: { x: 0n, y: 1n } },
        context.activeMaintainersAtPublication[1]!,
      ],
    })).toThrow(/prime order/u);
    expect(() => assertDecisionEpochPublicationSignatures(epoch, publicationEventHash, accepted, {
      ...context, activeMaintainersAtPublication: [
        { ...context.activeMaintainersAtPublication[0]!, publicKey: {
          x: 0n,
          y: 52435875175126190479447740508185965837690552500527637822603658699938581184512n,
        } },
        context.activeMaintainersAtPublication[1]!,
      ],
    })).toThrow(/prime order/u);
  });

  it("rejects a reordered quorum even when every signature is valid", () => {
    const { epoch, accepted, context, publicationEventHash } = fixture();
    expect(() => assertDecisionEpochPublicationSignatures({
      ...epoch,
      quorum: { ...epoch.quorum, signatures: [...epoch.quorum.signatures].reverse() },
    }, publicationEventHash, accepted, {
      ...context,
      firstSignerKeyIdCommitment: context.activeMaintainersAtPublication[1]!.keyIdCommitment,
    })).toThrow(/signer keys must be sorted/u);
  });

  it("rejects noncanonical signer IDs before decoding or verifying signatures", () => {
    const { epoch, accepted, context, publicationEventHash } = fixture();
    const reversed = [...epoch.quorum.signatures].reverse();
    const invalidEncoding = `0x${"0".repeat(reversed[0]!.signature.length - 2)}`;
    reversed[0] = { ...reversed[0]!, signature: invalidEncoding };
    expect(() => assertDecisionEpochPublicationSignatures({
      ...epoch, quorum: { ...epoch.quorum, signatures: reversed },
    }, publicationEventHash, accepted, context)).toThrow(/signer keys must be sorted/u);

    const repeated = { ...epoch.quorum.signatures[0]!, signature: invalidEncoding };
    expect(() => assertDecisionEpochPublicationSignatures({
      ...epoch, quorum: { ...epoch.quorum, signatures: [repeated, repeated] },
    }, publicationEventHash, accepted, context)).toThrow(/distinct active maintainer/u);
  });

  it("checks first-signer and accepted event commitments before Schnorr verification", () => {
    const { epoch, accepted, context, publicationEventHash } = fixture();
    const signatures = epoch.quorum.signatures.map((signer) => ({
      ...signer, signature: `0x${"0".repeat(signer.signature.length - 2)}`,
    }));
    const invalid = { ...epoch, quorum: { ...epoch.quorum, signatures } };
    expect(() => assertDecisionEpochPublicationSignatures(invalid, publicationEventHash, accepted, {
      ...context,
      firstSignerKeyIdCommitment: context.activeMaintainersAtPublication[1]!.keyIdCommitment,
    })).toThrow(/first signer/u);
    expect(() => assertDecisionEpochPublicationSignatures(invalid, A, {
      ...accepted, publicationEventHash: A,
    }, context)).toThrow(/signer set does not match the accepted event/u);
    expect(() => assertDecisionEpochPublicationSignatures(
      invalid, publicationEventHash, accepted, context,
    )).toThrow(/signature encoding is invalid/u);
  });

  it("rejects changed publication preimages, threshold, first signer, and event", () => {
    const { epoch, accepted, context, publicationEventHash } = fixture();
    for (const changed of [
      { stateRoot: B },
      { publicationPolicyCommitment: A },
      { publicationSequence: "11" },
      { validUntilSequence: "21" },
    ]) {
      expect(() => assertDecisionEpochPublicationSignatures(
        { ...epoch, ...changed }, publicationEventHash, accepted, context,
      )).toThrow(/accepted record/u);
    }
    expect(() => assertDecisionEpochPublicationSignatures(
      { ...epoch, quorum: { ...epoch.quorum, requiredSignatures: 3 } },
      publicationEventHash, { ...accepted, requiredSignatures: 3 }, context,
    )).toThrow(/quorum/u);
    expect(() => assertDecisionEpochPublicationSignatures(epoch, publicationEventHash, accepted, {
      ...context, firstSignerKeyIdCommitment: context.activeMaintainersAtPublication[1]!.keyIdCommitment,
    })).toThrow(/first signer/u);
    expect(() => assertDecisionEpochPublicationSignatures(epoch, A, {
      ...accepted, publicationEventHash: A,
    }, context)).toThrow(/accepted event/u);
  });
});
