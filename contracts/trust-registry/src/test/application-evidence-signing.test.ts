import { createHash } from "node:crypto";

import { ecMulGenerator } from "@midnight-ntwrk/compact-runtime";
import { payloadToJubjubDigest, verifyJubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { describe, expect, it } from "vitest";

import {
  applicationEvidenceSignatureDigest,
  computeDeploymentBoundMaintainerActionDigest,
  computeVerifierEvidenceBoundProposalPayloadHash,
  computeUpdateIssuerAuthorizationPayloadHash,
  decodeCanonicalJubjubSignatureHex,
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  JUBJUB_ORDER,
  signApplicationEvidenceCommitmentFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
  signVerifierProposalEvidenceFromSeed,
  verifyApplicationEvidenceCommitmentSignature,
  verifyAuditorProposalEvidenceSignature,
  verifyDeploymentBoundMaintainerAction,
  verifyIssuerProposalEvidenceSignature,
  verifyMaintainerProposalEvidenceSignature,
  verifyRecognitionProposalEvidenceSignature,
  verifyVerifierProposalEvidenceSignature,
} from "../signing.js";

const seed = new Uint8Array(32).fill(41);
const commitment = Uint8Array.from({ length: 32 }, (_, index) => index);
const keyIdCommitment = new Uint8Array(32).fill(7);

describe("application evidence commitment signing", () => {
  it("separates governed signatures across deployments and networks", () => {
    const registryId = new Uint8Array(32).fill(1);
    const network = new Uint8Array(32).fill(2);
    const address = new Uint8Array(32).fill(3);
    const policy = new Uint8Array(32).fill(4);
    const action = new Uint8Array(32).fill(5);
    const payload = new Uint8Array(32).fill(6);
    const publicKey = deriveJubjubPublicKeyFromSeed(seed);
    const signature = signDeploymentBoundMaintainerActionFromSeed(
      seed, registryId, network, address, policy, action, payload, 7n,
    );
    const verify = (targetNetwork: Uint8Array, targetAddress: Uint8Array) =>
      verifyDeploymentBoundMaintainerAction(
        publicKey, registryId, targetNetwork, targetAddress, policy, action, payload, 7n, signature,
      );

    expect(verify(network, address)).toBe(true);
    expect(verify(new Uint8Array(32).fill(8), address)).toBe(false);
    expect(verify(network, new Uint8Array(32).fill(9))).toBe(false);
    expect(computeDeploymentBoundMaintainerActionDigest(
      registryId, network, address, policy, action, payload, 7n,
    )).toHaveLength(4);
    expect(() => signDeploymentBoundMaintainerActionFromSeed(
      seed, registryId, network, new Uint8Array(31), policy, action, payload, 7n,
    )).toThrow(/Contract address must be 32 bytes/);
    expect(() => signDeploymentBoundMaintainerActionFromSeed(
      seed, registryId, new Uint8Array(32), address, policy, action, payload, 7n,
    )).toThrow(/Network id commitment must be set/);
  });

  it("separates the evidence domain from a raw DID payload and binds the key id", () => {
    const payload = new TextEncoder().encode('{"applicationId":"example"}');
    const payloadCommitment = createHash("sha256").update(payload).digest();
    const digest = applicationEvidenceSignatureDigest(keyIdCommitment, payloadCommitment);

    expect(digest).toHaveLength(4);
    expect(digest).not.toEqual(payloadToJubjubDigest(payload));
    expect(digest).not.toEqual(applicationEvidenceSignatureDigest(
      new Uint8Array(32).fill(8),
      payloadCommitment,
    ));
  });

  it("verifies only the signed commitment under the matching verifier key", () => {
    const signature = signApplicationEvidenceCommitmentFromSeed(seed, keyIdCommitment, commitment);
    const publicKey = deriveJubjubPublicKeyFromSeed(seed);

    expect(verifyApplicationEvidenceCommitmentSignature(publicKey, keyIdCommitment, commitment, signature)).toBe(true);
    expect(verifyApplicationEvidenceCommitmentSignature(
      publicKey,
      keyIdCommitment,
      new Uint8Array(32).fill(2),
      signature,
    )).toBe(false);
    expect(verifyApplicationEvidenceCommitmentSignature(
      deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(42)),
      keyIdCommitment,
      commitment,
      signature,
    )).toBe(false);
    expect(verifyApplicationEvidenceCommitmentSignature(
      publicKey,
      new Uint8Array(32).fill(8),
      commitment,
      signature,
    )).toBe(false);
    expect(verifyApplicationEvidenceCommitmentSignature(
      publicKey,
      keyIdCommitment,
      commitment,
      { ...signature, response: signature.response + JUBJUB_ORDER },
    )).toBe(false);
    expect(verifyApplicationEvidenceCommitmentSignature(
      publicKey,
      keyIdCommitment,
      commitment,
      { announcement: { x: 3n, y: 5n }, response: 12345n },
    )).toBe(false);
  });

  it("binds verifier proposal evidence to its policy, payload, key, and role", () => {
    const registryId = new Uint8Array(32).fill(1);
    const authorizationId = new Uint8Array(32).fill(2);
    const policyCommitment = new Uint8Array(32).fill(3);
    const basePayloadHash = new Uint8Array(32).fill(4);
    const bound = computeVerifierEvidenceBoundProposalPayloadHash(
      basePayloadHash, authorizationId, keyIdCommitment, policyCommitment, 1n,
    );
    const signature = signVerifierProposalEvidenceFromSeed(seed, registryId, keyIdCommitment, bound);
    const publicKey = deriveJubjubPublicKeyFromSeed(seed);
    expect(verifyVerifierProposalEvidenceSignature(publicKey, registryId, keyIdCommitment, bound, signature)).toBe(true);
    expect(verifyVerifierProposalEvidenceSignature(publicKey, registryId, keyIdCommitment,
      computeVerifierEvidenceBoundProposalPayloadHash(
        new Uint8Array(32).fill(5), authorizationId, keyIdCommitment, policyCommitment, 1n,
      ), signature)).toBe(false);
    expect(verifyVerifierProposalEvidenceSignature(publicKey, registryId, keyIdCommitment,
      computeVerifierEvidenceBoundProposalPayloadHash(
        basePayloadHash, authorizationId, keyIdCommitment, policyCommitment, 2n,
      ), signature)).toBe(false);
    expect(verifyVerifierProposalEvidenceSignature(publicKey, new Uint8Array(32).fill(9),
      keyIdCommitment, bound, signature)).toBe(false);
    expect(verifyVerifierProposalEvidenceSignature(publicKey, registryId,
      new Uint8Array(32).fill(8), bound, signature)).toBe(false);
    expect(verifyIssuerProposalEvidenceSignature(publicKey, registryId, keyIdCommitment, bound, signature)).toBe(false);
    expect(verifyVerifierProposalEvidenceSignature(publicKey, registryId, keyIdCommitment,
      bound, { ...signature, response: signature.response + JUBJUB_ORDER })).toBe(false);
  });

  it("rejects ambiguous commitment and seed lengths", () => {
    expect(() => applicationEvidenceSignatureDigest(new Uint8Array(31), commitment)).toThrow(/32 bytes/);
    expect(() => applicationEvidenceSignatureDigest(new Uint8Array(33), commitment)).toThrow(/32 bytes/);
    expect(() => applicationEvidenceSignatureDigest(keyIdCommitment, new Uint8Array(31))).toThrow(/32 bytes/);
    expect(() => signApplicationEvidenceCommitmentFromSeed(new Uint8Array(31), keyIdCommitment, commitment)).toThrow(/32 bytes/);
    expect(() => computeUpdateIssuerAuthorizationPayloadHash(
      keyIdCommitment,
      commitment,
      new Uint8Array(31),
    )).toThrow(/Evidence hash must be 32 bytes/);
    expect(() => computeUpdateIssuerAuthorizationPayloadHash(
      keyIdCommitment,
      commitment,
      new Uint8Array(33),
    )).toThrow(/Evidence hash must be 32 bytes/);
    expect(() => signDeploymentBoundMaintainerActionFromSeed(
      new Uint8Array(31),
      keyIdCommitment,
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      keyIdCommitment,
      keyIdCommitment,
      commitment,
      1n,
    )).toThrow(/Maintainer seed must be 32 bytes/);
  });

  it("rejects noncanonical wire encodings before decoding a signature", () => {
    const signature = signApplicationEvidenceCommitmentFromSeed(seed, keyIdCommitment, commitment);
    const encoded = `0x${Buffer.from(encodeJubjubSignature(signature)).toString("hex")}`;

    expect(decodeCanonicalJubjubSignatureHex(encoded)).toEqual(signature);
    expect(() => decodeCanonicalJubjubSignatureHex(null as unknown as string)).toThrow(/encoding is invalid/);
    for (const malformed of [
      encoded.slice(0, -1),
      encoded.toUpperCase(),
      `${encoded.slice(0, -1)}g`,
      encoded.slice(2),
    ]) {
      expect(() => decodeCanonicalJubjubSignatureHex(malformed)).toThrow(/encoding is invalid/);
    }
    const highResponse = `0x${Buffer.from(encodeJubjubSignature({
      ...signature,
      response: signature.response + JUBJUB_ORDER,
    })).toString("hex")}`;
    expect(() => decodeCanonicalJubjubSignatureHex(highResponse)).toThrow(/encoding is invalid/);
    const offCurve = `0x${Buffer.from(encodeJubjubSignature({
      announcement: { x: 3n, y: 5n },
      response: signature.response,
    })).toString("hex")}`;
    expect(() => decodeCanonicalJubjubSignatureHex(offCurve)).toThrow(/encoding is invalid/);
    const identityAnnouncement = `0x${Buffer.from(encodeJubjubSignature({
      announcement: { x: 0n, y: 1n },
      response: signature.response,
    })).toString("hex")}`;
    expect(() => decodeCanonicalJubjubSignatureHex(identityAnnouncement)).toThrow(/encoding is invalid/);
    const lowOrderAnnouncement = `0x${Buffer.from(encodeJubjubSignature({
      announcement: {
        x: 0n,
        y: 52435875175126190479447740508185965837690552500527637822603658699938581184512n,
      },
      response: signature.response,
    })).toString("hex")}`;
    expect(() => decodeCanonicalJubjubSignatureHex(lowOrderAnnouncement)).toThrow(/encoding is invalid/);
  });

  it("fails closed for malformed structured maintainer signatures", () => {
    const registryId = new Uint8Array(32).fill(1);
    const network = new Uint8Array(32).fill(5);
    const address = new Uint8Array(32).fill(6);
    const policyCommitment = new Uint8Array(32).fill(2);
    const actionKind = new Uint8Array(32).fill(3);
    const payloadHash = new Uint8Array(32).fill(4);
    const signature = signDeploymentBoundMaintainerActionFromSeed(
      seed, registryId, network, address, policyCommitment, actionKind, payloadHash, 1n,
    );
    const publicKey = deriveJubjubPublicKeyFromSeed(seed);
    const verify = (candidate: typeof signature) => verifyDeploymentBoundMaintainerAction(
      publicKey, registryId, network, address, policyCommitment, actionKind, payloadHash, 1n, candidate,
    );

    expect(verify(signature)).toBe(true);
    expect(verify({ ...signature, response: signature.response + JUBJUB_ORDER })).toBe(false);
    expect(verify({ announcement: { x: 3n, y: 5n }, response: signature.response })).toBe(false);
    expect(verify({ announcement: { x: 0n, y: 1n }, response: signature.response })).toBe(false);
    expect(verifyDeploymentBoundMaintainerAction(
      { x: 0n, y: 1n }, registryId, network, address,
      policyCommitment, actionKind, payloadHash, 1n, signature,
    )).toBe(false);
    expect(verifyApplicationEvidenceCommitmentSignature(
      { x: 0n, y: 1n }, keyIdCommitment, commitment,
      signApplicationEvidenceCommitmentFromSeed(seed, keyIdCommitment, commitment),
    )).toBe(false);
    expect(verify(null as unknown as typeof signature)).toBe(false);
  });

  it("rejects a forged identity-key signature that passes the raw Schnorr equation", () => {
    const identity = { x: 0n, y: 1n };
    const forged = { announcement: ecMulGenerator(1n), response: 1n };
    const digest = applicationEvidenceSignatureDigest(keyIdCommitment, commitment);

    expect(verifyJubjubDigest(identity, digest, forged)).toBe(true);
    expect(verifyApplicationEvidenceCommitmentSignature(
      identity, keyIdCommitment, commitment, forged,
    )).toBe(false);
    const registryId = new Uint8Array(32).fill(1);
    const lowOrder = {
      x: 0n,
      y: 52435875175126190479447740508185965837690552500527637822603658699938581184512n,
    };
    for (const verify of [
      verifyIssuerProposalEvidenceSignature,
      verifyVerifierProposalEvidenceSignature,
      verifyAuditorProposalEvidenceSignature,
      verifyMaintainerProposalEvidenceSignature,
      verifyRecognitionProposalEvidenceSignature,
    ]) {
      expect(verify(identity, registryId, keyIdCommitment, commitment, forged)).toBe(false);
      expect(verify(lowOrder, registryId, keyIdCommitment, commitment, forged)).toBe(false);
      expect(verify({ x: 3n, y: 5n }, registryId, keyIdCommitment, commitment, forged)).toBe(false);
    }
  });
});
