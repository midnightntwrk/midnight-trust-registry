import { createHash } from "node:crypto";

import { payloadToJubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { describe, expect, it } from "vitest";

import {
  applicationEvidenceSignatureDigest,
  deriveJubjubPublicKeyFromSeed,
  JUBJUB_ORDER,
  signApplicationEvidenceCommitmentFromSeed,
  verifyApplicationEvidenceCommitmentSignature,
} from "../signing.js";

const seed = new Uint8Array(32).fill(41);
const commitment = Uint8Array.from({ length: 32 }, (_, index) => index);
const keyIdCommitment = new Uint8Array(32).fill(7);

describe("application evidence commitment signing", () => {
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

  it("rejects ambiguous commitment and seed lengths", () => {
    expect(() => applicationEvidenceSignatureDigest(new Uint8Array(31), commitment)).toThrow(/32 bytes/);
    expect(() => applicationEvidenceSignatureDigest(new Uint8Array(33), commitment)).toThrow(/32 bytes/);
    expect(() => applicationEvidenceSignatureDigest(keyIdCommitment, new Uint8Array(31))).toThrow(/32 bytes/);
    expect(() => signApplicationEvidenceCommitmentFromSeed(new Uint8Array(31), keyIdCommitment, commitment)).toThrow(/32 bytes/);
  });
});
