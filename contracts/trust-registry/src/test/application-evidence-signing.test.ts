import { createHash } from "node:crypto";

import { payloadToJubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { describe, expect, it } from "vitest";

import {
  applicationEvidenceSignatureDigest,
  deriveJubjubPublicKeyFromSeed,
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
    const digest = applicationEvidenceSignatureDigest(payloadCommitment, keyIdCommitment);

    expect(digest).toHaveLength(4);
    expect(digest).not.toEqual(payloadToJubjubDigest(payload));
    expect(digest).not.toEqual(applicationEvidenceSignatureDigest(
      payloadCommitment,
      new Uint8Array(32).fill(8),
    ));
  });

  it("verifies only the signed commitment under the matching verifier key", () => {
    const signature = signApplicationEvidenceCommitmentFromSeed(seed, commitment, keyIdCommitment);
    const publicKey = deriveJubjubPublicKeyFromSeed(seed);

    expect(verifyApplicationEvidenceCommitmentSignature(publicKey, commitment, keyIdCommitment, signature)).toBe(true);
    expect(verifyApplicationEvidenceCommitmentSignature(
      publicKey,
      new Uint8Array(32).fill(2),
      keyIdCommitment,
      signature,
    )).toBe(false);
    expect(verifyApplicationEvidenceCommitmentSignature(
      deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(42)),
      commitment,
      keyIdCommitment,
      signature,
    )).toBe(false);
    expect(verifyApplicationEvidenceCommitmentSignature(
      publicKey,
      commitment,
      new Uint8Array(32).fill(8),
      signature,
    )).toBe(false);
  });

  it("rejects ambiguous commitment and seed lengths", () => {
    expect(() => applicationEvidenceSignatureDigest(new Uint8Array(31), keyIdCommitment)).toThrow(/32 bytes/);
    expect(() => applicationEvidenceSignatureDigest(new Uint8Array(33), keyIdCommitment)).toThrow(/32 bytes/);
    expect(() => applicationEvidenceSignatureDigest(commitment, new Uint8Array(31))).toThrow(/32 bytes/);
    expect(() => signApplicationEvidenceCommitmentFromSeed(new Uint8Array(31), commitment, keyIdCommitment)).toThrow(/32 bytes/);
  });
});
