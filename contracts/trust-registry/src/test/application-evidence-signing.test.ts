import { describe, expect, it } from "vitest";

import {
  applicationEvidenceCommitmentDigest,
  deriveJubjubPublicKeyFromSeed,
  signApplicationEvidenceCommitmentFromSeed,
  verifyApplicationEvidenceCommitmentSignature,
} from "../signing.js";

const seed = new Uint8Array(32).fill(41);
const commitment = Uint8Array.from({ length: 32 }, (_, index) => index);

describe("application evidence commitment signing", () => {
  it("splits the committed bytes into four big-endian circuit digest limbs", () => {
    expect(applicationEvidenceCommitmentDigest(commitment)).toEqual([
      0x0001020304050607n,
      0x08090a0b0c0d0e0fn,
      0x1011121314151617n,
      0x18191a1b1c1d1e1fn,
    ]);
  });

  it("verifies only the signed commitment under the matching verifier key", () => {
    const signature = signApplicationEvidenceCommitmentFromSeed(seed, commitment);
    const publicKey = deriveJubjubPublicKeyFromSeed(seed);

    expect(verifyApplicationEvidenceCommitmentSignature(publicKey, commitment, signature)).toBe(true);
    expect(verifyApplicationEvidenceCommitmentSignature(
      publicKey,
      new Uint8Array(32).fill(2),
      signature,
    )).toBe(false);
    expect(verifyApplicationEvidenceCommitmentSignature(
      deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(42)),
      commitment,
      signature,
    )).toBe(false);
  });

  it("rejects ambiguous commitment and seed lengths", () => {
    expect(() => applicationEvidenceCommitmentDigest(new Uint8Array(31))).toThrow(/32 bytes/);
    expect(() => applicationEvidenceCommitmentDigest(new Uint8Array(33))).toThrow(/32 bytes/);
    expect(() => signApplicationEvidenceCommitmentFromSeed(new Uint8Array(31), commitment)).toThrow(/32 bytes/);
  });
});
