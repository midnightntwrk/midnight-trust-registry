import { Buffer } from "node:buffer";

import { signJubjubDigestFromSeed, type JubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { deriveJubjubPublicKey, deriveJubjubPublicKeyFromSeed, encodeJubjubSignature, JUBJUB_ORDER } from "@midnight-ntwrk/trust-registry-contract";
import { describe, expect, it } from "vitest";

import { verifyDidJubjubSignature } from "../did-signature-verification.js";

const digest: JubjubDigest = [1n, 2n, 3n, 4n];
const seed = new Uint8Array(32).fill(93);
const publicKey = deriveJubjubPublicKeyFromSeed(seed);
const signed = signJubjubDigestFromSeed(seed, digest);
const hex = (signature: typeof signed): string =>
  `0x${Buffer.from(encodeJubjubSignature(signature)).toString("hex")}`;

describe("DID-resolved Jubjub signature verification", () => {
  it("accepts a canonical signature under a prime-order key", () => {
    expect(verifyDidJubjubSignature(publicKey, digest, hex(signed))).toBe(true);
  });

  it("rejects identity, low-order, and off-curve DID keys without trapping", () => {
    const nonce = 7n;
    const forged = hex({ announcement: deriveJubjubPublicKey(nonce), response: nonce });
    expect(verifyDidJubjubSignature({ x: 0n, y: 1n }, digest, forged)).toBe(false);
    expect(verifyDidJubjubSignature({
      x: 0n,
      y: 52435875175126190479447740508185965837690552500527637822603658699938581184512n,
    }, digest, forged)).toBe(false);
    expect(verifyDidJubjubSignature({ x: 3n, y: 5n }, digest, forged)).toBe(false);
  });

  it("rejects noncanonical and malformed signatures without runtime errors", () => {
    expect(verifyDidJubjubSignature(publicKey, digest, hex({
      ...signed, announcement: { x: 0n, y: 1n },
    }))).toBe(false);
    expect(verifyDidJubjubSignature(publicKey, digest, hex({
      ...signed,
      announcement: {
        x: 0n,
        y: 52435875175126190479447740508185965837690552500527637822603658699938581184512n,
      },
    }))).toBe(false);
    expect(verifyDidJubjubSignature(publicKey, digest, hex({
      ...signed, response: signed.response + JUBJUB_ORDER,
    }))).toBe(false);
    expect(verifyDidJubjubSignature(publicKey, digest, hex(signed).slice(0, -1))).toBe(false);
    expect(verifyDidJubjubSignature(publicKey, digest, null as unknown as string)).toBe(false);
    expect(verifyDidJubjubSignature(null as unknown as typeof publicKey, digest, hex(signed))).toBe(false);
  });
});
