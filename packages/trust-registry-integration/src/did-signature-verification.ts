import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import { verifyJubjubDigest, type JubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { decodeCanonicalJubjubSignatureHex, isPrimeOrderJubjubPoint } from "@midnight-ntwrk/trust-registry-contract";

/** DID method membership is insufficient when a malformed or low-order key makes Schnorr forgeable. */
export const verifyDidJubjubSignature = (
  publicKey: JubjubPoint,
  digest: JubjubDigest,
  signatureHex: string,
): boolean => {
  try {
    if (!isPrimeOrderJubjubPoint(publicKey)) return false;
    const signature = decodeCanonicalJubjubSignatureHex(signatureHex);
    return verifyJubjubDigest(publicKey, digest, signature);
  } catch {
    return false;
  }
};
