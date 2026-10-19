import { ecAdd, ecMul, type JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import { verifyJubjubDigest, type JubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { decodeCanonicalJubjubSignatureHex, JUBJUB_ORDER } from "@midnight-ntwrk/trust-registry-contract";

/** DID method membership is insufficient when a malformed or low-order key makes Schnorr forgeable. */
export const verifyDidJubjubSignature = (
  publicKey: JubjubPoint,
  digest: JubjubDigest,
  signatureHex: string,
): boolean => {
  try {
    const isPrimeOrder = (point: JubjubPoint): boolean => {
      if (point.x === 0n && point.y === 1n) return false;
      const orderMultiple = ecAdd(ecMul(point, JUBJUB_ORDER - 1n), point);
      return orderMultiple.x === 0n && orderMultiple.y === 1n;
    };
    if (!isPrimeOrder(publicKey)) return false;
    const signature = decodeCanonicalJubjubSignatureHex(signatureHex);
    return isPrimeOrder(signature.announcement) && verifyJubjubDigest(publicKey, digest, signature);
  } catch {
    return false;
  }
};
