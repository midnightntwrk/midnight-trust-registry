import {
  signatureVerifyingKey,
  type SignatureVerifyingKey,
  type SigningKey,
} from "@midnight-ntwrk/compact-runtime";

/** Maintenance policy stores canonical Schnorr verifying keys as 0x-prefixed hex. */
export const maintenanceVerifyingKeyHex = (key: SignatureVerifyingKey): string => {
  if (key.tag !== "schnorr" || !/^[0-9a-f]{64}$/iu.test(key.value)) {
    throw new Error("Maintenance authority requires a Schnorr verifying key");
  }
  return `0x${key.value.toLowerCase()}`;
};

export const maintenanceSigningKeyHex = (key: SigningKey): string =>
  maintenanceVerifyingKeyHex(signatureVerifyingKey(key));
