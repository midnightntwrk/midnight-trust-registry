import { constants, closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import { isAbsolute } from "node:path";

import { assertStrictDetachedSignatureStatus } from "@midnight-ntwrk/trust-registry-integration/reviewer-signature-status";
import { verifyDetachedReviewerBytes } from "@midnight-ntwrk/trust-registry-integration/reviewer-signature-verifier";

const FINGERPRINT = /^[0-9A-F]{40}$/u;

/** @param {string} output @param {string} signerFingerprint @param {number} [now] */
export function approvedMappingSigner(output, signerFingerprint, now = Date.now()) {
  if (!FINGERPRINT.test(signerFingerprint)) throw new Error("Invalid mapping signer fingerprint");
  try {
    assertStrictDetachedSignatureStatus({ output, exitStatus: 0,
      expectedPrimaryFingerprint: signerFingerprint, now });
  } catch {
    throw new Error("Helm image mapping has no valid detached signature");
  }
  return signerFingerprint;
}

/** @param {string} path @param {number} maxBytes */
function boundedFile(path, maxBytes) {
  if (!isAbsolute(path)) throw new Error("Helm approval input path must be absolute");
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size === 0 || before.size > maxBytes || before.nlink !== 1
      || (typeof process.getuid === "function" && before.uid !== process.getuid() && before.uid !== 0)) {
      throw new Error("Helm approval input must be an owned bounded regular file");
    }
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    if (bytes.length !== before.size || after.dev !== before.dev || after.ino !== before.ino
      || after.size !== before.size || after.mtimeMs !== before.mtimeMs
      || after.ctimeMs !== before.ctimeMs || after.mode !== before.mode) {
      throw new Error("Helm approval input changed during verification");
    }
    return bytes;
  } finally {
    closeSync(fd);
  }
}

/** @param {Buffer} receiptBytes
 * @param {string} signaturePath
 * @param {string} keyringPath
 * @param {string} signerFingerprint
 */
export function verifyMappingSignature(receiptBytes, signaturePath, keyringPath, signerFingerprint) {
  if (!Buffer.isBuffer(receiptBytes) || !FINGERPRINT.test(signerFingerprint)) {
    throw new Error("Helm image mapping approval input is invalid");
  }
  const signature = boundedFile(signaturePath, 64 * 1024);
  const keyring = boundedFile(keyringPath, 8 * 1024 * 1024);
  try {
    verifyDetachedReviewerBytes({ documentBytes: receiptBytes, signatureBytes: signature,
      publicKeyBytes: keyring, publicKeyFormat: "binary",
      expectedPrimaryFingerprint: signerFingerprint });
  } catch {
    throw new Error("Helm image mapping has no valid detached signature");
  }
  return signerFingerprint;
}
