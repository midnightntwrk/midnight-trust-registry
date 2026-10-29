import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";

import { assertStrictDetachedSignatureStatus } from "@midnight-ntwrk/trust-registry-integration/reviewer-signature-status";
import { verifyDetachedReviewerBytes } from "@midnight-ntwrk/trust-registry-integration/reviewer-signature-verifier";

import { regularBytes } from "./standalone-private-file-bytes.mjs";

const FINGERPRINT = /^[A-F0-9]{40}$/u;

/** @param {string} path */
async function privateDirectory(path) {
  const stat = await lstat(path);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Setup directory must be owned by this user and accessible only to them");
  }
  return realpath(path);
}

/** @param {string} output @param {string} expectedFingerprint
 * @param {string} approvedAt @param {number} [now] */
export function assertDetachedReviewerSignatureStatus(
  output, expectedFingerprint, approvedAt, now = Date.now(),
) {
  try {
    if (typeof approvedAt !== "string") throw new Error("Approval timestamp is required");
    assertStrictDetachedSignatureStatus({ output, exitStatus: 0,
      expectedPrimaryFingerprint: expectedFingerprint, approvedAt, now });
  } catch {
    throw new Error("Detached approval signature does not match the pinned reviewer key");
  }
}

/** @param {string} documentPath @param {string} signaturePath
 * @param {string} keyringDirectory @param {string} expectedFingerprint
 * @param {string} approvedAt */
export async function verifyDetachedReviewerSignature(
  documentPath, signaturePath, keyringDirectory, expectedFingerprint, approvedAt,
) {
  const documentBytes = await regularBytes(resolve(documentPath));
  const signatureBytes = await regularBytes(resolve(signaturePath));
  await verifyDetachedReviewerSignatureBytes(documentBytes, signatureBytes,
    keyringDirectory, expectedFingerprint, approvedAt);
}

/** @param {Buffer} documentBytes @param {Buffer} signatureBytes
 * @param {string} keyringDirectory @param {string} expectedFingerprint
 * @param {string} approvedAt */
export async function verifyDetachedReviewerSignatureBytes(
  documentBytes, signatureBytes, keyringDirectory, expectedFingerprint, approvedAt,
) {
  if (!FINGERPRINT.test(expectedFingerprint)) throw new Error("Reviewer signing-key fingerprint must be canonical");
  if (typeof approvedAt !== "string" || !Number.isFinite(Date.parse(approvedAt))) {
    throw new Error("Detached approval signature does not match the pinned reviewer key");
  }
  if (documentBytes.length > 32 * 1024 || signatureBytes.length > 64 * 1024) {
    throw new Error("Reviewer approval document or signature exceeds the bounded evidence size");
  }
  const publicKeySource = resolve(keyringDirectory);
  const sourceStat = await lstat(publicKeySource);
  const armoredExport = sourceStat.isFile();
  const keyboxPath = armoredExport ? publicKeySource
    : join(await privateDirectory(publicKeySource), "pubring.kbx");
  let keybox;
  try {
    keybox = await open(keyboxPath,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      throw new Error("Reviewer keyring needs pubring.kbx; export and import the public key into a pre-created private directory");
    }
    throw error;
  }
  let publicKeys;
  try {
    const stat = await keybox.stat();
    if (!stat.isFile() || stat.size === 0 || stat.size > 8 * 1024 * 1024
      || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
      throw new Error("Reviewer public keyring must be an owned bounded regular file");
    }
    publicKeys = await keybox.readFile();
    if (publicKeys.length !== stat.size) throw new Error("Reviewer public keyring changed during read");
  } finally {
    await keybox.close();
  }
  if (armoredExport && !publicKeys.toString("utf8").startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")) {
    throw new Error("Reviewer key file must be an armored public-key export");
  }
  try {
    verifyDetachedReviewerBytes({ documentBytes, signatureBytes, publicKeyBytes: publicKeys,
      publicKeyFormat: armoredExport ? "armored" : "keybox",
      expectedPrimaryFingerprint: expectedFingerprint, approvedAt });
  } catch {
    throw new Error("Detached approval signature does not match the pinned reviewer key");
  }
}
