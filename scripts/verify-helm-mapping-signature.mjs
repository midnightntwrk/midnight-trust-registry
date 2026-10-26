import { execFileSync } from "node:child_process";
import { constants, existsSync, closeSync, fstatSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";

import { assertStrictDetachedSignatureStatus } from "@midnight-ntwrk/trust-registry-integration/reviewer-signature-status";

const FINGERPRINT = /^[0-9A-F]{40}$/u;

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

export function verifyMappingSignature(receiptBytes, signaturePath, keyringPath, signerFingerprint) {
  if (!Buffer.isBuffer(receiptBytes) || !FINGERPRINT.test(signerFingerprint)) {
    throw new Error("Helm image mapping approval input is invalid");
  }
  const verifier = ["/usr/bin/gpgv", "/opt/homebrew/bin/gpgv", "/usr/local/bin/gpgv"].find(existsSync);
  if (!verifier) throw new Error("Helm image mapping requires a trusted GPGV executable");
  const signature = boundedFile(signaturePath, 64 * 1024);
  const keyring = boundedFile(keyringPath, 8 * 1024 * 1024);
  const temporary = mkdtempSync(join(tmpdir(), "tr-helm-mapping-"));
  try {
    const snapshotSignature = join(temporary, "mapping.sig");
    const snapshotKeyring = join(temporary, "pubring.gpg");
    writeFileSync(snapshotSignature, signature, { flag: "wx", mode: 0o600 });
    writeFileSync(snapshotKeyring, keyring, { flag: "wx", mode: 0o600 });
    const output = execFileSync(verifier, ["--homedir", temporary,
      "--keyring", snapshotKeyring, "--status-fd", "1", "--", snapshotSignature, "-"],
    { input: receiptBytes, encoding: "utf8", timeout: 30_000,
      maxBuffer: 1024 * 1024, stdio: ["pipe", "pipe", "pipe"],
      env: { PATH: "/usr/bin:/bin", HOME: temporary, LC_ALL: "C" } });
    return approvedMappingSigner(output, signerFingerprint);
  } catch {
    throw new Error("Helm image mapping has no valid detached signature");
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}
