import { execFileSync } from "node:child_process";
import { constants, existsSync, closeSync, fstatSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";

const FINGERPRINT = /^[0-9A-F]{40}$/u;

export function approvedMappingSigner(output, signerFingerprint, now = Date.now()) {
  if (!FINGERPRINT.test(signerFingerprint)) throw new Error("Invalid mapping signer fingerprint");
  const statuses = output.split("\n").filter((line) => line.startsWith("[GNUPG:] "));
  if (statuses.some((line) => /^\[GNUPG:\] (?:EXPKEYSIG|EXPSIG|REVKEYSIG|KEYREVOKED|KEYEXPIRED|SIGEXPIRED|BADSIG|ERRSIG|NO_PUBKEY|PLAINTEXT|PLAINTEXT_LENGTH)\b/u.test(line))) {
    throw new Error("Helm image mapping signer key or signature is expired, revoked, or invalid");
  }
  const valid = statuses.filter((line) => line.startsWith("[GNUPG:] VALIDSIG "));
  const good = statuses.filter((line) => line.startsWith("[GNUPG:] GOODSIG "));
  const fields = valid[0]?.split(/\s+/u);
  const signer = fields?.[2];
  if (valid.length !== 1 || good.length !== 1 || fields?.length !== 12
    || !FINGERPRINT.test(signer ?? "")
    || ![signer, signer?.slice(-16)].includes(good[0]?.split(/\s+/u)[2])
    || !Number.isSafeInteger(Number(fields?.[4])) || Number(fields?.[4]) <= 0
    || Number(fields?.[4]) > Math.floor(now / 1000) + 300
    || !Number.isSafeInteger(Number(fields?.[5])) || Number(fields?.[5]) < 0
    || (Number(fields?.[5]) !== 0 && Number(fields?.[5]) <= Math.floor(now / 1000))
    || !["8", "9", "10"].includes(fields?.[9]) || fields?.[10] !== "00") {
    throw new Error("Helm image mapping has no valid detached signature");
  }
  if (fields[11] !== signerFingerprint) {
    throw new Error("Helm image mapping signature is not from the approved signer");
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
