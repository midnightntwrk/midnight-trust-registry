import { spawnSync } from "node:child_process";
import { constants, existsSync } from "node:fs";
import { lstat, mkdtemp, open, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";

const FINGERPRINT = /^[0-9A-F]{40}$/u;

export function assertApprovedReviewerSignatureStatus(
  output: string,
  exitStatus: number | null,
  expectedPrimaryFingerprint: string,
  now = Date.now(),
  description = "Local API runtime plan",
): void {
  const statuses = output.split("\n").filter((line) => line.startsWith("[GNUPG:] "));
  const valid = statuses.filter((line) => line.startsWith("[GNUPG:] VALIDSIG "));
  const good = statuses.filter((line) => line.startsWith("[GNUPG:] GOODSIG "));
  const fields = valid[0]?.split(/\s+/u);
  const signerFingerprint = fields?.[2];
  const goodSignerKeyId = good[0]?.split(/\s+/u)[2];
  const primaryFingerprint = fields?.[11];
  const signedAt = Number(fields?.[4]);
  const expiresAt = Number(fields?.[5]);
  const hashAlgorithm = fields?.[9];
  const signatureClass = fields?.[10];
  const nowSeconds = Math.floor(now / 1000);
  if (exitStatus !== 0 || !FINGERPRINT.test(expectedPrimaryFingerprint)
    || valid.length !== 1 || good.length !== 1
    || fields?.length !== 12
    || !FINGERPRINT.test(signerFingerprint ?? "")
    || ![signerFingerprint?.slice(-16), signerFingerprint].includes(goodSignerKeyId)
    || primaryFingerprint !== expectedPrimaryFingerprint
    || !Number.isSafeInteger(signedAt) || signedAt <= 0 || signedAt > nowSeconds + 300
    || !Number.isSafeInteger(expiresAt) || expiresAt < 0
    || (expiresAt !== 0 && expiresAt <= nowSeconds)
    || !["8", "9", "10"].includes(hashAlgorithm ?? "")
    || signatureClass !== "00"
    || statuses.some((line) => /^\[GNUPG:\] (?:BADSIG|ERRSIG|EXPKEYSIG|EXPSIG|REVKEYSIG|KEYREVOKED|SIGEXPIRED|PLAINTEXT|PLAINTEXT_LENGTH)\b/u.test(line))) {
    throw new Error(`${description} lacks the approved detached reviewer signature`);
  }
}

export async function readBoundedLocalApprovalFile(
  path: string, maxBytes: number, privateOnly = false,
): Promise<Buffer> {
  if (!isAbsolute(path)) throw new Error("Local API approval path must be absolute");
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.size === 0n || before.size > BigInt(maxBytes)
      || (privateOnly && before.nlink !== 1n)) {
      throw new Error("Local API approval file must be a bounded regular file");
    }
    if (typeof process.getuid === "function" && before.uid !== BigInt(process.getuid()) && before.uid !== 0n) {
      throw new Error("Local API approval file must be owned by root or the runtime user");
    }
    const buffer = Buffer.alloc(Number(before.size));
    let count = 0;
    while (count < buffer.length) {
      const result = await file.read(buffer, count, buffer.length - count, count);
      if (result.bytesRead === 0) break;
      count += result.bytesRead;
    }
    const after = await file.stat({ bigint: true });
    if (count !== buffer.length || after.size !== before.size || after.dev !== before.dev
      || after.ino !== before.ino || after.nlink !== before.nlink || after.mode !== before.mode
      || after.uid !== before.uid || after.mtimeNs !== before.mtimeNs
      || after.ctimeNs !== before.ctimeNs) {
      throw new Error("Local API approval file changed or exceeded its size limit");
    }
    return buffer;
  } finally {
    await file.close();
  }
}

export async function verifyDetachedLocalReviewerSignature(input: {
  documentBytes: Buffer;
  signaturePath: string;
  keyringDirectory: string;
  reviewerFingerprint: string;
  description?: string;
}): Promise<void> {
  const description = input.description ?? "Local API runtime plan";
  if (!FINGERPRINT.test(input.reviewerFingerprint)) {
    throw new Error(`${description} reviewer primary signing-key fingerprint must be canonical`);
  }
  const signatureBytes = await readBoundedLocalApprovalFile(input.signaturePath, 64 * 1024);
  if (!isAbsolute(input.keyringDirectory)) {
    throw new Error(`${description} reviewer keyring path must be absolute`);
  }
  const keyring = await lstat(input.keyringDirectory, { bigint: true });
  if (!keyring.isDirectory() || (keyring.mode & 0o077n) !== 0n
    || (typeof process.getuid === "function" && keyring.uid !== BigInt(process.getuid()) && keyring.uid !== 0n)) {
    throw new Error(`${description} reviewer keyring must be a private directory`);
  }
  const canonicalDirectory = await realpath(input.keyringDirectory);
  let ancestor = canonicalDirectory;
  for (;;) {
    const stat = await lstat(ancestor, { bigint: true });
    const stickyRoot = stat.uid === 0n && (stat.mode & 0o1000n) !== 0n;
    if (!stat.isDirectory()
      || (typeof process.getuid === "function"
        && stat.uid !== BigInt(process.getuid()) && stat.uid !== 0n)
      || ((stat.mode & 0o022n) !== 0n && !stickyRoot)) {
      throw new Error(`${description} reviewer keyring path has an untrusted ancestor`);
    }
    const parent = dirname(ancestor);
    if (parent === ancestor) break;
    ancestor = parent;
  }
  const keyringBytes = await readBoundedLocalApprovalFile(
    join(canonicalDirectory, "pubring.kbx"), 8 * 1024 * 1024, true,
  );
  const keyringAfter = await lstat(input.keyringDirectory, { bigint: true });
  if (!keyringAfter.isDirectory() || keyringAfter.dev !== keyring.dev
    || keyringAfter.ino !== keyring.ino || keyringAfter.uid !== keyring.uid
    || keyringAfter.mode !== keyring.mode || keyringAfter.ctimeNs !== keyring.ctimeNs) {
    throw new Error(`${description} reviewer keyring changed during verification`);
  }
  const gpg = ["/usr/bin/gpg", "/opt/homebrew/bin/gpg", "/usr/local/bin/gpg"].find(existsSync);
  if (gpg === undefined) throw new Error(`${description} requires an installed GPG verifier`);
  const temporary = await mkdtemp(join(tmpdir(), "tr-local-reviewer-approval-"));
  try {
    const documentCopy = join(temporary, "document.json");
    const signatureCopy = join(temporary, "document.sig");
    await writeFile(documentCopy, input.documentBytes, { flag: "wx", mode: 0o600 });
    await writeFile(signatureCopy, signatureBytes, { flag: "wx", mode: 0o600 });
    await writeFile(join(temporary, "pubring.kbx"), keyringBytes, { flag: "wx", mode: 0o600 });
    const verification = spawnSync(gpg, ["--batch", "--no-options", "--no-auto-key-retrieve",
      "--trust-model", "always", "--no-default-keyring", "--homedir", temporary,
      "--keyring", join(temporary, "pubring.kbx"), "--status-fd=1",
      "--verify", signatureCopy, documentCopy],
    { encoding: "utf8", timeout: 10_000, maxBuffer: 1024 * 1024,
      env: { PATH: "/usr/bin:/bin", HOME: temporary, LC_ALL: "C" } });
    if (verification.error) {
      throw new Error(`${description} lacks the approved detached reviewer signature`);
    }
    assertApprovedReviewerSignatureStatus(verification.stdout ?? "", verification.status,
      input.reviewerFingerprint, Date.now(), description);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}
