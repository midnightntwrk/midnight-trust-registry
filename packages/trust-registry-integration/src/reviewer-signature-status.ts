const FINGERPRINT = /^[0-9A-F]{40}$/u;
const REJECTED_STATUS = /^\[GNUPG:\] (?:BADSIG|ERRSIG|EXPKEYSIG|EXPSIG|REVKEYSIG|KEYREVOKED|KEYEXPIRED|SIGEXPIRED|NO_PUBKEY|NODATA|PLAINTEXT|PLAINTEXT_LENGTH)\b/u;

/** Validate the pinned primary signer, not merely gpg's successful process exit. */
export function assertStrictDetachedSignatureStatus(input: {
  output: string;
  exitStatus: number | null;
  expectedPrimaryFingerprint: string;
  approvedAt?: string;
  now?: number;
}): void {
  const { output, exitStatus, expectedPrimaryFingerprint, approvedAt } = input;
  const now = input.now ?? Date.now();
  const statuses = output.split("\n").filter((line) => line.startsWith("[GNUPG:] "));
  const valid = statuses.filter((line) => line.startsWith("[GNUPG:] VALIDSIG "));
  const good = statuses.filter((line) => line.startsWith("[GNUPG:] GOODSIG "));
  const fields = valid[0]?.split(/\s+/u);
  const signer = fields?.[2];
  const goodSigner = good[0]?.split(/\s+/u)[2];
  const signedAt = Number(fields?.[4]);
  const expiresAt = Number(fields?.[5]);
  const nowSeconds = Math.floor(now / 1000);
  const minimumSignedAt = approvedAt === undefined ? 0 : Math.floor(Date.parse(approvedAt) / 1000);
  if (exitStatus !== 0 || !FINGERPRINT.test(expectedPrimaryFingerprint)
    || valid.length !== 1 || good.length !== 1 || fields?.length !== 12
    || !FINGERPRINT.test(signer ?? "")
    || ![signer, signer?.slice(-16)].includes(goodSigner ?? "")
    || fields[11] !== expectedPrimaryFingerprint
    || !Number.isSafeInteger(signedAt) || signedAt <= 0
    || !Number.isSafeInteger(minimumSignedAt) || signedAt < minimumSignedAt
    || signedAt > nowSeconds + 300
    || !Number.isSafeInteger(expiresAt) || expiresAt < 0
    || (expiresAt !== 0 && expiresAt <= nowSeconds)
    || !["8", "9", "10"].includes(fields[9] ?? "") || fields[10] !== "00"
    || statuses.some((line) => REJECTED_STATUS.test(line))) {
    throw new Error("Detached signature does not match the pinned reviewer and strict status policy");
  }
}
