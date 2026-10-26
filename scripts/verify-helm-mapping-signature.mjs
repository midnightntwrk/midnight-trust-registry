import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

const FINGERPRINT = /^[0-9A-F]{40}$/u;

export function approvedMappingSigner(output, signerFingerprint) {
  if (!FINGERPRINT.test(signerFingerprint)) throw new Error("Invalid mapping signer fingerprint");
  if (/^\[GNUPG:\] (?:EXPKEYSIG|REVKEYSIG|KEYEXPIRED|SIGEXPIRED|BADSIG|ERRSIG|NO_PUBKEY)\b/mu.test(output)) {
    throw new Error("Helm image mapping signer key or signature is expired, revoked, or invalid");
  }
  const valid = /^\[GNUPG:\] VALIDSIG (.+)$/mu.exec(output)?.[1]?.trim().split(/\s+/u);
  if (!valid || (valid[0] !== signerFingerprint && valid[9] !== signerFingerprint)) {
    throw new Error("Helm image mapping signature is not from the approved signer");
  }
  return signerFingerprint;
}

export function verifyMappingSignature(receiptBytes, signaturePath, keyringPath, signerFingerprint) {
  let output;
  try {
    output = execFileSync("gpgv", ["--keyring", resolve(keyringPath), "--status-fd", "1",
      "--", resolve(signaturePath), "-"], { input: receiptBytes, encoding: "utf8",
      timeout: 30_000, stdio: ["pipe", "pipe", "pipe"] });
  } catch {
    throw new Error("Helm image mapping has no valid detached signature");
  }
  return approvedMappingSigner(output, signerFingerprint);
}
