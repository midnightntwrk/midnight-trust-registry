import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { assertStrictDetachedSignatureStatus } from "./reviewer-signature-status.js";

export type ReviewerKeyFormat = "keybox" | "binary" | "armored";

/** Verify only caller-snapshotted bytes using an isolated public-key home. */
export function verifyDetachedReviewerBytes(input: {
  documentBytes: Buffer;
  signatureBytes: Buffer;
  publicKeyBytes: Buffer;
  publicKeyFormat: ReviewerKeyFormat;
  expectedPrimaryFingerprint: string;
  approvedAt?: string;
  now?: number;
}): void {
  if (!Buffer.isBuffer(input.documentBytes) || input.documentBytes.length === 0
    || input.documentBytes.length > 16 * 1024 * 1024
    || !Buffer.isBuffer(input.signatureBytes) || input.signatureBytes.length === 0
    || input.signatureBytes.length > 64 * 1024
    || !Buffer.isBuffer(input.publicKeyBytes) || input.publicKeyBytes.length === 0
    || input.publicKeyBytes.length > 8 * 1024 * 1024
    || !["keybox", "binary", "armored"].includes(input.publicKeyFormat)) {
    throw new Error("Detached reviewer signature input is invalid");
  }
  const gpg = ["/usr/bin/gpg", "/opt/homebrew/bin/gpg", "/usr/local/bin/gpg"].find(existsSync);
  if (gpg === undefined) throw new Error("A trusted GPG executable is required");
  // Keep GPG agent sockets below the macOS Unix-domain path limit.
  const shortTempRoot = tmpdir().length > 55 ? "/tmp" : tmpdir();
  const temporary = mkdtempSync(join(shortTempRoot, "tr-reviewer-verifier-"));
  const env = { PATH: "/usr/bin:/bin", HOME: temporary, LC_ALL: "C" };
  try {
    const document = join(temporary, "document.json");
    const signature = join(temporary, "document.sig");
    const keyring = join(temporary, input.publicKeyFormat === "binary" ? "pubring.gpg" : "pubring.kbx");
    writeFileSync(document, input.documentBytes, { flag: "wx", mode: 0o600 });
    writeFileSync(signature, input.signatureBytes, { flag: "wx", mode: 0o600 });
    if (input.publicKeyFormat === "armored") {
      const publicExport = join(temporary, "reviewer-public.asc");
      writeFileSync(publicExport, input.publicKeyBytes, { flag: "wx", mode: 0o600 });
      const imported = spawnSync(gpg, ["--batch", "--no-options", "--no-auto-key-retrieve",
        "--homedir", temporary, "--import", publicExport],
      { env, encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024 });
      if (imported.error || imported.status !== 0) throw new Error("Reviewer public-key import failed");
    } else {
      writeFileSync(keyring, input.publicKeyBytes, { flag: "wx", mode: 0o600 });
    }
    const result = spawnSync(gpg, ["--batch", "--no-options", "--no-auto-key-retrieve",
      "--trust-model", "always", "--no-default-keyring", "--homedir", temporary,
      "--keyring", keyring, "--status-fd=1", "--verify", signature, document],
    { env, encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024 });
    if (result.error) throw new Error("Detached reviewer signature verification failed");
    assertStrictDetachedSignatureStatus({ output: result.stdout ?? "", exitStatus: result.status,
      expectedPrimaryFingerprint: input.expectedPrimaryFingerprint,
      ...(input.approvedAt === undefined ? {} : { approvedAt: input.approvedAt }),
      ...(input.now === undefined ? {} : { now: input.now }) });
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}
