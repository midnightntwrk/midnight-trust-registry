import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  loadApprovedLocalLedgerRuntimePlan,
  sequenceTimestampMap,
  validateLocalLedgerRuntimePlan,
} from "../local-ledger-runtime.js";

const sourceRevision = "a".repeat(40);
const sha256 = (bytes: Buffer | string): string => createHash("sha256").update(bytes).digest("hex");
const plan = (root: string) => ({
  format: "tr-local-api-runtime-v1",
  networkId: "undeployed",
  sourceRevision,
  installInventoryPath: join(root, "install-inventory.json"),
  installInventorySha256: "b".repeat(64),
  releaseManifestPath: join(root, "release-manifest.json"),
  releaseManifestSha256: "c".repeat(64),
  expectedGenesisHash: `0x${"d".repeat(64)}`,
  contractAddress: `0x${"e".repeat(64)}`,
  rpcUrl: "http://127.0.0.1:29944",
  indexerHttpUrl: "http://127.0.0.1:28088/api/v4/graphql",
  indexerWsUrl: "ws://127.0.0.1:28088/api/v4/graphql/ws",
  allowedHosts: ["127.0.0.1"],
  snapshotPath: join(root, "snapshot.json"),
  snapshotSha256: "f".repeat(64),
  notBefore: new Date(Date.now() - 60_000).toISOString(),
  notAfter: new Date(Date.now() + 7 * 24 * 60 * 60_000).toISOString(),
  sequenceTimestamps: {
    "0": "2026-01-01T00:00:00.000Z",
    "1": "2026-01-01T00:01:00.000Z",
  },
});

describe("approved local-ledger API runtime", () => {
  it("rejects missing, extra, nonlocal, and unordered plan fields", () => {
    const valid = plan("/tmp/tr-api-runtime-test");
    expect(validateLocalLedgerRuntimePlan(valid).sourceRevision).toBe(sourceRevision);
    for (const invalid of [
      { ...valid, networkId: "preprod" },
      { ...valid, extra: true },
      { ...valid, contractAddress: `0x${"0".repeat(64)}` },
      { ...valid, snapshotPath: "relative.json" },
      { ...valid, sequenceTimestamps: {} },
      { ...valid, notAfter: "2026-01-01T00:00:00.000Z" },
      { ...valid, notBefore: new Date(Date.now() + 60_000).toISOString() },
      { ...valid, sequenceTimestamps: { "1": "2026-01-01T00:00:00.000Z" } },
      { ...valid, sequenceTimestamps: { "0": new Date(Date.now() + 60 * 60_000).toISOString() } },
      { ...valid, sequenceTimestamps: { "0": "2026-01-01T00:00:00Z" } },
      { ...valid, sequenceTimestamps: { "0": "2026-01-01T00:01:00.000Z",
        "1": "2026-01-01T00:00:00.000Z" } },
    ]) {
      expect(() => validateLocalLedgerRuntimePlan(invalid)).toThrow();
    }
    const mapper = sequenceTimestampMap(validateLocalLedgerRuntimePlan(valid));
    expect(mapper(1n)).toBe("2026-01-01T00:01:00.000Z");
    expect(() => mapper(2n)).toThrow(/no approved ledger timestamp/u);
    expect(validateLocalLedgerRuntimePlan({ ...valid, sequenceTimestamps: {
      "0": "2026-01-01T00:00:00.000Z", "1": "2026-01-01T00:00:00.000Z",
    } }).sequenceTimestamps["1"]).toBe("2026-01-01T00:00:00.000Z");
  });

  it("requires an actual detached reviewer signature and exact install bytes", async () => {
    expect(spawnSync("gpg", ["--version"], { stdio: "ignore" }).status).toBe(0);
    const root = await mkdtemp(join(tmpdir(), "tr-api-runtime-"));
    try {
      const signer = join(root, "signer");
      const verifier = join(root, "verifier");
      await mkdir(signer, { mode: 0o700 });
      await mkdir(verifier, { mode: 0o700 });
      execFileSync("gpg", ["--homedir", signer, "--batch", "--pinentry-mode", "loopback",
        "--passphrase", "", "--quick-generate-key", "API Reviewer <reviewer@example.test>",
        "ed25519", "sign", "0"], { stdio: "pipe", timeout: 30_000 });
      const listing = execFileSync("gpg", ["--homedir", signer, "--batch", "--with-colons",
        "--list-secret-keys"], { encoding: "utf8" });
      const fingerprint = listing.split("\n").find((line) => line.startsWith("fpr:"))?.split(":")[9];
      expect(fingerprint).toMatch(/^[A-F0-9]{40}$/u);
      const publicKey = execFileSync("gpg", ["--homedir", signer, "--batch", "--export", fingerprint!]);
      execFileSync("gpg", ["--homedir", verifier, "--batch", "--import"],
        { input: publicKey, stdio: ["pipe", "pipe", "pipe"] });
      const inventory = JSON.stringify({ format: "tr-standalone-install-v3", sourceRevision });
      const manifest = JSON.stringify({ format: "tr-release-candidate-manifest-v2", sourceRevision });
      const candidate = { ...plan(root), installInventorySha256: sha256(inventory),
        releaseManifestSha256: sha256(manifest) };
      await writeFile(candidate.installInventoryPath, inventory);
      await writeFile(candidate.releaseManifestPath, manifest);
      const planPath = join(root, "api-plan.json");
      const signaturePath = join(root, "api-plan.sig");
      await writeFile(planPath, `${JSON.stringify(candidate)}\n`);
      execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
        "--output", signaturePath, planPath]);
      const input = { planPath, signaturePath, keyringDirectory: verifier,
        reviewerFingerprint: fingerprint! };
      expect((await loadApprovedLocalLedgerRuntimePlan(input)).sourceRevision).toBe(sourceRevision);
      const v4Inventory = JSON.stringify({ format: "tr-standalone-install-v4", sourceRevision,
        apiRuntime: { manifest: "images/api.manifest.json", manifestSha256: "d".repeat(64),
          archive: "images/api.image.tar", archiveSha256: "e".repeat(64) } });
      await writeFile(candidate.installInventoryPath, v4Inventory);
      const v4Candidate = { ...candidate, installInventorySha256: sha256(v4Inventory) };
      await writeFile(planPath, `${JSON.stringify(v4Candidate)}\n`);
      execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
        "--output", signaturePath, planPath]);
      expect((await loadApprovedLocalLedgerRuntimePlan(input)).sourceRevision).toBe(sourceRevision);
      await writeFile(candidate.installInventoryPath, JSON.stringify({
        format: "tr-standalone-install-v4", sourceRevision,
      }));
      await expect(loadApprovedLocalLedgerRuntimePlan(input)).rejects.toThrow(/approved bytes/u);
      await writeFile(candidate.installInventoryPath, v4Inventory);
      await chmod(verifier, 0o500);
      expect((await loadApprovedLocalLedgerRuntimePlan(input)).sourceRevision).toBe(sourceRevision);
      await chmod(verifier, 0o700);
      const linkedPlan = join(root, "linked-plan.json");
      await symlink(planPath, linkedPlan);
      await expect(loadApprovedLocalLedgerRuntimePlan({ ...input, planPath: linkedPlan })).rejects.toThrow();
      await expect(loadApprovedLocalLedgerRuntimePlan({ ...input,
        reviewerFingerprint: "B".repeat(40) })).rejects.toThrow(/detached reviewer signature/u);
      await writeFile(candidate.releaseManifestPath, `${manifest}\n`);
      await expect(loadApprovedLocalLedgerRuntimePlan(input)).rejects.toThrow(/approved bytes/u);
      await writeFile(candidate.releaseManifestPath, manifest);
      await writeFile(planPath, `${(await readFile(planPath, "utf8")).replace("undeployed", "preprod")}`);
      await expect(loadApprovedLocalLedgerRuntimePlan(input)).rejects.toThrow(/detached reviewer signature/u);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 45_000);
});
