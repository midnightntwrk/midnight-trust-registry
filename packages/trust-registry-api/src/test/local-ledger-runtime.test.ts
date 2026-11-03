import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

const readerMocks = vi.hoisted(() => ({ createReader: vi.fn() }));
vi.mock("@midnight-ntwrk/trust-registry-integration", async (importOriginal) => ({
  ...await importOriginal<typeof import("@midnight-ntwrk/trust-registry-integration")>(),
  createLocalNetworkDeploymentActionReader: readerMocks.createReader,
}));

import {
  assertApprovedDeploymentImage,
  assertApprovedPlanCoversGovernanceCount,
  assertApprovedReviewerSignatureStatus,
  assertLocalApiImageSourceRevision,
  createApprovedLocalLedgerRuntimeSource,
  loadApprovedLocalLedgerRuntimePlan,
  loadApprovedLocalLedgerRuntimePlanWithDigest,
  sequenceTimestampMap,
  validateLocalLedgerRuntimePlan,
} from "../local-ledger-runtime.js";
import { resolveAuthorizationEntry, resolveRecognitionEntry } from "../source.js";

const sourceRevision = "a".repeat(40);
const sha256 = (bytes: Buffer | string): string => createHash("sha256").update(bytes).digest("hex");
const verifierKeySha256 = { first: "1".repeat(64), second: "2".repeat(64) };
const contractAddress = `0x${"e".repeat(64)}`;
const identity = { networkId: "undeployed", contractAddress };
const maintenanceAuthority = { committee: ["3", "4", "5"].map((digit) => `0x${digit.repeat(64)}`),
  threshold: 2, counter: "2" };
const plan = (root: string) => ({
  format: "tr-local-api-runtime-v2",
  networkId: "undeployed",
  sourceRevision,
  installInventoryPath: join(root, "install-inventory.json"),
  installInventorySha256: "b".repeat(64),
  releaseManifestPath: join(root, "release-manifest.json"),
  releaseManifestSha256: "c".repeat(64),
  expectedGenesisHash: `0x${"d".repeat(64)}`,
  contractAddress,
  rpcUrl: "http://127.0.0.1:29944",
  indexerHttpUrl: "http://127.0.0.1:28088/api/v4/graphql",
  indexerWsUrl: "ws://127.0.0.1:28088/api/v4/graphql/ws",
  allowedHosts: ["127.0.0.1"],
  snapshotPath: join(root, "snapshot.json"),
  snapshotSha256: "f".repeat(64),
  verifierKeySha256,
  maintenanceAuthority,
  notBefore: new Date(Date.now() - 60_000).toISOString(),
  notAfter: new Date(Date.now() + 7 * 24 * 60 * 60_000).toISOString(),
  sequenceTimestamps: {
    "0": "2026-01-01T00:00:00.000Z",
    "1": "2026-01-01T00:01:00.000Z",
  },
});

describe("approved local-ledger API runtime", () => {
  it("pins the primary reviewer key when a signing subkey makes the detached signature", () => {
    const primary = "A".repeat(40);
    const signer = "B".repeat(40);
    const now = Date.now();
    const signedAt = Math.floor(now / 1000);
    const valid = `[GNUPG:] VALIDSIG ${signer} 2026-10-23 ${signedAt} 0 4 0 22 8 00 ${primary}`;
    const output = `[GNUPG:] GOODSIG ${signer.slice(-16)} Reviewer\n${valid}\n`;
    expect(() => assertApprovedReviewerSignatureStatus(output, 0, primary, now)).not.toThrow();
    expect(() => assertApprovedReviewerSignatureStatus(
      output.replace(signer.slice(-16), signer), 0, primary, now)).not.toThrow();
    for (const invalid of [
      [output, 0, "C".repeat(40)],
      [output, 1, primary],
      [valid, 0, primary],
      [output.replace(`GOODSIG ${signer.slice(-16)}`, `GOODSIG ${"C".repeat(16)}`), 0, primary],
      [`${output}${valid}\n`, 0, primary],
      [`${output}[GNUPG:] REVKEYSIG ${signer} Reviewer\n`, 0, primary],
      [`${output}[GNUPG:] KEYREVOKED\n`, 0, primary],
      [`${output}[GNUPG:] KEYEXPIRED ${signedAt - 1}\n`, 0, primary],
      [`${output}[GNUPG:] EXPKEYSIG ${signer} Reviewer\n`, 0, primary],
      [`[GNUPG:] GOODSIG ${signer} Reviewer\n[GNUPG:] VALIDSIG ${signer} 2026-10-23 ${signedAt} 0 4 0 22 8 00\n`, 0, primary],
      [`[GNUPG:] GOODSIG ${primary} Reviewer\n[GNUPG:] VALIDSIG ${primary} 2026-10-23 ${signedAt} 0 4 0 22 8 00\n`, 0, primary],
      [`[GNUPG:] GOODSIG ${signer} Reviewer\n[GNUPG:] VALIDSIG ${signer} 2026-10-23 ${signedAt + 600} 0 4 0 22 8 00 ${primary}\n`, 0, primary],
      [`[GNUPG:] GOODSIG ${signer} Reviewer\n[GNUPG:] VALIDSIG ${signer} 2026-10-23 ${signedAt} ${signedAt - 1} 4 0 22 8 00 ${primary}\n`, 0, primary],
      [output.replace(" 22 8 00 ", " 22 2 00 "), 0, primary],
      [output.replace(" 22 8 00 ", " 22 8 01 "), 0, primary],
    ] as const) {
      expect(() => assertApprovedReviewerSignatureStatus(invalid[0], invalid[1], invalid[2], now))
        .toThrow(/approved detached reviewer signature/u);
    }
  });

  it("compares the approved source revision with a bounded container file", async () => {
    const root = await mkdtemp(join(tmpdir(), "tr-api-image-revision-"));
    try {
      const path = join(root, "source-revision");
      await writeFile(path, `${sourceRevision}\n`);
      await expect(assertLocalApiImageSourceRevision(sourceRevision, path)).resolves.toBeUndefined();
      await expect(assertLocalApiImageSourceRevision("b".repeat(40), path))
        .rejects.toThrow(/differs from the approved local plan/u);
      await writeFile(path, `${"b".repeat(40)}\n`);
      await expect(assertLocalApiImageSourceRevision(sourceRevision, path))
        .rejects.toThrow(/differs from the approved local plan/u);
      await writeFile(path, `${sourceRevision}\nextra`);
      await expect(assertLocalApiImageSourceRevision(sourceRevision, path)).rejects.toThrow();
      const linked = join(root, "linked-revision");
      await symlink(path, linked);
      await expect(assertLocalApiImageSourceRevision(sourceRevision, linked)).rejects.toThrow();
      const fifo = join(root, "revision-fifo");
      execFileSync("mkfifo", [fifo]);
      await expect(assertLocalApiImageSourceRevision(sourceRevision, fifo))
        .rejects.toThrow(/bounded regular file/u);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  it("rejects missing, extra, nonlocal, and unordered plan fields", () => {
    const valid = plan("/tmp/tr-api-runtime-test");
    expect(validateLocalLedgerRuntimePlan(valid).sourceRevision).toBe(sourceRevision);
    for (const invalid of [
      { ...valid, networkId: "preprod" },
      { ...valid, extra: true },
      { ...valid, contractAddress: `0x${"0".repeat(64)}` },
      { ...valid, snapshotPath: "relative.json" },
      { ...valid, format: "tr-local-api-runtime-v1" },
      { ...valid, verifierKeySha256: {} },
      { ...valid, verifierKeySha256: { first: "a".repeat(63) } },
      { ...valid, maintenanceAuthority: { ...maintenanceAuthority, counter: "-1" } },
      { ...valid, maintenanceAuthority: { ...maintenanceAuthority, counter: "0" } },
      { ...valid, maintenanceAuthority: { ...maintenanceAuthority, threshold: 1 } },
      { ...valid, maintenanceAuthority: { ...maintenanceAuthority,
        committee: [maintenanceAuthority.committee[0]] } },
      { ...valid, maintenanceAuthority: { ...maintenanceAuthority,
        committee: [maintenanceAuthority.committee[0], maintenanceAuthority.committee[0]] } },
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

  it("rejects finalized verifier-key and maintenance-authority drift", () => {
    const approved = validateLocalLedgerRuntimePlan(plan("/tmp/tr-api-runtime-test"));
    const image = { ...identity, verifierKeySha256, maintenanceAuthority: {
      committee: maintenanceAuthority.committee, threshold: 2, counter: 2n,
    } };
    expect(() => assertApprovedDeploymentImage(approved, image)).not.toThrow();
    for (const invalid of [
      { ...image, networkId: "preprod" },
      { ...image, contractAddress: `0x${"f".repeat(64)}` },
    ]) {
      expect(() => assertApprovedDeploymentImage(approved, invalid))
        .toThrow(/Finalized registry identity differs/u);
    }
    for (const invalid of [
      { ...image, verifierKeySha256: { first: verifierKeySha256.first } },
      { ...image, verifierKeySha256: { ...verifierKeySha256, second: "4".repeat(64) } },
      { ...image, verifierKeySha256: { ...verifierKeySha256, extra: "4".repeat(64) } },
    ]) {
      expect(() => assertApprovedDeploymentImage(approved, invalid))
        .toThrow(/Finalized verifier-key catalog differs/u);
    }
    for (const invalid of [
      { ...image, maintenanceAuthority: { ...image.maintenanceAuthority, counter: 1n } },
      { ...image, maintenanceAuthority: { ...image.maintenanceAuthority, threshold: 1 } },
      { ...image, maintenanceAuthority: { ...image.maintenanceAuthority,
        committee: [`0x${"4".repeat(64)}`] } },
    ]) {
      expect(() => assertApprovedDeploymentImage(approved, invalid))
        .toThrow(/Finalized maintenance authority differs/u);
    }
  });

  it("fails closed when a governed mutation makes the signed sequence map stale", () => {
    const approved = validateLocalLedgerRuntimePlan(plan("/tmp/tr-api-runtime-test"));
    expect(() => assertApprovedPlanCoversGovernanceCount(approved, 1n)).not.toThrow();
    for (const count of [0n, 2n, undefined, "1"]) {
      expect(() => assertApprovedPlanCoversGovernanceCount(approved, count))
        .toThrow(/do not cover the finalized governance count/u);
    }
    const rotated = validateLocalLedgerRuntimePlan({ ...approved,
      snapshotSha256: "a".repeat(64),
      sequenceTimestamps: { ...approved.sequenceTimestamps,
        "2": new Date().toISOString() },
    });
    expect(() => assertApprovedPlanCoversGovernanceCount(approved, 2n)).toThrow();
    expect(() => assertApprovedPlanCoversGovernanceCount(rotated, 2n)).not.toThrow();
    expect(() => assertApprovedPlanCoversGovernanceCount(rotated, 3n)).toThrow();
  });

  it("checks the signed governance count and expiry on actual source reads", async () => {
    const readCurrentFinalizedLedger = vi.fn(async () => ({ ...identity,
      ledger: { governanceActionCount: 2n }, verifierKeySha256,
      maintenanceAuthority: { ...maintenanceAuthority, counter: 2n },
    }));
    readerMocks.createReader.mockResolvedValue({
      readCurrentFinalizedLedger,
    });
    const approved = validateLocalLedgerRuntimePlan(plan("/tmp/tr-api-runtime-test"));
    const source = await createApprovedLocalLedgerRuntimeSource(approved);
    const stale = { cause: { message: expect.stringMatching(/do not cover the finalized governance count/u) } };
    await expect(source.loadSnapshot()).rejects.toMatchObject(stale);
    await expect(source.readFinalizedProposalLedger()).rejects.toMatchObject({
      cause: { message: expect.stringMatching(/operator restart is required/u) },
    });
    expect(readCurrentFinalizedLedger).toHaveBeenCalledTimes(1);
    readCurrentFinalizedLedger.mockResolvedValue({ ...identity, ledger: { governanceActionCount: 1n },
      verifierKeySha256: { ...verifierKeySha256, first: "4".repeat(64) },
      maintenanceAuthority: { ...maintenanceAuthority, counter: 2n } });
    await expect((await createApprovedLocalLedgerRuntimeSource(approved)).loadSnapshot()).rejects.toMatchObject({
      cause: { message: expect.stringMatching(/Finalized verifier-key catalog differs/u) },
    });
    readCurrentFinalizedLedger.mockResolvedValue({ ...identity, ledger: { governanceActionCount: 1n },
      verifierKeySha256,
      maintenanceAuthority: { ...maintenanceAuthority, counter: 1n } });
    await expect((await createApprovedLocalLedgerRuntimeSource(approved)).readFinalizedProposalLedger())
      .rejects.toMatchObject({
        cause: { message: expect.stringMatching(/Finalized maintenance authority differs/u) },
      });
    readCurrentFinalizedLedger.mockResolvedValue({ ...identity, ledger: { governanceActionCount: 1n },
      verifierKeySha256,
      maintenanceAuthority: { ...maintenanceAuthority, counter: 2n } });
    await expect(source.loadSnapshot()).rejects.toMatchObject({
      cause: { message: expect.stringMatching(/operator restart is required/u) },
    });
    expect(readCurrentFinalizedLedger).toHaveBeenCalledTimes(3);
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date(approved.notAfter).getTime() + 1);
      const expired = { cause: { message: expect.stringMatching(/not currently valid/u) } };
      await expect(source.loadSnapshot()).rejects.toMatchObject(expired);
      await expect(source.loadCurrentLedgerSelection()).rejects.toMatchObject(expired);
      await expect(source.readFinalizedProposalLedger()).rejects.toMatchObject(expired);
      await expect(source.readIssuerProposalSnapshot()).rejects.toMatchObject(expired);
      await expect(resolveAuthorizationEntry(source, {
        role: "issuer", subjectDid: "did:midnight:expired", resourceId: "resource:expired",
      })).rejects.toMatchObject(expired);
      await expect(resolveRecognitionEntry(source, {
        recognizedAuthorityDid: "did:midnight:expired", scopeResourceId: "resource:expired",
      })).rejects.toMatchObject(expired);
      expect(readCurrentFinalizedLedger).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
      readerMocks.createReader.mockReset();
    }
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
      const manifest = JSON.stringify({ format: "tr-release-candidate-manifest-v2", sourceRevision,
        verifierKeySha256 });
      const manifestSha256 = sha256(manifest);
      const manifestPin = { packageManifest: "release-manifest.json",
        packageManifestSha256: manifestSha256 };
      const apiRuntime = { manifest: "images/api.manifest.json", manifestSha256: "d".repeat(64),
        archive: "images/api.image.tar", archiveSha256: "e".repeat(64) };
      const inventory = JSON.stringify({ format: "tr-standalone-install-v4", sourceRevision,
        ...manifestPin, apiRuntime });
      const candidate = { ...plan(root), installInventorySha256: sha256(inventory),
        releaseManifestSha256: manifestSha256 };
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
      const fakeBin = join(root, "fake-bin");
      const pathMarker = join(root, "ambient-gpg-invoked");
      await mkdir(fakeBin);
      await writeFile(join(fakeBin, "gpg"),
        `#!/bin/sh\nprintf called > '${pathMarker}'\nexit 0\n`, { mode: 0o700 });
      const ambient = Object.fromEntries(["PATH", "GNUPGHOME", "GPG_AGENT_INFO", "GPG_TTY"]
        .map((key) => [key, process.env[key]]));
      try {
        process.env.PATH = `${fakeBin}:${ambient.PATH ?? ""}`;
        process.env.GNUPGHOME = join(root, "untrusted-home");
        process.env.GPG_AGENT_INFO = "untrusted-agent";
        process.env.GPG_TTY = "/dev/null";
        expect((await loadApprovedLocalLedgerRuntimePlan(input)).sourceRevision).toBe(sourceRevision);
        await expect(readFile(pathMarker)).rejects.toMatchObject({ code: "ENOENT" });
      } finally {
        for (const [key, value] of Object.entries(ambient)) {
          if (value === undefined) delete process.env[key];
          else process.env[key] = value;
        }
      }
      expect(await loadApprovedLocalLedgerRuntimePlanWithDigest(input)).toEqual({
        plan: candidate,
        planSha256: sha256(await readFile(planPath)),
        reviewerFingerprint: fingerprint,
      });
      await writeFile(planPath, `${JSON.stringify(candidate).replace('"networkId":"undeployed"',
        '"networkId":"preprod","networkId":"undeployed"')}\n`);
      execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
        "--output", signaturePath, planPath]);
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/canonical signed JSON without duplicate keys/u);
      await writeFile(planPath, `${JSON.stringify(candidate)}\n`);
      execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
        "--output", signaturePath, planPath]);
      execFileSync("gpg", ["--homedir", signer, "--batch", "--pinentry-mode", "loopback",
        "--passphrase", "", "--quick-add-key", fingerprint!, "ed25519", "sign", "0"],
      { stdio: "pipe", timeout: 30_000 });
      const subkeys = execFileSync("gpg", ["--homedir", signer, "--batch", "--with-colons",
        "--with-subkey-fingerprint", "--list-secret-keys"], { encoding: "utf8" }).split("\n");
      const subkeyIndex = subkeys.findIndex((line) => line.startsWith("ssb:"));
      const subkeyFingerprint = subkeys.slice(subkeyIndex + 1)
        .find((line) => line.startsWith("fpr:"))?.split(":")[9];
      expect(subkeyFingerprint).toMatch(/^[A-F0-9]{40}$/u);
      const updatedPublicKey = execFileSync("gpg", ["--homedir", signer, "--batch",
        "--export", fingerprint!]);
      execFileSync("gpg", ["--homedir", verifier, "--batch", "--import"],
        { input: updatedPublicKey, stdio: ["pipe", "pipe", "pipe"] });
      execFileSync("gpg", ["--homedir", signer, "--batch", "--yes",
        "--local-user", `${subkeyFingerprint}!`, "--detach-sign", "--output", signaturePath,
        planPath]);
      expect((await loadApprovedLocalLedgerRuntimePlan(input)).sourceRevision).toBe(sourceRevision);
      expect((await loadApprovedLocalLedgerRuntimePlan({ ...input, requireApiRuntimePin: true }))
        .sourceRevision).toBe(sourceRevision);
      const v3Inventory = JSON.stringify({ format: "tr-standalone-install-v3", sourceRevision,
        ...manifestPin });
      await writeFile(candidate.installInventoryPath, v3Inventory);
      await writeFile(planPath, `${JSON.stringify({ ...candidate,
        installInventorySha256: sha256(v3Inventory) })}\n`);
      execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
        "--output", signaturePath, planPath]);
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/approved install artifacts/u);
      await expect(loadApprovedLocalLedgerRuntimePlan({ ...input, requireApiRuntimePin: true }))
        .rejects.toThrow(/Cluster API binding requires a signed install/u);
      await writeFile(candidate.installInventoryPath, inventory);
      await writeFile(planPath, `${JSON.stringify(candidate)}\n`);
      execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
        "--output", signaturePath, planPath]);
      const portalPin = (role: string) => ({ manifest: `images/${role}.manifest.json`,
        manifestSha256: "b".repeat(64), archive: `images/${role}.image.tar`,
        archiveSha256: "c".repeat(64) });
      const v6 = { format: "tr-standalone-install-v6", sourceRevision, ...manifestPin,
        apiRuntime,
        portalRuntimes: { admin: portalPin("admin"), applicant: portalPin("applicant") },
        installRelay: { path: "install-relay.mjs", sha256: "d".repeat(64), imageRole: "node" } };
      const signInventory = async (value: object) => {
        const bytes = JSON.stringify(value);
        await writeFile(candidate.installInventoryPath, bytes);
        await writeFile(planPath, `${JSON.stringify({ ...candidate,
          installInventorySha256: sha256(bytes) })}\n`);
        execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
          "--output", signaturePath, planPath]);
      };
      await signInventory(v6);
      expect((await loadApprovedLocalLedgerRuntimePlan({ ...input, requireApiRuntimePin: true }))
        .sourceRevision).toBe(sourceRevision);
      await signInventory({ ...v6, installRelay: { ...v6.installRelay, imageRole: "api" } });
      expect((await loadApprovedLocalLedgerRuntimePlan({ ...input, requireApiRuntimePin: true }))
        .sourceRevision).toBe(sourceRevision);
      await signInventory(v6);
      await writeFile(planPath, `${JSON.stringify({ ...candidate,
        installInventorySha256: sha256(JSON.stringify(v6)),
        verifierKeySha256: { first: "4".repeat(64), second: verifierKeySha256.second } })}\n`);
      execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
        "--output", signaturePath, planPath]);
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/approved verifier-key catalog differs/u);
      await signInventory(v6);
      await signInventory({ ...v6, packageManifestSha256: "f".repeat(64) });
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/disagrees with approved install artifacts/u);
      await signInventory({ ...v6, packageManifest: "unrelated-manifest.json" });
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/disagrees with approved install artifacts/u);
      await signInventory(v6);
      const unrelatedManifestPath = join(root, "unrelated", "release-manifest.json");
      await mkdir(join(root, "unrelated"));
      await writeFile(unrelatedManifestPath, manifest);
      await writeFile(planPath, `${JSON.stringify({ ...candidate,
        installInventorySha256: sha256(JSON.stringify(v6)),
        releaseManifestPath: unrelatedManifestPath })}\n`);
      execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign",
        "--output", signaturePath, planPath]);
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/disagrees with approved install artifacts/u);
      await signInventory(v6);
      await signInventory({ ...v6, format: "tr-standalone-install-v5", installRelay: undefined });
      expect((await loadApprovedLocalLedgerRuntimePlan({ ...input, requireApiRuntimePin: true }))
        .sourceRevision).toBe(sourceRevision);
      await signInventory({ ...v6, format: "tr-standalone-install-v5", installRelay: undefined,
        portalRuntimes: undefined });
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/approved install artifacts/u);
      await signInventory({ ...v6, apiRuntime: undefined });
      await expect(loadApprovedLocalLedgerRuntimePlan({ ...input, requireApiRuntimePin: true }))
        .rejects.toThrow(/approved install artifacts/u);
      await signInventory({ ...v6, installRelay: { ...v6.installRelay, sha256: "invalid" } });
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/disagrees with approved install artifacts/u);
      await signInventory({ ...v6, installRelay: { ...v6.installRelay, sha256: ["d".repeat(64)] } });
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/approved install artifacts/u);
      await signInventory({ ...v6, installRelay: { ...v6.installRelay, path: "../install-relay.mjs" } });
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/approved install artifacts/u);
      await signInventory({ ...v6, installRelay: { ...v6.installRelay, imageRole: "indexer" } });
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/approved install artifacts/u);
      await signInventory({ ...v6, installRelay: undefined });
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/approved install artifacts/u);
      await signInventory({ ...v6, portalRuntimes: { admin: portalPin("admin") } });
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/disagrees with approved install artifacts/u);
      await signInventory({ ...v6, portalRuntimes: { ...v6.portalRuntimes,
        extra: portalPin("extra") } });
      await expect(loadApprovedLocalLedgerRuntimePlan(input))
        .rejects.toThrow(/approved install artifacts/u);
      await signInventory(JSON.parse(inventory));
      await writeFile(candidate.installInventoryPath, JSON.stringify({
        format: "tr-standalone-install-v4", sourceRevision,
      }));
      await expect(loadApprovedLocalLedgerRuntimePlan(input)).rejects.toThrow(/approved bytes/u);
      await writeFile(candidate.installInventoryPath, inventory);
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
