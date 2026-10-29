import { chmod, link, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { sha256Hex } from "@midnight-ntwrk/trust-registry-domain";
import { withExclusiveWorkspaceWrite, WorkspaceMutationLockedError } from "@midnight-ntwrk/trust-registry-cli";
import { afterEach, describe, expect, it } from "vitest";

import type { ApplicationChallengeRecord } from "../application-challenges.js";
import { FileRecognitionAdmissionStore } from "../file-recognition-admission.js";

const NOW = Date.parse("2026-05-20T00:10:00.000Z");
const registryId = "registry:recognition-admission:trusted";
const recognitionId = "recognition:external:admission:v1";
const hash = (value: string): string => sha256Hex(value);
const challenge = (): ApplicationChallengeRecord => ({
  challengeHash: hash("recognition-challenge"),
  bindingHash: hash("recognition-binding"),
  applicationHash: hash(JSON.stringify([
    "tr:recognition:authority-challenge-identity:v1", registryId, recognitionId,
  ])),
  issuedAtMs: NOW,
  expiresAtMs: NOW + 300_000,
});
const admission = (record: ApplicationChallengeRecord, assertCurrentGovernance = async () => {}) => ({
  targetRegistryId: registryId,
  recognitionId,
  challengeHash: record.challengeHash,
  bindingHash: record.bindingHash,
  policyCommitment: hash("governed-recognition-policy"),
  anchorCommitment: hash("governed-accreditor-anchor"),
  evidenceCommitment: hash("verified-recognition-evidence"),
  expiresAtMs: NOW + 120_000,
  nowMs: NOW + 1000,
  assertCurrentGovernance,
});

const directories: string[] = [];
const paths = async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-recognition-admission-"));
  directories.push(directory);
  const path = join(directory, "private", "recognition.json");
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  return { path, governancePath: join(directory, "workspace.json") };
};
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("file recognition admission store", () => {
  it("atomically replaces a one-use challenge with only redacted receipt fields", async () => {
    const { path, governancePath } = await paths();
    const first = new FileRecognitionAdmissionStore(path, governancePath);
    const second = new FileRecognitionAdmissionStore(path, governancePath);
    const record = challenge();
    expect(await first.insert(record, NOW, () => NOW)).toEqual({ inserted: true, supersededPrevious: false });
    const accepted = await second.accept(admission(record));
    expect(accepted).toMatchObject({
      recognitionId,
      applicationHash: record.applicationHash,
      challengeHash: record.challengeHash,
      policyCommitment: hash("governed-recognition-policy"),
      evidenceCommitment: hash("verified-recognition-evidence"),
    });
    expect(await first.readAccepted(recognitionId)).toEqual(accepted);
    expect(await first.readLive(record.challengeHash, record.bindingHash, NOW + 1000)).toBeNull();
    expect(await second.accept(admission(record))).toBeNull();
    await expect(first.insert({ ...record, challengeHash: hash("new-challenge") }, NOW + 1000, () => NOW + 1000))
      .rejects.toThrow(/already been admitted/u);
    const raw = await readFile(path, "utf8");
    expect(JSON.parse(raw)).toEqual({ version: 1, challenges: [], accepted: [accepted] });
    expect(raw).not.toMatch(/credentialProof|presentationProof|rawCredentialBody|holderDid|nonce/u);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it("retains the challenge when governance changes or the supplied binding is wrong", async () => {
    const { path, governancePath } = await paths();
    const store = new FileRecognitionAdmissionStore(path, governancePath);
    const record = challenge();
    await store.insert(record, NOW, () => NOW);
    await expect(store.accept(admission(record, async () => { throw new Error("stale policy"); })))
      .rejects.toThrow(/stale policy/u);
    expect(await store.accept({ ...admission(record), recognitionId: "recognition:other:v1" })).toBeNull();
    expect(await store.accept({ ...admission(record), bindingHash: hash("other-binding") })).toBeNull();
    expect(await store.readLive(record.challengeHash, record.bindingHash, NOW + 1000)).toEqual(record);
    expect(await store.accept(admission(record))).not.toBeNull();
  });

  it("permits only one cross-instance acceptance and rejects expired evidence", async () => {
    const { path, governancePath } = await paths();
    const first = new FileRecognitionAdmissionStore(path, governancePath);
    const second = new FileRecognitionAdmissionStore(path, governancePath);
    const record = challenge();
    await first.insert(record, NOW, () => NOW);
    expect(await first.accept({ ...admission(record), expiresAtMs: NOW + 999 })).toBeNull();
    const settled = await Promise.all([first.accept(admission(record)), second.accept(admission(record))]);
    expect(settled.filter((receipt) => receipt !== null)).toHaveLength(1);
    expect(await first.readAccepted(recognitionId)).toEqual(settled.find((receipt) => receipt !== null));
  });

  it("holds the governance writer lock through policy recheck and receipt commit", async () => {
    const { path, governancePath } = await paths();
    const store = new FileRecognitionAdmissionStore(path, governancePath);
    const record = challenge();
    await store.insert(record, NOW, () => NOW);
    let entered!: () => void;
    let release!: () => void;
    const insideCheck = new Promise<void>((resolve) => { entered = resolve; });
    const continueCheck = new Promise<void>((resolve) => { release = resolve; });
    const accepting = store.accept(admission(record, async () => {
      entered();
      await continueCheck;
    }));
    await insideCheck;
    await expect(withExclusiveWorkspaceWrite(governancePath, async () => "policy changed"))
      .rejects.toBeInstanceOf(WorkspaceMutationLockedError);
    release();
    expect(await accepting).not.toBeNull();
    await expect(withExclusiveWorkspaceWrite(governancePath, async () => "policy changed"))
      .resolves.toBe("policy changed");
  });

  it("fails closed on a malformed or publicly readable admission file", async () => {
    const { path, governancePath } = await paths();
    const store = new FileRecognitionAdmissionStore(path, governancePath);
    await writeFile(path, "{}", { mode: 0o600 });
    await expect(store.readAccepted(recognitionId)).rejects.toThrow(/file is invalid/u);
    await writeFile(path, JSON.stringify({ version: 1, challenges: [], accepted: [] }), { mode: 0o644 });
    await chmod(path, 0o644);
    await expect(store.readAccepted(recognitionId)).rejects.toThrow(/file is invalid/u);
  });

  it("rejects symbolic and hard links for admission state", async () => {
    for (const makeLink of [symlink, link]) {
      const { path, governancePath } = await paths();
      const target = join(dirname(path), "other.json");
      const contents = JSON.stringify({ version: 1, challenges: [], accepted: [] });
      await writeFile(target, contents, { mode: 0o600 });
      await makeLink(target, path);
      const store = new FileRecognitionAdmissionStore(path, governancePath);
      await expect(store.readAccepted(recognitionId)).rejects.toMatchObject({
        name: "InvalidRecognitionAdmissionFileError",
      });
      await expect(store.insert(challenge(), NOW, () => NOW)).rejects.toMatchObject({
        name: "InvalidRecognitionAdmissionFileError",
      });
      expect(await readFile(target, "utf8")).toBe(contents);
    }
  });
});
