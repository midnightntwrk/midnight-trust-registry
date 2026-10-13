import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { afterEach, describe, expect, it } from "vitest";

import type { ApplicationChallengeRecord } from "../application-challenges.js";
import { FileApplicationChallengeStore } from "../file-application-challenges.js";

const START = Date.parse("2026-10-13T00:00:00.000Z");
const hash = (value: number): string => `0x${value.toString(16).padStart(64, "0")}`;
const record = (challenge: number, application: number, binding = 1): ApplicationChallengeRecord => ({
  challengeHash: hash(challenge),
  applicationHash: hash(application),
  bindingHash: hash(binding),
  issuedAtMs: START,
  expiresAtMs: START + 300_000,
});

const directories: string[] = [];
async function storePath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "tr-file-challenges-"));
  directories.push(directory);
  const path = join(directory, "nested", "challenges.json");
  await mkdir(dirname(path), { recursive: true });
  return path;
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("file application challenge store", () => {
  it("persists only hashes and timestamps in a private file across instances", async () => {
    const path = await storePath();
    const first = new FileApplicationChallengeStore(path);
    const second = new FileApplicationChallengeStore(path);
    const challenge = record(10, 20);
    expect(await first.insert(challenge, START, () => START)).toEqual({ inserted: true, supersededPrevious: false });
    expect(await second.readLive(challenge.challengeHash, challenge.bindingHash, START)).toEqual(challenge);
    const raw = await readFile(path, "utf8");
    expect(JSON.parse(raw)).toEqual({ version: 1, records: [challenge] });
    expect(raw).not.toContain("nonce");
    expect(raw).not.toContain("presentation");
    expect(raw).not.toContain("claims");
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it("allows only one cross-instance consumer, including concurrent attempts", async () => {
    const path = await storePath();
    const first = new FileApplicationChallengeStore(path);
    const second = new FileApplicationChallengeStore(path);
    const challenge = record(10, 20);
    await first.insert(challenge, START, () => START);
    const results = await Promise.all([
      first.consume(challenge.challengeHash, challenge.bindingHash, START),
      second.consume(challenge.challengeHash, challenge.bindingHash, START),
    ]);
    expect(results.sort()).toEqual([false, true]);
    expect(await first.consume(challenge.challengeHash, challenge.bindingHash, START)).toBe(false);
    expect(await second.readLive(challenge.challengeHash, challenge.bindingHash, START)).toBeNull();
  });

  it("supersedes only a live challenge with the same application and binding", async () => {
    const path = await storePath();
    const first = new FileApplicationChallengeStore(path);
    const second = new FileApplicationChallengeStore(path);
    const old = record(10, 20);
    const next = record(11, 20);
    await first.insert(old, START, () => START);
    expect(await second.insert(next, START, () => START)).toEqual({ inserted: true, supersededPrevious: true });
    expect(await first.readLive(old.challengeHash, old.bindingHash, START)).toBeNull();
    expect(await first.consume(next.challengeHash, next.bindingHash, START)).toBe(true);
  });

  it("rejects binding conflict and hash collision without altering the live record", async () => {
    const path = await storePath();
    const first = new FileApplicationChallengeStore(path);
    const second = new FileApplicationChallengeStore(path);
    const existing = record(10, 20);
    await first.insert(existing, START, () => START);
    await expect(second.insert(record(11, 20, 2), START, () => START)).rejects.toMatchObject({
      code: "CHALLENGE_BINDING_CONFLICT",
    });
    expect(await second.insert(record(10, 21), START, () => START)).toEqual({
      inserted: false, supersededPrevious: false,
    });
    expect(await first.readLive(existing.challengeHash, existing.bindingHash, START)).toEqual(existing);
    expect(await second.consume(existing.challengeHash, hash(2), START)).toBe(false);
  });

  it("enforces capacity, then permits expiry replacement and rejects expired consumption", async () => {
    const path = await storePath();
    const first = new FileApplicationChallengeStore(path, 1);
    const second = new FileApplicationChallengeStore(path, 1);
    const old = record(10, 20);
    await first.insert(old, START, () => START);
    await expect(second.insert(record(11, 21), START, () => START)).rejects.toMatchObject({
      code: "CHALLENGE_CAPACITY",
    });
    expect(await second.consume(old.challengeHash, old.bindingHash, START + 300_000)).toBe(false);
    expect(await first.readLive(old.challengeHash, old.bindingHash, START + 300_000)).toBeNull();
    expect(await second.insert(record(11, 21), START + 300_000, () => START + 300_000)).toEqual({
      inserted: false, supersededPrevious: false,
    });
    const fresh = { ...record(11, 21), issuedAtMs: START + 300_000, expiresAtMs: START + 600_000 };
    expect(await second.insert(fresh, START + 300_000, () => START + 300_000)).toEqual({
      inserted: true, supersededPrevious: false,
    });
  });

  it("rejects clock rollback and invalid expiry without consuming or replacing", async () => {
    const path = await storePath();
    const store = new FileApplicationChallengeStore(path);
    const challenge = record(10, 20);
    await store.insert(challenge, START, () => START);
    await expect(store.consume(challenge.challengeHash, challenge.bindingHash, START - 10_000)).rejects.toMatchObject({
      code: "CHALLENGE_CLOCK_INVALID",
    });
    await expect(store.readLive(challenge.challengeHash, challenge.bindingHash, START - 10_000)).rejects.toMatchObject({
      code: "CHALLENGE_CLOCK_INVALID",
    });
    await expect(store.insert({ ...record(11, 21), expiresAtMs: START + 2_147_483_647 + 10_000 }, START, () => START))
      .rejects.toMatchObject({ code: "CHALLENGE_EXPIRY_RANGE" });
    expect(await store.consume(challenge.challengeHash, challenge.bindingHash, START)).toBe(true);
  });

  it("does not consume a challenge that expires while waiting for the write lock", async () => {
    const path = await storePath();
    const store = new FileApplicationChallengeStore(path);
    const challenge = { ...record(10, 20), expiresAtMs: START + 30 };
    await store.insert(challenge, START, () => START);
    await writeFile(`${path}.lock`, "busy", { mode: 0o600 });
    const pending = store.consume(challenge.challengeHash, challenge.bindingHash, START);
    await delay(60);
    await rm(`${path}.lock`);
    expect(await pending).toBe(false);
  });

  it.each([
    "not json",
    JSON.stringify({ version: 2, records: [] }),
    JSON.stringify({ version: 1, records: [], nonce: "secret" }),
    JSON.stringify({ version: 1, records: [{ ...record(10, 20), nonce: "secret" }] }),
    JSON.stringify({ version: 1, records: [record(10, 20), record(11, 20)] }),
    JSON.stringify({ version: 1, records: [record(10, 20), record(10, 21)] }),
    JSON.stringify({ version: 1, records: [{ ...record(10, 20), expiresAtMs: START }] }),
  ])("fails closed on malformed persisted state", async (state) => {
    const path = await storePath();
    await writeFile(path, state, { mode: 0o600 });
    const store = new FileApplicationChallengeStore(path);
    await expect(store.readLive(hash(10), hash(1), START)).rejects.toMatchObject({
      name: "InvalidApplicationChallengeFileError",
    });
    await expect(store.consume(hash(10), hash(1), START)).rejects.toMatchObject({
      name: "InvalidApplicationChallengeFileError",
    });
    await expect(store.insert(record(11, 21), START, () => START)).rejects.toMatchObject({
      name: "InvalidApplicationChallengeFileError",
    });
    expect(await readFile(path, "utf8")).toBe(state);
  });

  it("rejects a readable-by-others file without replacing it", async () => {
    const path = await storePath();
    await writeFile(path, JSON.stringify({ version: 1, records: [] }), { mode: 0o644 });
    const store = new FileApplicationChallengeStore(path);
    await expect(store.insert(record(10, 20), START, () => START)).rejects.toMatchObject({
      name: "InvalidApplicationChallengeFileError",
    });
    expect((await stat(path)).mode & 0o777).toBe(0o644);
  });

  it("does not remove a stale lock or silently bypass it", async () => {
    const path = await storePath();
    const lockPath = `${path}.lock`;
    await writeFile(lockPath, "operator recovery required");
    const store = new FileApplicationChallengeStore(path);
    await expect(store.insert(record(10, 20), START, () => START)).rejects.toMatchObject({
      name: "WorkspaceMutationLockedError",
    });
    expect(await readFile(lockPath, "utf8")).toBe("operator recovery required");
  });
});
