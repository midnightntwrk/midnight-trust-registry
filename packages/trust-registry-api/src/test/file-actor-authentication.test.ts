import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  FileActorAuthenticationChallengeStore,
  InvalidActorAuthenticationFileError,
} from "../file-actor-authentication.js";

const START = Date.parse("2026-11-14T00:00:00.000Z");
const digest = (character: string) => `0x${character.repeat(64)}`;
const actor = digest("a");

async function withPrivateFile(run: (path: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "tr-actor-auth-"));
  try {
    await run(join(directory, "challenges.json"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("file actor authentication challenge store", () => {
  it("keeps a consumed tombstone across restart and rejects a repeated signed digest", async () => {
    await withPrivateFile(async (path) => {
      let now = START;
      const first = new FileActorAuthenticationChallengeStore(path, () => now);
      expect(await first.insert(digest("1"), actor, START + 120_000, START)).toBe(true);
      expect(await first.consume(digest("1"), START)).toBe(true);
      const restarted = new FileActorAuthenticationChallengeStore(path, () => now);
      expect(await restarted.consume(digest("1"), START)).toBe(false);
      expect(await restarted.insert(digest("1"), actor, START + 120_000, START)).toBe(false);
      now += 120_000;
      expect(await restarted.consume(digest("1"), now)).toBe(false);
    });
  });

  it("serializes competing consumers across store instances", async () => {
    await withPrivateFile(async (path) => {
      const first = new FileActorAuthenticationChallengeStore(path, () => START);
      const second = new FileActorAuthenticationChallengeStore(path, () => START);
      expect(await first.insert(digest("2"), actor, START + 120_000, START)).toBe(true);
      const results = await Promise.all([
        first.consume(digest("2"), START), second.consume(digest("2"), START),
      ]);
      expect(results.sort()).toEqual([false, true]);
      expect(await first.consume(digest("2"), START)).toBe(false);
    });
  });

  it("rejects a challenge that expires while its state is being checked", async () => {
    await withPrivateFile(async (path) => {
      const initial = new FileActorAuthenticationChallengeStore(path, () => START);
      expect(await initial.insert(digest("7"), actor, START + 120_000, START)).toBe(true);
      let clockReads = 0;
      const delayed = new FileActorAuthenticationChallengeStore(path,
        () => ++clockReads === 1 ? START : START + 120_000);
      expect(await delayed.consume(digest("7"), START)).toBe(false);
      expect(clockReads).toBe(2);
    });
  });

  it("does not commit a consumed tombstone when expiry passes during file sync", async () => {
    await withPrivateFile(async (path) => {
      const initial = new FileActorAuthenticationChallengeStore(path, () => START);
      expect(await initial.insert(digest("9"), actor, START + 120_000, START)).toBe(true);
      let clockReads = 0;
      const delayed = new FileActorAuthenticationChallengeStore(path,
        () => ++clockReads < 3 ? START : START + 120_000);
      expect(await delayed.consume(digest("9"), START)).toBe(false);
      expect(clockReads).toBe(3);
      const state = JSON.parse(await readFile(path, "utf8")) as { records: Array<{ consumedAtMs?: number }> };
      expect(state.records[0]?.consumedAtMs).toBeUndefined();
    });
  });

  it("rejects a committed consumption when expiry passes during rename or directory sync", async () => {
    await withPrivateFile(async (path) => {
      const initial = new FileActorAuthenticationChallengeStore(path, () => START);
      expect(await initial.insert(digest("b"), actor, START + 120_000, START)).toBe(true);
      let clockReads = 0;
      const delayed = new FileActorAuthenticationChallengeStore(path,
        () => ++clockReads < 4 ? START : START + 120_000);
      expect(await delayed.consume(digest("b"), START)).toBe(false);
      expect(clockReads).toBe(4);
      const state = JSON.parse(await readFile(path, "utf8")) as { records: Array<{ consumedAtMs?: number }> };
      expect(state.records[0]?.consumedAtMs).toBe(START);
    });
  });

  it("bounds issuance per actor including consumed challenges until expiry", async () => {
    await withPrivateFile(async (path) => {
      let now = START;
      const store = new FileActorAuthenticationChallengeStore(path, () => now, 2, 1);
      expect(await store.insert(digest("3"), actor, now + 120_000, now)).toBe(true);
      expect(await store.consume(digest("3"), now)).toBe(true);
      expect(await store.insert(digest("4"), actor, now + 120_000, now)).toBe(false);
      expect(await store.insert(digest("4"), digest("b"), now + 120_000, now)).toBe(true);
      expect(await store.insert(digest("5"), digest("c"), now + 120_000, now)).toBe(false);
      now += 120_000;
      expect(await store.insert(digest("5"), actor, now + 120_000, now)).toBe(true);
      expect(await store.consume(digest("3"), now)).toBe(false);
    });
  });

  it("rejects expiry, clock rollback, tampering, and a substituted file", async () => {
    await withPrivateFile(async (path) => {
      let now = START;
      const store = new FileActorAuthenticationChallengeStore(path, () => now);
      await expect(store.insert(digest("6"), actor, START + 120_001, START))
        .rejects.toBeInstanceOf(InvalidActorAuthenticationFileError);
      expect(await store.insert(digest("6"), actor, START + 120_000, START)).toBe(true);
      now -= 1;
      await expect(store.consume(digest("6"), now)).rejects.toBeInstanceOf(InvalidActorAuthenticationFileError);
      now = START;
      await chmod(path, 0o644);
      await expect(store.consume(digest("6"), now)).rejects.toBeInstanceOf(InvalidActorAuthenticationFileError);
      await rm(path);
      const target = `${path}.target`;
      await writeFile(target, '{}', { mode: 0o600 });
      await symlink(target, path);
      await expect(store.consume(digest("6"), now)).rejects.toBeInstanceOf(InvalidActorAuthenticationFileError);
    });
  });

  it("fails closed on a crash lock and resumes only after operator lock recovery", async () => {
    await withPrivateFile(async (path) => {
      const first = new FileActorAuthenticationChallengeStore(path, () => START);
      expect(await first.insert(digest("8"), actor, START + 120_000, START)).toBe(true);
      await writeFile(`${path}.lock`, "crashed writer", { mode: 0o600 });
      const restarted = new FileActorAuthenticationChallengeStore(path, () => START);
      await expect(restarted.consume(digest("8"), START))
        .rejects.toMatchObject({ name: "WorkspaceMutationLockedError" });
      await rm(`${path}.lock`);
      expect(await restarted.consume(digest("8"), START)).toBe(true);
      await writeFile(`${path}.lock`, "crashed writer", { mode: 0o600 });
      await expect(first.consume(digest("8"), START))
        .rejects.toMatchObject({ name: "WorkspaceMutationLockedError" });
      await rm(`${path}.lock`);
      expect(await new FileActorAuthenticationChallengeStore(path, () => START).consume(digest("8"), START)).toBe(false);
    });
  });
});
