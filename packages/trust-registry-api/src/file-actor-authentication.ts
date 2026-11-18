import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { open, rename, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { withExclusiveWorkspaceWrite, WorkspaceMutationLockedError } from "@midnightntwrk/trust-registry-cli";
import { MAX_ACTOR_AUTHENTICATION_CHALLENGE_AGE_MS } from "@midnightntwrk/trust-registry-domain";
import { z } from "zod";

import type { ActorAuthenticationChallengeStore } from "./actor-authentication.js";

const MAX_ENTRIES = 10_000;
const MAX_PER_ACTOR = 32;
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const LOCK_ATTEMPTS = 100;
const LOCK_RETRY_MS = 10;
const HashSchema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const TimestampSchema = z.number().int().safe().nonnegative();
const RecordSchema = z.object({
  digest: HashSchema,
  actorHash: HashSchema,
  issuedAtMs: TimestampSchema,
  expiresAtMs: TimestampSchema,
  consumedAtMs: TimestampSchema.optional(),
}).strict().superRefine((record, context) => {
  if (record.expiresAtMs <= record.issuedAtMs
    || record.expiresAtMs - record.issuedAtMs > MAX_ACTOR_AUTHENTICATION_CHALLENGE_AGE_MS
    || (record.consumedAtMs !== undefined
      && (record.consumedAtMs < record.issuedAtMs || record.consumedAtMs >= record.expiresAtMs))) {
    context.addIssue({ code: "custom", message: "Invalid challenge time" });
  }
});
const StateSchema = z.object({
  version: z.literal(1),
  records: z.array(RecordSchema).max(MAX_ENTRIES),
}).strict().superRefine((state, context) => {
  const seen = new Set<string>();
  for (const [index, record] of state.records.entries()) {
    if (seen.has(record.digest)) {
      context.addIssue({ code: "custom", message: "Duplicate challenge", path: ["records", index] });
    }
    seen.add(record.digest);
  }
});

type State = z.infer<typeof StateSchema>;

export class InvalidActorAuthenticationFileError extends Error {
  constructor() {
    super("Actor authentication challenge file is invalid");
    this.name = "InvalidActorAuthenticationFileError";
  }
}

/** Local durable adapter; the caller must place this private file on a trusted filesystem. */
export class FileActorAuthenticationChallengeStore implements ActorAuthenticationChallengeStore {
  private readonly path: string;

  constructor(path: string, private readonly clock: () => number = Date.now,
    private readonly maxEntries = MAX_ENTRIES, private readonly maxPerActor = MAX_PER_ACTOR) {
    if (path.length === 0 || !Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > MAX_ENTRIES
      || !Number.isSafeInteger(maxPerActor) || maxPerActor < 1 || maxPerActor > maxEntries) {
      throw new RangeError("Actor authentication challenge store configuration is invalid");
    }
    this.path = resolve(path);
  }

  async insert(digest: string, actorHash: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    this.assertClock(nowMs);
    this.assertClock(expiresAtMs);
    if (!HashSchema.safeParse(digest).success || !HashSchema.safeParse(actorHash).success
      || expiresAtMs <= nowMs || expiresAtMs - nowMs > MAX_ACTOR_AUTHENTICATION_CHALLENGE_AGE_MS) {
      throw new InvalidActorAuthenticationFileError();
    }
    return this.withWrite(async () => {
      const currentNow = this.currentTime(nowMs);
      const state = await this.readState();
      this.assertStateClock(state, currentNow);
      const commitNow = this.currentTime(currentNow);
      if (expiresAtMs <= commitNow) return false;
      const live = state.records.filter((entry) => entry.expiresAtMs > commitNow);
      if (live.some((entry) => entry.digest === digest)) return false;
      if (live.length >= this.maxEntries || live.filter((entry) => entry.actorHash === actorHash).length >= this.maxPerActor) {
        return false;
      }
      return this.writeState(
        { version: 1, records: [...live, { digest, actorHash, issuedAtMs: nowMs, expiresAtMs }] },
        () => this.currentTime(commitNow) < expiresAtMs,
      );
    });
  }

  async consume(digest: string, nowMs: number): Promise<boolean> {
    this.assertClock(nowMs);
    if (!HashSchema.safeParse(digest).success) return false;
    return this.withWrite(async () => {
      const currentNow = this.currentTime(nowMs);
      const state = await this.readState();
      this.assertStateClock(state, currentNow);
      const commitNow = this.currentTime(currentNow);
      const record = state.records.find((entry) => entry.digest === digest);
      if (record === undefined || record.expiresAtMs <= commitNow || record.consumedAtMs !== undefined) return false;
      return this.writeState(
        { version: 1, records: state.records.map((entry) => entry.digest === digest
          ? { ...entry, consumedAtMs: commitNow } : entry) },
        () => this.currentTime(commitNow) < record.expiresAtMs,
      );
    });
  }

  private assertClock(nowMs: number): void {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new InvalidActorAuthenticationFileError();
  }

  private currentTime(callerTime: number): number {
    const current = this.clock();
    this.assertClock(current);
    if (current < callerTime) throw new InvalidActorAuthenticationFileError();
    return current;
  }

  private assertStateClock(state: State, currentNow: number): void {
    if (state.records.some((entry) => entry.issuedAtMs > currentNow
      || (entry.consumedAtMs !== undefined && entry.consumedAtMs > currentNow))) {
      throw new InvalidActorAuthenticationFileError();
    }
  }

  private async withWrite<T>(operation: () => Promise<T>): Promise<T> {
    const directoryIdentity = await this.directoryIdentity();
    for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
      try {
        return await withExclusiveWorkspaceWrite(this.path, async () => {
          if (await this.directoryIdentity() !== directoryIdentity) throw new InvalidActorAuthenticationFileError();
          return operation();
        });
      } catch (error) {
        if (!(error instanceof WorkspaceMutationLockedError) || attempt === LOCK_ATTEMPTS - 1) throw error;
        await delay(LOCK_RETRY_MS);
      }
    }
    throw new WorkspaceMutationLockedError();
  }

  private async directoryIdentity(): Promise<string> {
    let directory;
    try {
      directory = await open(dirname(this.path), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    } catch {
      throw new InvalidActorAuthenticationFileError();
    }
    try {
      const stat = await directory.stat({ bigint: true });
      if (!stat.isDirectory()) throw new InvalidActorAuthenticationFileError();
      return `${stat.dev}:${stat.ino}`;
    } finally {
      await directory.close();
    }
  }

  private async readState(): Promise<State> {
    let handle;
    try {
      handle = await open(this.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { version: 1, records: [] };
      if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new InvalidActorAuthenticationFileError();
      throw error;
    }
    try {
      const before = await handle.stat({ bigint: true });
      if (!before.isFile() || before.nlink !== 1n || (before.mode & 0o077n) !== 0n
        || before.size === 0n || before.size > BigInt(MAX_FILE_BYTES)) throw new InvalidActorAuthenticationFileError();
      const raw = Buffer.alloc(Number(before.size));
      let offset = 0;
      while (offset < raw.length) {
        const { bytesRead } = await handle.read(raw, offset, raw.length - offset, offset);
        if (bytesRead === 0) throw new InvalidActorAuthenticationFileError();
        offset += bytesRead;
      }
      const after = await handle.stat({ bigint: true });
      if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size
        || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs) {
        throw new InvalidActorAuthenticationFileError();
      }
      try {
        const state = StateSchema.parse(JSON.parse(raw.toString("utf8")));
        if (state.records.length > this.maxEntries) throw new InvalidActorAuthenticationFileError();
        return state;
      } catch {
        throw new InvalidActorAuthenticationFileError();
      }
    } finally {
      await handle.close();
    }
  }

  private async writeState(state: State, stillLive: () => boolean): Promise<boolean> {
    const serialized = JSON.stringify(StateSchema.parse(state));
    if (Buffer.byteLength(serialized, "utf8") > MAX_FILE_BYTES) throw new InvalidActorAuthenticationFileError();
    const temporaryPath = `${this.path}.${randomUUID()}.tmp`;
    try {
      const temporary = await open(temporaryPath, "wx", 0o600);
      try {
        await temporary.writeFile(serialized);
        await temporary.sync();
      } finally {
        await temporary.close();
      }
      if (!stillLive()) return false;
      await rename(temporaryPath, this.path);
      const directory = await open(dirname(this.path), "r");
      try {
        await directory.sync();
      } finally {
        await directory.close();
      }
      return stillLive();
    } finally {
      await rm(temporaryPath, { force: true });
    }
  }
}
