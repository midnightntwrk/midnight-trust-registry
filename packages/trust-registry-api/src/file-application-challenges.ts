import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { open, rename, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";

import { withExclusiveWorkspaceWrite, WorkspaceMutationLockedError } from "@midnight-ntwrk/trust-registry-cli";
import { z } from "zod";

import {
  ApplicationChallengeBindingConflictError,
  ApplicationChallengeCapacityError,
  ApplicationChallengeSubjectCapacityError,
  ApplicationChallengeClockError,
  ApplicationChallengeExpiryError,
  type ApplicationChallengeInsertResult,
  type ApplicationChallengeRecord,
  type ApplicationChallengeStore,
} from "./application-challenges.js";

const MAX_ENTRIES = 10_000;
const MAX_PER_SUBJECT = 32;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_TIMEOUT_MS = 2_147_483_647;
const LOCK_ATTEMPTS = 100;
const LOCK_RETRY_MS = 10;
const HashSchema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const TimestampSchema = z.number().int().safe().nonnegative();
const RecordSchema = z.object({
  challengeHash: HashSchema,
  bindingHash: HashSchema,
  applicationHash: HashSchema,
  subjectHash: HashSchema.optional(),
  issuedAtMs: TimestampSchema,
  expiresAtMs: TimestampSchema,
}).strict().refine((record) => record.expiresAtMs > record.issuedAtMs);
const StateSchema = z.object({
  version: z.literal(1),
  records: z.array(RecordSchema).max(MAX_ENTRIES),
}).strict().superRefine((state, context) => {
  const challenges = new Set<string>();
  const applications = new Set<string>();
  for (const [index, record] of state.records.entries()) {
    if (challenges.has(record.challengeHash) || applications.has(record.applicationHash)) {
      context.addIssue({ code: "custom", message: "Duplicate challenge or application", path: ["records", index] });
    }
    challenges.add(record.challengeHash);
    applications.add(record.applicationHash);
  }
});

export class InvalidApplicationChallengeFileError extends Error {
  constructor() {
    super("Application challenge file is invalid");
    this.name = "InvalidApplicationChallengeFileError";
  }
}

/** Local file adapter with fsync-backed replacement and cross-process write exclusion. */
export class FileApplicationChallengeStore implements ApplicationChallengeStore {
  private readonly path: string;

  constructor(path: string, private readonly maxEntries = MAX_ENTRIES,
    private readonly maxPerSubject = MAX_PER_SUBJECT) {
    if (path.length === 0) throw new RangeError("Application challenge path is invalid");
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > MAX_ENTRIES
      || !Number.isSafeInteger(maxPerSubject) || maxPerSubject < 1) {
      throw new RangeError("Application challenge store capacity is invalid");
    }
    this.path = resolve(path);
  }

  async insert(
    record: ApplicationChallengeRecord,
    nowMs: number,
    readNow: () => number = Date.now,
  ): Promise<ApplicationChallengeInsertResult> {
    this.assertClock(nowMs);
    if (!RecordSchema.safeParse(record).success) throw new InvalidApplicationChallengeFileError();
    const startedAt = performance.now();
    return this.withWrite(async () => {
      const observedNow = readNow();
      this.assertClock(observedNow);
      if (observedNow < nowMs) {
        throw new ApplicationChallengeClockError("Application challenge issuance time is invalid");
      }
      const currentNow = Math.max(observedNow, nowMs + Math.floor(performance.now() - startedAt));
      this.assertClock(currentNow);
      const state = await this.readState();
      if (record.issuedAtMs > currentNow) throw new ApplicationChallengeClockError("Application challenge issuance time is invalid");
      if (record.expiresAtMs <= currentNow) return { inserted: false, supersededPrevious: false };
      if (record.expiresAtMs - currentNow > MAX_TIMEOUT_MS) throw new ApplicationChallengeExpiryError();
      if (state.records.some((entry) => entry.issuedAtMs > currentNow)) {
        throw new ApplicationChallengeClockError("Application challenge clock precedes issuance");
      }
      const live = state.records.filter((entry) => entry.expiresAtMs > currentNow);
      if (live.some((entry) => entry.challengeHash === record.challengeHash)) {
        return { inserted: false, supersededPrevious: false };
      }
      const previous = live.find((entry) => entry.applicationHash === record.applicationHash);
      if (previous !== undefined && previous.bindingHash !== record.bindingHash) {
        throw new ApplicationChallengeBindingConflictError();
      }
      const remaining = live.filter((entry) => entry.applicationHash !== record.applicationHash);
      if (remaining.length >= this.maxEntries) throw new ApplicationChallengeCapacityError();
      if (record.subjectHash !== undefined
        && remaining.filter((entry) => entry.subjectHash === record.subjectHash).length >= this.maxPerSubject) {
        throw new ApplicationChallengeSubjectCapacityError();
      }
      await this.writeState({ version: 1, records: [...remaining, record] });
      return { inserted: true, supersededPrevious: previous !== undefined };
    });
  }

  async readLive(challengeHash: string, bindingHash: string, nowMs: number): Promise<ApplicationChallengeRecord | null> {
    this.assertClock(nowMs);
    if (!HashSchema.safeParse(challengeHash).success || !HashSchema.safeParse(bindingHash).success) return null;
    const record = (await this.readState()).records.find((entry) => entry.challengeHash === challengeHash);
    if (record === undefined) return null;
    if (nowMs < record.issuedAtMs) throw new ApplicationChallengeClockError("Application challenge clock precedes issuance");
    return nowMs < record.expiresAtMs && record.bindingHash === bindingHash ? { ...record } : null;
  }

  async consume(challengeHash: string, bindingHash: string, nowMs: number): Promise<boolean> {
    this.assertClock(nowMs);
    if (!HashSchema.safeParse(challengeHash).success || !HashSchema.safeParse(bindingHash).success) return false;
    const startedAt = performance.now();
    return this.withWrite(async () => {
      const currentNow = nowMs + Math.floor(performance.now() - startedAt);
      this.assertClock(currentNow);
      const state = await this.readState();
      const record = state.records.find((entry) => entry.challengeHash === challengeHash);
      if (record === undefined) return false;
      if (currentNow < record.issuedAtMs) throw new ApplicationChallengeClockError("Application challenge clock precedes issuance");
      if (currentNow >= record.expiresAtMs) {
        await this.writeState({ version: 1, records: state.records.filter((entry) => entry.challengeHash !== challengeHash) });
        return false;
      }
      if (record.bindingHash !== bindingHash) return false;
      await this.writeState({ version: 1, records: state.records.filter((entry) => entry.challengeHash !== challengeHash) });
      return true;
    });
  }

  private assertClock(nowMs: number): void {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new ApplicationChallengeClockError();
  }

  private async withWrite<T>(operation: () => Promise<T>): Promise<T> {
    const directoryIdentity = await this.directoryIdentity();
    for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
      try {
        return await withExclusiveWorkspaceWrite(this.path, async () => {
          const lockedIdentity = await this.directoryIdentity();
          if (lockedIdentity !== directoryIdentity) throw new InvalidApplicationChallengeFileError();
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
      throw new InvalidApplicationChallengeFileError();
    }
    try {
      const state = await directory.stat({ bigint: true });
      if (!state.isDirectory()) throw new InvalidApplicationChallengeFileError();
      return `${state.dev}:${state.ino}`;
    } finally {
      await directory.close();
    }
  }

  private async readState(): Promise<z.infer<typeof StateSchema>> {
    let handle;
    try {
      handle = await open(this.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { version: 1, records: [] };
      if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new InvalidApplicationChallengeFileError();
      throw error;
    }
    try {
      const before = await handle.stat({ bigint: true });
      if (!before.isFile() || before.nlink !== 1n || (before.mode & 0o077n) !== 0n
        || before.size === 0n || before.size > BigInt(MAX_FILE_BYTES)) {
        throw new InvalidApplicationChallengeFileError();
      }
      const raw = Buffer.alloc(Number(before.size));
      let offset = 0;
      while (offset < raw.length) {
        const { bytesRead } = await handle.read(raw, offset, raw.length - offset, offset);
        if (bytesRead === 0) throw new InvalidApplicationChallengeFileError();
        offset += bytesRead;
      }
      const after = await handle.stat({ bigint: true });
      if (BigInt(raw.length) !== before.size || after.dev !== before.dev || after.ino !== before.ino
        || after.size !== before.size || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs) {
        throw new InvalidApplicationChallengeFileError();
      }
      try {
        const parsed = StateSchema.parse(JSON.parse(raw.toString("utf8")));
        if (parsed.records.length > this.maxEntries) throw new InvalidApplicationChallengeFileError();
        return parsed;
      } catch {
        throw new InvalidApplicationChallengeFileError();
      }
    } finally {
      await handle.close();
    }
  }

  private async writeState(state: z.infer<typeof StateSchema>): Promise<void> {
    const directoryPath = dirname(this.path);
    const serialized = JSON.stringify(StateSchema.parse(state));
    if (Buffer.byteLength(serialized, "utf8") > MAX_FILE_BYTES) throw new InvalidApplicationChallengeFileError();
    const temporaryPath = `${this.path}.${randomUUID()}.tmp`;
    try {
      const temporary = await open(temporaryPath, "wx", 0o600);
      try {
        await temporary.writeFile(serialized);
        await temporary.sync();
      } finally {
        await temporary.close();
      }
      await rename(temporaryPath, this.path);
      const directory = await open(directoryPath, "r");
      try {
        await directory.sync();
      } finally {
        await directory.close();
      }
    } finally {
      await rm(temporaryPath, { force: true });
    }
  }
}
