import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, rename, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";

import { withExclusiveWorkspaceWrite, WorkspaceMutationLockedError } from "@midnight-ntwrk/trust-registry-cli";
import { sha256Hex } from "@midnight-ntwrk/trust-registry-domain";
import { z } from "zod";

import {
  ApplicationChallengeBindingConflictError,
  ApplicationChallengeCapacityError,
  ApplicationChallengeClockError,
  ApplicationChallengeExpiryError,
  type ApplicationChallengeInsertResult,
  type ApplicationChallengeRecord,
  type ApplicationChallengeStore,
} from "./application-challenges.js";
import { recognitionAuthorityChallengeIdentityHash } from "./recognition-authority-challenges.js";

const MAX_ENTRIES = 10_000;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_TIMEOUT_MS = 2_147_483_647;
const LOCK_ATTEMPTS = 100;
const LOCK_RETRY_MS = 10;
const HashSchema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const TimestampSchema = z.number().int().safe().nonnegative();
const ChallengeSchema = z.strictObject({
  challengeHash: HashSchema,
  bindingHash: HashSchema,
  applicationHash: HashSchema,
  issuedAtMs: TimestampSchema,
  expiresAtMs: TimestampSchema,
}).refine((record) => record.expiresAtMs > record.issuedAtMs);

export const RecognitionAdmissionReceiptSchema = z.strictObject({
  receiptId: HashSchema,
  recognitionId: z.string().trim().min(1).max(256),
  applicationHash: HashSchema,
  challengeHash: HashSchema,
  bindingHash: HashSchema,
  policyCommitment: HashSchema,
  anchorCommitment: HashSchema,
  evidenceCommitment: HashSchema,
  acceptedAtMs: TimestampSchema,
  expiresAtMs: TimestampSchema,
}).refine((receipt) => receipt.expiresAtMs > receipt.acceptedAtMs);
export type RecognitionAdmissionReceipt = z.infer<typeof RecognitionAdmissionReceiptSchema>;
export type RecognitionAdmissionInput = {
  targetRegistryId: string;
  recognitionId: string;
  challengeHash: string;
  bindingHash: string;
  policyCommitment: string;
  anchorCommitment: string;
  evidenceCommitment: string;
  expiresAtMs: number;
  nowMs: number;
  /** Must read the policy under the same workspace lock used by governance mutations. */
  assertCurrentGovernance: () => Promise<void>;
};
export interface RecognitionAdmissionStore extends ApplicationChallengeStore {
  accept(input: RecognitionAdmissionInput): Promise<RecognitionAdmissionReceipt | null>;
  readAccepted(recognitionId: string): Promise<RecognitionAdmissionReceipt | null>;
}

const receiptId = (receipt: Omit<RecognitionAdmissionReceipt, "receiptId">): string => sha256Hex(JSON.stringify([
  "tr:recognition:admission-receipt:v1",
  receipt.recognitionId,
  receipt.applicationHash,
  receipt.challengeHash,
  receipt.bindingHash,
  receipt.policyCommitment,
  receipt.anchorCommitment,
  receipt.evidenceCommitment,
  receipt.acceptedAtMs,
  receipt.expiresAtMs,
]));

const StateSchema = z.strictObject({
  version: z.literal(1),
  challenges: z.array(ChallengeSchema).max(MAX_ENTRIES),
  accepted: z.array(RecognitionAdmissionReceiptSchema).max(MAX_ENTRIES),
}).superRefine((state, context) => {
  const challengeHashes = new Set<string>();
  const applicationHashes = new Set<string>();
  for (const [index, challenge] of state.challenges.entries()) {
    if (challengeHashes.has(challenge.challengeHash) || applicationHashes.has(challenge.applicationHash)) {
      context.addIssue({ code: "custom", message: "Duplicate recognition challenge", path: ["challenges", index] });
    }
    challengeHashes.add(challenge.challengeHash);
    applicationHashes.add(challenge.applicationHash);
  }
  const recognitionIds = new Set<string>();
  for (const [index, receipt] of state.accepted.entries()) {
    if (recognitionIds.has(receipt.recognitionId) || challengeHashes.has(receipt.challengeHash)
      || applicationHashes.has(receipt.applicationHash)
      || receipt.receiptId !== receiptId(receipt)) {
      context.addIssue({ code: "custom", message: "Invalid recognition admission", path: ["accepted", index] });
    }
    recognitionIds.add(receipt.recognitionId);
    challengeHashes.add(receipt.challengeHash);
    applicationHashes.add(receipt.applicationHash);
  }
});

type State = z.infer<typeof StateSchema>;
const emptyState = (): State => ({ version: 1, challenges: [], accepted: [] });

export class InvalidRecognitionAdmissionFileError extends Error {
  constructor() {
    super("Recognition admission file is invalid");
    this.name = "InvalidRecognitionAdmissionFileError";
  }
}

/** A local reference store; the governance lock path must be the same one used by policy mutations. */
export class FileRecognitionAdmissionStore implements RecognitionAdmissionStore {
  private readonly path: string;
  private readonly governanceWorkspacePath: string;

  constructor(path: string, governanceWorkspacePath: string, private readonly maxEntries = MAX_ENTRIES) {
    if (path.length === 0 || governanceWorkspacePath.length === 0) {
      throw new RangeError("Recognition admission and governance paths are required");
    }
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > MAX_ENTRIES) {
      throw new RangeError("Recognition admission capacity is invalid");
    }
    this.path = resolve(path);
    this.governanceWorkspacePath = resolve(governanceWorkspacePath);
    if (this.path === this.governanceWorkspacePath) throw new RangeError("Recognition admission must use a separate file");
  }

  async insert(record: ApplicationChallengeRecord, nowMs: number, readNow: () => number = Date.now): Promise<ApplicationChallengeInsertResult> {
    this.assertClock(nowMs);
    if (!ChallengeSchema.safeParse(record).success) throw new InvalidRecognitionAdmissionFileError();
    const startedAt = performance.now();
    return this.withWrite(this.path, async () => {
      const observedNow = readNow();
      this.assertClock(observedNow);
      if (observedNow < nowMs) throw new ApplicationChallengeClockError("Recognition challenge issuance time is invalid");
      const currentNow = Math.max(observedNow, nowMs + Math.floor(performance.now() - startedAt));
      this.assertClock(currentNow);
      const state = await this.readState();
      if (record.issuedAtMs > currentNow) throw new ApplicationChallengeClockError("Recognition challenge issuance time is invalid");
      if (record.expiresAtMs <= currentNow) return { inserted: false, supersededPrevious: false };
      if (record.expiresAtMs - currentNow > MAX_TIMEOUT_MS) throw new ApplicationChallengeExpiryError();
      if (state.accepted.some((receipt) => receipt.applicationHash === record.applicationHash)) {
        throw new Error("Recognition has already been admitted");
      }
      const live = state.challenges.filter((challenge) => challenge.expiresAtMs > currentNow);
      if (live.some((challenge) => challenge.challengeHash === record.challengeHash)
        || state.accepted.some((receipt) => receipt.challengeHash === record.challengeHash)) {
        return { inserted: false, supersededPrevious: false };
      }
      const previous = live.find((challenge) => challenge.applicationHash === record.applicationHash);
      if (previous !== undefined && previous.bindingHash !== record.bindingHash) {
        throw new ApplicationChallengeBindingConflictError();
      }
      const remaining = live.filter((challenge) => challenge.applicationHash !== record.applicationHash);
      if (remaining.length >= this.maxEntries) throw new ApplicationChallengeCapacityError();
      await this.writeState({ ...state, challenges: [...remaining, record] });
      return { inserted: true, supersededPrevious: previous !== undefined };
    });
  }

  async readLive(challengeHash: string, bindingHash: string, nowMs: number): Promise<ApplicationChallengeRecord | null> {
    this.assertClock(nowMs);
    if (!HashSchema.safeParse(challengeHash).success || !HashSchema.safeParse(bindingHash).success) return null;
    const record = (await this.readState()).challenges.find((challenge) => challenge.challengeHash === challengeHash);
    if (record === undefined) return null;
    if (nowMs < record.issuedAtMs) throw new ApplicationChallengeClockError("Recognition challenge clock precedes issuance");
    return nowMs < record.expiresAtMs && record.bindingHash === bindingHash ? { ...record } : null;
  }

  async consume(challengeHash: string, bindingHash: string, nowMs: number): Promise<boolean> {
    this.assertClock(nowMs);
    if (!HashSchema.safeParse(challengeHash).success || !HashSchema.safeParse(bindingHash).success) return false;
    const startedAt = performance.now();
    return this.withWrite(this.path, async () => {
      const currentNow = nowMs + Math.floor(performance.now() - startedAt);
      this.assertClock(currentNow);
      const state = await this.readState();
      const record = state.challenges.find((challenge) => challenge.challengeHash === challengeHash);
      if (record === undefined || record.bindingHash !== bindingHash) return false;
      if (currentNow < record.issuedAtMs) throw new ApplicationChallengeClockError("Recognition challenge clock precedes issuance");
      if (currentNow >= record.expiresAtMs) return false;
      await this.writeState({ ...state, challenges: state.challenges.filter((challenge) => challenge !== record) });
      return true;
    });
  }

  async accept(input: RecognitionAdmissionInput): Promise<RecognitionAdmissionReceipt | null> {
    this.assertClock(input.nowMs);
    const startedAt = performance.now();
    return this.withWrite(this.governanceWorkspacePath, () => this.withWrite(this.path, async () => {
      const nowMs = input.nowMs + Math.floor(performance.now() - startedAt);
      this.assertClock(nowMs);
      const state = await this.readState();
      const challenge = state.challenges.find((record) => record.challengeHash === input.challengeHash);
      if (challenge === undefined || challenge.bindingHash !== input.bindingHash
        || challenge.applicationHash !== recognitionAuthorityChallengeIdentityHash({
          targetRegistryId: input.targetRegistryId,
          recognitionId: input.recognitionId,
        })
        || nowMs < challenge.issuedAtMs || nowMs >= challenge.expiresAtMs
        || state.accepted.some((receipt) => receipt.applicationHash === challenge.applicationHash)) return null;
      await input.assertCurrentGovernance();
      const acceptedAtMs = input.nowMs + Math.floor(performance.now() - startedAt);
      if (acceptedAtMs >= challenge.expiresAtMs || acceptedAtMs >= input.expiresAtMs) return null;
      const receipt = RecognitionAdmissionReceiptSchema.parse({
        receiptId: receiptId({
          recognitionId: input.recognitionId,
          applicationHash: challenge.applicationHash,
          challengeHash: challenge.challengeHash,
          bindingHash: challenge.bindingHash,
          policyCommitment: input.policyCommitment,
          anchorCommitment: input.anchorCommitment,
          evidenceCommitment: input.evidenceCommitment,
          acceptedAtMs,
          expiresAtMs: input.expiresAtMs,
        }),
        recognitionId: input.recognitionId,
        applicationHash: challenge.applicationHash,
        challengeHash: challenge.challengeHash,
        bindingHash: challenge.bindingHash,
        policyCommitment: input.policyCommitment,
        anchorCommitment: input.anchorCommitment,
        evidenceCommitment: input.evidenceCommitment,
        acceptedAtMs,
        expiresAtMs: input.expiresAtMs,
      });
      await this.writeState(StateSchema.parse({
        ...state,
        challenges: state.challenges.filter((record) => record !== challenge),
        accepted: [...state.accepted, receipt],
      }));
      return structuredClone(receipt);
    }));
  }

  async readAccepted(recognitionId: string): Promise<RecognitionAdmissionReceipt | null> {
    const receipt = (await this.readState()).accepted.find((entry) => entry.recognitionId === recognitionId);
    return receipt === undefined ? null : structuredClone(receipt);
  }

  private assertClock(nowMs: number): void {
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new ApplicationChallengeClockError();
  }

  private async withWrite<T>(path: string, operation: () => Promise<T>): Promise<T> {
    for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
      try {
        return await withExclusiveWorkspaceWrite(path, operation);
      } catch (error) {
        if (!(error instanceof WorkspaceMutationLockedError) || attempt === LOCK_ATTEMPTS - 1) throw error;
        await delay(LOCK_RETRY_MS);
      }
    }
    throw new WorkspaceMutationLockedError();
  }

  private async readState(): Promise<State> {
    let handle;
    try {
      handle = await open(this.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return emptyState();
      if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new InvalidRecognitionAdmissionFileError();
      throw error;
    }
    try {
      const info = await handle.stat({ bigint: true });
      if (!info.isFile() || info.nlink !== 1n || (info.mode & 0o077n) !== 0n
        || info.size === 0n || info.size > BigInt(MAX_FILE_BYTES)) {
        throw new InvalidRecognitionAdmissionFileError();
      }
      const raw = Buffer.alloc(Number(info.size));
      let offset = 0;
      while (offset < raw.length) {
        const { bytesRead } = await handle.read(raw, offset, raw.length - offset, offset);
        if (bytesRead === 0) throw new InvalidRecognitionAdmissionFileError();
        offset += bytesRead;
      }
      const after = await handle.stat({ bigint: true });
      if (BigInt(raw.length) !== info.size || after.dev !== info.dev || after.ino !== info.ino
        || after.size !== info.size || after.mtimeNs !== info.mtimeNs || after.ctimeNs !== info.ctimeNs) {
        throw new InvalidRecognitionAdmissionFileError();
      }
      try {
        const state = StateSchema.parse(JSON.parse(raw.toString("utf8")));
        if (state.challenges.length > this.maxEntries || state.accepted.length > this.maxEntries) {
          throw new InvalidRecognitionAdmissionFileError();
        }
        return state;
      } catch {
        throw new InvalidRecognitionAdmissionFileError();
      }
    } finally {
      await handle.close();
    }
  }

  private async writeState(state: State): Promise<void> {
    const serialized = JSON.stringify(StateSchema.parse(state));
    if (Buffer.byteLength(serialized, "utf8") > MAX_FILE_BYTES) throw new InvalidRecognitionAdmissionFileError();
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const temporaryPath = `${this.path}.${randomUUID()}.tmp`;
    try {
      const handle = await open(temporaryPath, "wx", 0o600);
      try {
        await handle.writeFile(serialized);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(temporaryPath, this.path);
      const directory = await open(dirname(this.path), "r");
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
