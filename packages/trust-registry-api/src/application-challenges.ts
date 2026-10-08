import { randomBytes } from "node:crypto";

import {
  ApplicationChallengeBindingSchema,
  HashHexSchema,
  computeApplicationChallengeBindingHash,
  sha256Hex,
  type ApplicationChallengeBinding,
} from "@midnight-ntwrk/trust-registry-domain";
import { z } from "zod";

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const NONCE_BYTES = 32;
const MAX_COLLISION_ATTEMPTS = 3;
const MAX_IN_MEMORY_CHALLENGES = 10_000;
const MAX_TIMEOUT_MS = 2_147_483_647;
const HashSchema = HashHexSchema;
const NonceSchema = z.string().regex(/^0x[0-9a-f]{64}$/);
export { ApplicationChallengeBindingSchema };
export type { ApplicationChallengeBinding };

/** Syntax and digest check only; the store remains authoritative for liveness and one-time use. */
export function hasMatchingApplicationChallengeHash(nonce: string, challengeHash: string): boolean {
  return NonceSchema.safeParse(nonce).success &&
    HashSchema.safeParse(challengeHash).success &&
    sha256Hex(Buffer.from(nonce.slice(2), "hex")) === challengeHash.toLowerCase();
}

export type ApplicationChallengeRecord = {
  challengeHash: string;
  bindingHash: string;
  applicationHash: string;
  issuedAtMs: number;
  expiresAtMs: number;
};

export type ApplicationChallengeInsertResult = {
  inserted: boolean;
  supersededPrevious: boolean;
};

/** A production adapter must atomically replace per application and check-and-delete on consume. */
export interface ApplicationChallengeStore {
  insert(record: ApplicationChallengeRecord, nowMs: number, readNow: () => number): Promise<ApplicationChallengeInsertResult>;
  readLive(challengeHash: string, bindingHash: string, nowMs: number): Promise<ApplicationChallengeRecord | null>;
  consume(challengeHash: string, bindingHash: string, nowMs: number): Promise<boolean>;
}

export class ApplicationChallengeCapacityError extends Error {
  readonly code = "CHALLENGE_CAPACITY";
  constructor() {
    super("Application challenge store is at capacity");
    this.name = "ApplicationChallengeCapacityError";
  }
}

export class ApplicationChallengeClockError extends RangeError {
  readonly code = "CHALLENGE_CLOCK_INVALID";
  constructor() {
    super("Application challenge clock is invalid");
    this.name = "ApplicationChallengeClockError";
  }
}

export class ApplicationChallengeExpiryError extends RangeError {
  readonly code = "CHALLENGE_EXPIRY_RANGE";
  constructor() {
    super("Application challenge expiry is outside the timer range");
    this.name = "ApplicationChallengeExpiryError";
  }
}

export class ApplicationChallengeCollisionError extends Error {
  readonly code = "CHALLENGE_COLLISION";
  constructor() {
    super("Could not issue an application challenge");
    this.name = "ApplicationChallengeCollisionError";
  }
}

export class ApplicationChallengeBindingConflictError extends Error {
  readonly code = "CHALLENGE_BINDING_CONFLICT";
  constructor() {
    super("A different challenge binding is already live for this application");
    this.name = "ApplicationChallengeBindingConflictError";
  }
}

/** Process-local reference adapter with bounded capacity and idle expiry. */
export class InMemoryApplicationChallengeStore implements ApplicationChallengeStore {
  private readonly records = new Map<string, { record: ApplicationChallengeRecord; timer: NodeJS.Timeout }>();
  private readonly applicationHashes = new Map<string, string>();

  constructor(private readonly maxEntries = MAX_IN_MEMORY_CHALLENGES) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new RangeError("Application challenge store capacity is invalid");
    }
  }

  async insert(record: ApplicationChallengeRecord, nowMs: number, readNow: () => number = Date.now): Promise<ApplicationChallengeInsertResult> {
    if (!Number.isSafeInteger(record.issuedAtMs) || record.issuedAtMs < 0 || record.issuedAtMs > nowMs) {
      throw new RangeError("Application challenge issuance time is invalid");
    }
    if (record.expiresAtMs <= nowMs) return { inserted: false, supersededPrevious: false };
    const delayMs = record.expiresAtMs - nowMs;
    if (!Number.isSafeInteger(delayMs) || delayMs > MAX_TIMEOUT_MS) {
      throw new ApplicationChallengeExpiryError();
    }
    const existing = this.records.get(record.challengeHash);
    if (existing !== undefined) {
      if (nowMs < existing.record.expiresAtMs) return { inserted: false, supersededPrevious: false };
      this.remove(record.challengeHash);
    }
    const previousHash = this.applicationHashes.get(record.applicationHash);
    const previous = previousHash === undefined ? undefined : this.records.get(previousHash);
    if (previous !== undefined && nowMs < previous.record.expiresAtMs && previous.record.bindingHash !== record.bindingHash) {
      throw new ApplicationChallengeBindingConflictError();
    }
    const supersededPrevious = previous !== undefined && nowMs < previous.record.expiresAtMs;
    if (previousHash !== undefined) this.remove(previousHash);
    if (this.records.size >= this.maxEntries) {
      for (const [hash, current] of this.records) {
        if (nowMs >= current.record.expiresAtMs) this.remove(hash);
      }
      if (this.records.size >= this.maxEntries) throw new ApplicationChallengeCapacityError();
    }
    const saved = Object.freeze({ ...record });
    const entry = { record: saved, timer: undefined as unknown as NodeJS.Timeout };
    this.records.set(saved.challengeHash, entry);
    this.scheduleExpiry(saved.challengeHash, entry, delayMs, readNow);
    this.applicationHashes.set(record.applicationHash, record.challengeHash);
    return { inserted: true, supersededPrevious };
  }

  async consume(challengeHash: string, bindingHash: string, nowMs: number): Promise<boolean> {
    const current = this.records.get(challengeHash);
    if (current === undefined) return false;
    if (nowMs < current.record.issuedAtMs) throw new RangeError("Application challenge clock precedes issuance");
    if (nowMs >= current.record.expiresAtMs) {
      this.remove(challengeHash);
      return false;
    }
    if (current.record.bindingHash !== bindingHash) return false;
    this.remove(challengeHash);
    return true;
  }

  async readLive(challengeHash: string, bindingHash: string, nowMs: number): Promise<ApplicationChallengeRecord | null> {
    const current = this.records.get(challengeHash);
    if (current === undefined) return null;
    if (nowMs < current.record.issuedAtMs) throw new RangeError("Application challenge clock precedes issuance");
    if (nowMs >= current.record.expiresAtMs) {
      this.remove(challengeHash);
      return null;
    }
    return current.record.bindingHash === bindingHash ? { ...current.record } : null;
  }

  private remove(challengeHash: string): void {
    const current = this.records.get(challengeHash);
    if (current === undefined) return;
    clearTimeout(current.timer);
    this.records.delete(challengeHash);
    if (this.applicationHashes.get(current.record.applicationHash) === challengeHash) {
      this.applicationHashes.delete(current.record.applicationHash);
    }
  }

  private scheduleExpiry(
    challengeHash: string,
    entry: { record: ApplicationChallengeRecord; timer: NodeJS.Timeout },
    delayMs: number,
    readNow: () => number,
  ): void {
    entry.timer = setTimeout(() => {
      if (this.records.get(challengeHash) !== entry) return;
      let remainingMs: number;
      try {
        remainingMs = entry.record.expiresAtMs - readNow();
      } catch {
        remainingMs = 1000;
      }
      if (!Number.isFinite(remainingMs)) remainingMs = 1000;
      if (remainingMs <= 0) {
        this.remove(challengeHash);
      } else {
        this.scheduleExpiry(challengeHash, entry, Math.max(1000, Math.min(MAX_TIMEOUT_MS, remainingMs)), readNow);
      }
    }, delayMs);
    entry.timer.unref();
  }
}

export type IssuedApplicationChallenge = {
  nonce: string;
  challengeHash: string;
  issuedAt: string;
  expiresAt: string;
  supersededPrevious: boolean;
};

export class ApplicationChallengeService {
  constructor(
    private readonly store: ApplicationChallengeStore,
    private readonly clock: () => number = Date.now,
  ) {}

  async issue(bindingInput: ApplicationChallengeBinding): Promise<IssuedApplicationChallenge> {
    const binding = ApplicationChallengeBindingSchema.parse(bindingInput);
    const issuedAtMs = this.now();
    const expiresAtMs = issuedAtMs + CHALLENGE_TTL_MS;
    const bindingHash = computeApplicationChallengeBindingHash(binding);
    const applicationHash = sha256Hex(JSON.stringify([
      "tr:application:identity:v1",
      binding.registryId,
      binding.applicationId,
    ]));

    for (let attempt = 0; attempt < MAX_COLLISION_ATTEMPTS; attempt += 1) {
      const nonceBytes = randomBytes(NONCE_BYTES);
      const challengeHash = sha256Hex(nonceBytes);
      const result = await this.store.insert(
        { challengeHash, bindingHash, applicationHash, issuedAtMs, expiresAtMs },
        issuedAtMs,
        () => this.now(),
      );
      if (result.inserted) {
        return {
          nonce: `0x${nonceBytes.toString("hex")}`,
          challengeHash,
          issuedAt: new Date(issuedAtMs).toISOString(),
          expiresAt: new Date(expiresAtMs).toISOString(),
          supersededPrevious: result.supersededPrevious,
        };
      }
    }
    throw new ApplicationChallengeCollisionError();
  }

  /** Call only after the VP challenge has been verified against the returned nonce. */
  async consume(input: {
    binding: ApplicationChallengeBinding;
    nonce: string;
    challengeHash: string;
  }): Promise<string | null> {
    const parsedBinding = ApplicationChallengeBindingSchema.safeParse(input.binding);
    if (!parsedBinding.success) return null;
    if (!hasMatchingApplicationChallengeHash(input.nonce, input.challengeHash)) return null;
    const challengeHash = input.challengeHash.toLowerCase();
    return await this.store.consume(challengeHash, computeApplicationChallengeBindingHash(parsedBinding.data), this.now())
      ? challengeHash
      : null;
  }

  /** Advisory preflight only; consume remains the atomic replay boundary. */
  async isLive(input: {
    binding: ApplicationChallengeBinding;
    nonce: string;
    challengeHash: string;
  }): Promise<boolean> {
    return (await this.liveWindow(input)) !== null;
  }

  /** Advisory preflight; the returned window comes from the store, not the caller. */
  async liveWindow(input: {
    binding: ApplicationChallengeBinding;
    nonce: string;
    challengeHash: string;
  }): Promise<{ issuedAtMs: number; expiresAtMs: number } | null> {
    const parsedBinding = ApplicationChallengeBindingSchema.safeParse(input.binding);
    if (!parsedBinding.success || !hasMatchingApplicationChallengeHash(input.nonce, input.challengeHash)) return null;
    const record = await this.store.readLive(
      input.challengeHash.toLowerCase(),
      computeApplicationChallengeBindingHash(parsedBinding.data),
      this.now(),
    );
    return record === null ? null : { issuedAtMs: record.issuedAtMs, expiresAtMs: record.expiresAtMs };
  }

  private now(): number {
    const value = this.clock();
    if (!Number.isSafeInteger(value) || value < 0 || value > Date.parse("9999-12-31T23:54:59.999Z")) {
      throw new ApplicationChallengeClockError();
    }
    return value;
  }
}
