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
  expiresAtMs: number;
};

/** A production adapter must atomically replace the live challenge for an application and check-and-delete on consume. */
export interface ApplicationChallengeStore {
  insert(record: ApplicationChallengeRecord, nowMs: number): Promise<boolean>;
  consume(challengeHash: string, bindingHash: string, nowMs: number): Promise<boolean>;
}

export class ApplicationChallengeCapacityError extends Error {
  constructor() {
    super("Application challenge store is at capacity");
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

  async insert(record: ApplicationChallengeRecord, nowMs: number): Promise<boolean> {
    if (record.expiresAtMs <= nowMs) return false;
    const delayMs = record.expiresAtMs - nowMs;
    if (!Number.isSafeInteger(delayMs) || delayMs > MAX_TIMEOUT_MS) {
      throw new RangeError("Application challenge expiry is outside the timer range");
    }
    const existing = this.records.get(record.challengeHash);
    if (existing !== undefined) {
      if (nowMs < existing.record.expiresAtMs) return false;
      this.remove(record.challengeHash);
    }
    const previousHash = this.applicationHashes.get(record.applicationHash);
    if (previousHash !== undefined) this.remove(previousHash);
    if (this.records.size >= this.maxEntries) {
      for (const [hash, current] of this.records) {
        if (nowMs >= current.record.expiresAtMs) this.remove(hash);
      }
      if (this.records.size >= this.maxEntries) throw new ApplicationChallengeCapacityError();
    }
    const timer = setTimeout(() => {
      if (this.records.get(record.challengeHash)?.record === record) {
        this.remove(record.challengeHash);
      }
    }, delayMs);
    timer.unref();
    this.records.set(record.challengeHash, { record, timer });
    this.applicationHashes.set(record.applicationHash, record.challengeHash);
    return true;
  }

  async consume(challengeHash: string, bindingHash: string, nowMs: number): Promise<boolean> {
    const current = this.records.get(challengeHash);
    if (current === undefined) return false;
    if (nowMs >= current.record.expiresAtMs) {
      this.remove(challengeHash);
      return false;
    }
    if (current.record.bindingHash !== bindingHash) return false;
    this.remove(challengeHash);
    return true;
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
}

export type IssuedApplicationChallenge = {
  nonce: string;
  challengeHash: string;
  issuedAt: string;
  expiresAt: string;
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
      if (await this.store.insert({ challengeHash, bindingHash, applicationHash, expiresAtMs }, issuedAtMs)) {
        return {
          nonce: `0x${nonceBytes.toString("hex")}`,
          challengeHash,
          issuedAt: new Date(issuedAtMs).toISOString(),
          expiresAt: new Date(expiresAtMs).toISOString(),
        };
      }
    }
    throw new Error("Could not issue an application challenge");
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

  private now(): number {
    const value = this.clock();
    if (!Number.isSafeInteger(value) || value < 0 || value > Date.parse("9999-12-31T23:54:59.999Z")) {
      throw new RangeError("Application challenge clock is invalid");
    }
    return value;
  }
}
