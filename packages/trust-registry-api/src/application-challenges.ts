import { randomBytes } from "node:crypto";

import {
  ApplicationEvidenceRoleSchema,
  DidSchema,
  HashHexSchema,
  ScopedIdentifierSchema,
  sha256Hex,
} from "@midnight-ntwrk/trust-registry-domain";
import { z } from "zod";

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const NONCE_BYTES = 32;
const MAX_COLLISION_ATTEMPTS = 3;
const CanonicalHashSchema = HashHexSchema.regex(/^0x[0-9a-f]{64}$/);
const NonceSchema = z.string().regex(/^0x[0-9a-f]{64}$/);

export const ApplicationChallengeBindingSchema = z.strictObject({
  registryId: ScopedIdentifierSchema,
  applicationId: ScopedIdentifierSchema,
  subjectDid: DidSchema.startsWith("did:midnight:"),
  evidenceVerifierDid: DidSchema.startsWith("did:midnight:"),
  role: ApplicationEvidenceRoleSchema,
  policyId: ScopedIdentifierSchema,
  policyVersion: z.string().regex(/^v[1-9][0-9]*$/u),
  scopeCommitment: CanonicalHashSchema,
});

export type ApplicationChallengeBinding = z.infer<typeof ApplicationChallengeBindingSchema>;

export type ApplicationChallengeRecord = {
  challengeHash: string;
  bindingHash: string;
  expiresAtMs: number;
};

/** A production adapter must make insert-if-absent and check-and-delete atomic. */
export interface ApplicationChallengeStore {
  insert(record: ApplicationChallengeRecord): Promise<boolean>;
  consume(challengeHash: string, bindingHash: string, nowMs: number): Promise<boolean>;
}

/** Process-local reference adapter only; it does not survive restarts or span replicas. */
export class InMemoryApplicationChallengeStore implements ApplicationChallengeStore {
  private readonly records = new Map<string, ApplicationChallengeRecord>();

  async insert(record: ApplicationChallengeRecord): Promise<boolean> {
    if (this.records.has(record.challengeHash)) return false;
    this.records.set(record.challengeHash, record);
    return true;
  }

  async consume(challengeHash: string, bindingHash: string, nowMs: number): Promise<boolean> {
    const record = this.records.get(challengeHash);
    if (record === undefined) return false;
    if (nowMs >= record.expiresAtMs) {
      this.records.delete(challengeHash);
      return false;
    }
    if (record.bindingHash !== bindingHash) return false;
    this.records.delete(challengeHash);
    return true;
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
    const bindingHash = hashBinding(binding);

    for (let attempt = 0; attempt < MAX_COLLISION_ATTEMPTS; attempt += 1) {
      const nonceBytes = randomBytes(NONCE_BYTES);
      const challengeHash = sha256Hex(nonceBytes);
      if (await this.store.insert({ challengeHash, bindingHash, expiresAtMs })) {
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
  }): Promise<boolean> {
    const parsedBinding = ApplicationChallengeBindingSchema.safeParse(input.binding);
    if (!parsedBinding.success) return false;
    if (!NonceSchema.safeParse(input.nonce).success) return false;
    if (!CanonicalHashSchema.safeParse(input.challengeHash).success) return false;

    const challengeHash = sha256Hex(Buffer.from(input.nonce.slice(2), "hex"));
    if (challengeHash !== input.challengeHash) return false;
    return this.store.consume(challengeHash, hashBinding(parsedBinding.data), this.now());
  }

  private now(): number {
    const value = this.clock();
    if (!Number.isSafeInteger(value) || value < 0 || value > Date.parse("9999-12-31T23:54:59.999Z")) {
      throw new RangeError("Application challenge clock is invalid");
    }
    return value;
  }
}

function hashBinding(binding: ApplicationChallengeBinding): string {
  return sha256Hex(JSON.stringify([
    "tr:application:challenge:v1",
    binding.registryId,
    binding.applicationId,
    binding.subjectDid,
    binding.evidenceVerifierDid,
    binding.role,
    binding.policyId,
    binding.policyVersion,
    binding.scopeCommitment,
  ]));
}
