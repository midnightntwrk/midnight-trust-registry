import { randomBytes } from "node:crypto";

import {
  ApplicationEvidenceRoleSchema,
  AuthorizationScopeSchema,
  computeAuthorizationScopeCommitment,
  DidSchema,
  HashHexSchema,
  ScopedIdentifierSchema,
  sha256Hex,
} from "@midnight-ntwrk/trust-registry-domain";
import { z } from "zod";

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const NONCE_BYTES = 32;
const MAX_COLLISION_ATTEMPTS = 3;
const MAX_IN_MEMORY_CHALLENGES = 10_000;
const MAX_TIMEOUT_MS = 2_147_483_647;
const HashSchema = HashHexSchema;
const NonceSchema = z.string().regex(/^0x[0-9a-f]{64}$/);
const CanonicalIdentifierSchema = ScopedIdentifierSchema.refine(
  (value) => value === value.toLowerCase(),
  "Challenge identifier must be canonical lowercase",
);

export const ApplicationChallengeBindingSchema = z.strictObject({
  registryId: CanonicalIdentifierSchema,
  applicationId: CanonicalIdentifierSchema,
  subjectDid: DidSchema.startsWith("did:midnight:"),
  evidenceVerifierDid: DidSchema,
  role: ApplicationEvidenceRoleSchema,
  policyId: CanonicalIdentifierSchema,
  policyVersion: z.string().regex(/^v[1-9][0-9]*$/u),
  scope: AuthorizationScopeSchema,
  scopeCommitment: HashSchema,
}).superRefine((binding, ctx) => {
  const scope = AuthorizationScopeSchema.safeParse(binding.scope);
  if (!scope.success) return;
  const commitment = HashSchema.safeParse(binding.scopeCommitment);
  if (!commitment.success) return;
  if (scope.data.role !== binding.role) {
    ctx.addIssue({ code: "custom", path: ["scope", "role"], message: "Scope role must match application role" });
  }
  if (scope.data.role === "maintainer" && scope.data.registryId !== binding.registryId) {
    ctx.addIssue({ code: "custom", path: ["scope", "registryId"], message: "Maintainer scope registry must match application registry" });
  }
  if (computeAuthorizationScopeCommitment(scope.data) !== commitment.data.toLowerCase()) {
    ctx.addIssue({ code: "custom", path: ["scopeCommitment"], message: "Scope commitment does not match canonical scope" });
  }
});

export type ApplicationChallengeBinding = z.infer<typeof ApplicationChallengeBindingSchema>;

export type ApplicationChallengeRecord = {
  challengeHash: string;
  bindingHash: string;
  expiresAtMs: number;
};

/** A production adapter must atomically replace the live challenge for a binding and check-and-delete on consume. */
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
  private readonly bindingHashes = new Map<string, string>();

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
    const previousHash = this.bindingHashes.get(record.bindingHash);
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
    this.bindingHashes.set(record.bindingHash, record.challengeHash);
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
    if (this.bindingHashes.get(current.record.bindingHash) === challengeHash) {
      this.bindingHashes.delete(current.record.bindingHash);
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
    const bindingHash = hashBinding(binding);

    for (let attempt = 0; attempt < MAX_COLLISION_ATTEMPTS; attempt += 1) {
      const nonceBytes = randomBytes(NONCE_BYTES);
      const challengeHash = sha256Hex(nonceBytes);
      if (await this.store.insert({ challengeHash, bindingHash, expiresAtMs }, issuedAtMs)) {
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
    if (!NonceSchema.safeParse(input.nonce).success) return null;
    if (!HashSchema.safeParse(input.challengeHash).success) return null;

    const challengeHash = sha256Hex(Buffer.from(input.nonce.slice(2), "hex"));
    if (challengeHash !== input.challengeHash.toLowerCase()) return null;
    return await this.store.consume(challengeHash, hashBinding(parsedBinding.data), this.now())
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
    binding.scopeCommitment.toLowerCase(),
  ]));
}
