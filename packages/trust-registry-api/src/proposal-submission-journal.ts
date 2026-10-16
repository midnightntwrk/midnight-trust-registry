import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, rename, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { withExclusiveWorkspaceWrite, WorkspaceMutationLockedError } from "@midnight-ntwrk/trust-registry-cli";
import { z } from "zod";

import { GovernedMembershipActionReceiptSchema, type GovernedMembershipActionReceipt } from "./governed-membership-actions.js";
import { GovernedProposalObservationSchema, type GovernedProposalObservation } from "./governed-proposal-observation.js";

const MAX_ENTRIES = 10_000;
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const Bytes32Schema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const ProposalRoleSchema = z.enum(["issuer", "verifier", "auditor", "maintainer"]);
const AttemptSchema = z.strictObject({
  role: ProposalRoleSchema,
  authorizationId: z.string().trim().min(1).max(256),
  evidenceCommitment: Bytes32Schema,
  state: z.enum(["reserved", "submitted", "observed"]),
  eventHash: Bytes32Schema.nullable(),
}).refine((attempt) => (attempt.state === "reserved") === (attempt.eventHash === null));
const StateSchema = z.strictObject({
  version: z.literal(1),
  attempts: z.array(AttemptSchema).max(MAX_ENTRIES),
}).superRefine((state, context) => {
  const keys = new Set<string>();
  for (const [index, attempt] of state.attempts.entries()) {
    const key = `${attempt.role}\0${attempt.authorizationId}`;
    if (keys.has(key)) context.addIssue({ code: "custom", path: ["attempts", index], message: "Duplicate proposal attempt" });
    keys.add(key);
  }
});

export type GovernedProposalSubmissionRole = z.infer<typeof ProposalRoleSchema>;
export type ProposalSubmissionAttempt = z.infer<typeof AttemptSchema>;
type JournalState = z.infer<typeof StateSchema>;
const emptyState = (): JournalState => ({ version: 1, attempts: [] });

export class InvalidProposalSubmissionJournalError extends Error {
  constructor() {
    super("Proposal submission journal is invalid");
    this.name = "InvalidProposalSubmissionJournalError";
  }
}

export class ProposalSubmissionAlreadyPendingError extends Error {
  constructor(readonly state: ProposalSubmissionAttempt["state"]) {
    super("Proposal submission already has an unresolved or observed attempt");
    this.name = "ProposalSubmissionAlreadyPendingError";
  }
}

export class ProposalSubmissionConflictError extends Error {
  constructor() {
    super("Proposal submission conflicts with recorded evidence or event");
    this.name = "ProposalSubmissionConflictError";
  }
}

export class ProposalSubmissionCapacityError extends Error {
  constructor() {
    super("Proposal submission journal capacity is exhausted; operator rotation is required");
    this.name = "ProposalSubmissionCapacityError";
  }
}

export class ProposalSubmissionOutcomeUnknownError extends Error {
  constructor(cause: unknown) {
    super("Proposal may have reached Compact; reconcile before any further action", { cause });
    this.name = "ProposalSubmissionOutcomeUnknownError";
  }
}

/** Reservation survives a lost Compact response; only an independently finalized reader can confirm observation. */
export interface ProposalSubmissionJournal {
  executeOnce(
    role: GovernedProposalSubmissionRole,
    authorizationId: string,
    evidenceCommitment: string,
    execute: () => Promise<GovernedMembershipActionReceipt>,
  ): Promise<GovernedMembershipActionReceipt>;
  reconcile(
    role: GovernedProposalSubmissionRole,
    authorizationId: string,
    readFinalized: (role: GovernedProposalSubmissionRole, authorizationId: string) => Promise<GovernedProposalObservation | null>,
  ): Promise<ProposalSubmissionAttempt>;
}

/** Private single-host file adapter. Never delete a reserved attempt on an ambiguous execution error. */
export class FileProposalSubmissionJournal implements ProposalSubmissionJournal {
  private readonly path: string;

  constructor(path: string) {
    if (path.length === 0) throw new RangeError("Proposal submission journal path is invalid");
    this.path = resolve(path);
  }

  async executeOnce(
    role: GovernedProposalSubmissionRole,
    authorizationId: string,
    evidenceCommitment: string,
    execute: () => Promise<GovernedMembershipActionReceipt>,
  ): Promise<GovernedMembershipActionReceipt> {
    const key = this.parseKey(role, authorizationId, evidenceCommitment);
    await this.withWrite(async () => {
      const state = await this.readState();
      const existing = state.attempts.find((attempt) => attempt.role === key.role
        && attempt.authorizationId === key.authorizationId);
      if (existing !== undefined) {
        if (existing.evidenceCommitment !== key.evidenceCommitment) throw new ProposalSubmissionConflictError();
        throw new ProposalSubmissionAlreadyPendingError(existing.state);
      }
      if (state.attempts.length >= MAX_ENTRIES) throw new ProposalSubmissionCapacityError();
      const attempts = [...state.attempts, { ...key, state: "reserved" as const, eventHash: null }];
      const projectedAttempts = state.attempts.map((attempt) => attempt.state === "reserved"
        ? { ...attempt, state: "submitted", eventHash: `0x${"0".repeat(64)}` }
        : attempt);
      const submittedSize = Buffer.byteLength(JSON.stringify({
        version: 1,
        attempts: [...projectedAttempts, { ...key, state: "submitted", eventHash: `0x${"0".repeat(64)}` }],
      }), "utf8");
      if (submittedSize > MAX_FILE_BYTES) throw new ProposalSubmissionCapacityError();
      await this.writeState(StateSchema.parse({
        ...state, attempts,
      }));
    });

    // Any failure after reservation may follow a successful submission.
    try {
      const receipt = GovernedMembershipActionReceiptSchema.parse(await execute());
      await this.withWrite(async () => {
        const state = await this.readState();
        const attempt = state.attempts.find((entry) => entry.role === key.role
          && entry.authorizationId === key.authorizationId);
        if (attempt === undefined || attempt.evidenceCommitment !== key.evidenceCommitment
          || (attempt.eventHash !== null && attempt.eventHash !== receipt.eventHash)) {
          throw new ProposalSubmissionConflictError();
        }
        if (attempt.state !== "observed") attempt.state = "submitted";
        attempt.eventHash = receipt.eventHash;
        await this.writeState(state);
      });
      return receipt;
    } catch (error) {
      throw new ProposalSubmissionOutcomeUnknownError(error);
    }
  }

  async read(role: GovernedProposalSubmissionRole, authorizationId: string): Promise<ProposalSubmissionAttempt | null> {
    const parsedRole = ProposalRoleSchema.parse(role);
    const parsedId = AttemptSchema.shape.authorizationId.parse(authorizationId);
    const attempt = (await this.readState()).attempts.find((entry) => entry.role === parsedRole
      && entry.authorizationId === parsedId);
    return attempt === undefined ? null : structuredClone(attempt);
  }

  async reconcile(
    role: GovernedProposalSubmissionRole,
    authorizationId: string,
    readFinalized: (role: GovernedProposalSubmissionRole, authorizationId: string) => Promise<GovernedProposalObservation | null>,
  ): Promise<ProposalSubmissionAttempt> {
    const current = await this.read(role, authorizationId);
    if (current === null) throw new ProposalSubmissionConflictError();
    const rawObservation = await readFinalized(current.role, current.authorizationId);
    if (rawObservation === null) return current;
    const observation = GovernedProposalObservationSchema.parse(rawObservation);
    if (observation.evidenceCommitment !== current.evidenceCommitment
      || (current.eventHash !== null && current.eventHash !== observation.eventHash)) {
      throw new ProposalSubmissionConflictError();
    }
    return this.withWrite(async () => {
      const state = await this.readState();
      const attempt = state.attempts.find((entry) => entry.role === current.role
        && entry.authorizationId === current.authorizationId);
      if (attempt === undefined || attempt.evidenceCommitment !== observation.evidenceCommitment
        || (attempt.eventHash !== null && attempt.eventHash !== observation.eventHash)) {
        throw new ProposalSubmissionConflictError();
      }
      attempt.state = "observed";
      attempt.eventHash = observation.eventHash;
      await this.writeState(state);
      return structuredClone(attempt);
    });
  }

  private parseKey(role: GovernedProposalSubmissionRole, authorizationId: string, evidenceCommitment: string) {
    return {
      role: ProposalRoleSchema.parse(role),
      authorizationId: AttemptSchema.shape.authorizationId.parse(authorizationId),
      evidenceCommitment: Bytes32Schema.parse(evidenceCommitment),
    };
  }

  private async withWrite<T>(operation: () => Promise<T>): Promise<T> {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try {
        return await withExclusiveWorkspaceWrite(this.path, operation);
      } catch (error) {
        if (!(error instanceof WorkspaceMutationLockedError) || attempt === 99) throw error;
        await delay(10);
      }
    }
    throw new WorkspaceMutationLockedError();
  }

  private async readState(): Promise<JournalState> {
    let handle;
    try {
      handle = await open(this.path, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return emptyState();
      if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new InvalidProposalSubmissionJournalError();
      throw error;
    }
    try {
      const info = await handle.stat();
      if (!info.isFile() || (info.mode & 0o077) !== 0 || info.size > MAX_FILE_BYTES) {
        throw new InvalidProposalSubmissionJournalError();
      }
      const raw = await handle.readFile({ encoding: "utf8" });
      if (Buffer.byteLength(raw, "utf8") > MAX_FILE_BYTES) throw new InvalidProposalSubmissionJournalError();
      try {
        return StateSchema.parse(JSON.parse(raw));
      } catch {
        throw new InvalidProposalSubmissionJournalError();
      }
    } finally {
      await handle.close();
    }
  }

  private async writeState(state: JournalState): Promise<void> {
    const serialized = JSON.stringify(StateSchema.parse(state));
    if (Buffer.byteLength(serialized, "utf8") > MAX_FILE_BYTES) throw new InvalidProposalSubmissionJournalError();
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
