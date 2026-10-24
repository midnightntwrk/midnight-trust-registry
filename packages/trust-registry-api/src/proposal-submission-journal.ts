import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, mkdir, open, rename, rm } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { withExclusiveWorkspaceWrite, WorkspaceMutationLockedError } from "@midnight-ntwrk/trust-registry-cli";
import { z } from "zod";

import { GovernedMembershipActionReceiptSchema, type GovernedMembershipActionReceipt } from "./governed-membership-actions.js";
import { GovernedProposalObservationSchema, type GovernedProposalObservation } from "./governed-proposal-observation.js";

const MAX_ENTRIES = 10_000;
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_ARCHIVES = 64;
const Bytes32Schema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const ActionSequenceSchema = z.string().regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) < (1n << 64n));
const ProposalRoleSchema = z.enum(["issuer", "verifier", "auditor", "maintainer", "recognition"]);
const ReservationContextSchema = z.strictObject({
  actionSequence: ActionSequenceSchema,
  actionKind: Bytes32Schema,
  actionPayloadHash: Bytes32Schema,
});
const AttemptSchema = z.strictObject({
  role: ProposalRoleSchema,
  authorizationId: z.string().trim().min(1).max(256),
  evidenceCommitment: Bytes32Schema,
  state: z.enum(["reserved", "submitted", "observed"]),
  eventHash: Bytes32Schema.nullable(),
  reservationContext: ReservationContextSchema.optional(),
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
const SegmentSchema = z.strictObject({
  file: z.string().regex(/^[a-zA-Z0-9._-]+\.[0-9a-f-]{36}\.segment$/u),
  sha256: z.string().regex(/^[0-9a-f]{64}$/u),
});
const ManifestSchema = z.strictObject({
  version: z.literal(2),
  archives: z.array(SegmentSchema).max(MAX_ARCHIVES),
  active: SegmentSchema,
});
const DeploymentBindingSchema = z.strictObject({
  format: z.literal("tr-proposal-journal-binding-v1"),
  registryId: z.string().trim().min(1).max(256),
  networkId: z.literal("undeployed"),
  expectedGenesisHash: Bytes32Schema,
  contractAddress: Bytes32Schema,
});

export type GovernedProposalSubmissionRole = z.infer<typeof ProposalRoleSchema>;
export type ProposalReservationContext = z.infer<typeof ReservationContextSchema>;
export type ProposalSubmissionAttempt = z.infer<typeof AttemptSchema>;
export type FinalizedProposalReader = (
  role: GovernedProposalSubmissionRole,
  authorizationId: string,
) => Promise<GovernedProposalObservation | null>;
type JournalState = z.infer<typeof StateSchema>;
type Manifest = z.infer<typeof ManifestSchema>;
type JournalStorage = {
  manifest: Manifest | null;
  active: JournalState;
  archived: ProposalSubmissionAttempt[];
};
export type ProposalSubmissionJournalCapacity = {
  activeEntries: number;
  pendingEntries: number;
  archivedEntries: number;
  archiveCount: number;
  activeBytes: number;
  projectedActiveBytes: number;
  maxActiveEntries: number;
  maxActiveBytes: number;
  maxArchives: number;
};
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

export class ProposalSubmissionBlockedByReservationError extends Error {
  constructor(
    readonly blockingRole: GovernedProposalSubmissionRole,
    readonly blockingAuthorizationId: string,
  ) {
    super("Another proposal submission is reserved; reconcile it before submitting a different proposal");
    this.name = "ProposalSubmissionBlockedByReservationError";
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
  assertDeploymentBinding?(
    registryId: string, contractAddress: string, expectedGenesisHash: string,
  ): Promise<void>;
  executeOnce(
    role: GovernedProposalSubmissionRole,
    authorizationId: string,
    evidenceCommitment: string,
    execute: () => Promise<GovernedMembershipActionReceipt>,
    reservationContext?: ProposalReservationContext,
  ): Promise<GovernedMembershipActionReceipt>;
  reconcile(
    role: GovernedProposalSubmissionRole,
    authorizationId: string,
    readFinalized: FinalizedProposalReader,
  ): Promise<ProposalSubmissionAttempt>;
}

/** Private single-host file adapter. Never delete a reserved attempt on an ambiguous execution error. */
export class FileProposalSubmissionJournal implements ProposalSubmissionJournal {
  private readonly path: string;

  constructor(path: string) {
    if (path.length === 0) throw new RangeError("Proposal submission journal path is invalid");
    this.path = resolve(path);
  }

  /** A legacy journal with attempts cannot be retrospectively assigned to a deployment. */
  async bindDeployment(registryId: string, contractAddress: string, expectedGenesisHash: string): Promise<void> {
    const binding = DeploymentBindingSchema.parse({
      format: "tr-proposal-journal-binding-v1", registryId,
      networkId: "undeployed", contractAddress, expectedGenesisHash,
    });
    await this.withWrite(async () => {
      const current = await this.readBinding();
      if (current !== null) {
        if (current.registryId !== binding.registryId || current.contractAddress !== binding.contractAddress
          || current.expectedGenesisHash !== binding.expectedGenesisHash) {
          throw new ProposalSubmissionConflictError();
        }
        await this.requireExisting();
        return;
      }
      const storage = await this.readStorage();
      if (storage.active.attempts.length !== 0 || storage.archived.length !== 0) {
        throw new ProposalSubmissionConflictError();
      }
      if (await this.readPrivateFile(this.path, MAX_FILE_BYTES) === null) {
        await this.writeState(emptyState());
      }
      const bindingPath = `${this.path}.binding`;
      const temporaryPath = `${bindingPath}.${randomUUID()}.tmp`;
      try {
        const handle = await open(temporaryPath, "wx", 0o600);
        try {
          await handle.writeFile(JSON.stringify(binding));
          await handle.sync();
        } finally {
          await handle.close();
        }
        await link(temporaryPath, bindingPath);
      } finally {
        await rm(temporaryPath, { force: true });
      }
      const directory = await open(dirname(bindingPath), "r");
      try {
        await directory.sync();
      } finally {
        await directory.close();
      }
    });
  }

  async assertDeploymentBinding(
    registryId: string, contractAddress: string, expectedGenesisHash: string,
  ): Promise<void> {
    const expected = DeploymentBindingSchema.parse({
      format: "tr-proposal-journal-binding-v1", registryId,
      networkId: "undeployed", contractAddress, expectedGenesisHash,
    });
    const current = await this.readBinding();
    if (current === null || current.registryId !== expected.registryId
      || current.contractAddress !== expected.contractAddress
      || current.expectedGenesisHash !== expected.expectedGenesisHash) throw new ProposalSubmissionConflictError();
    await this.requireExisting();
  }

  async requireExisting(): Promise<void> {
    if (await this.readPrivateFile(this.path, MAX_FILE_BYTES) === null) {
      throw new InvalidProposalSubmissionJournalError();
    }
  }

  private async readBinding(): Promise<z.infer<typeof DeploymentBindingSchema> | null> {
    const raw = await this.readPrivateFile(`${this.path}.binding`, 1024);
    if (raw === null) return null;
    try {
      return DeploymentBindingSchema.parse(JSON.parse(raw));
    } catch {
      throw new InvalidProposalSubmissionJournalError();
    }
  }

  async executeOnce(
    role: GovernedProposalSubmissionRole,
    authorizationId: string,
    evidenceCommitment: string,
    execute: () => Promise<GovernedMembershipActionReceipt>,
    reservationContext?: ProposalReservationContext,
  ): Promise<GovernedMembershipActionReceipt> {
    const key = this.parseKey(role, authorizationId, evidenceCommitment);
    const context = reservationContext === undefined ? undefined : ReservationContextSchema.parse(reservationContext);
    await this.withWrite(async () => {
      const storage = await this.readStorage();
      const existing = [...storage.active.attempts, ...storage.archived].find((attempt) => attempt.role === key.role
        && attempt.authorizationId === key.authorizationId);
      if (existing !== undefined) {
        if (existing.evidenceCommitment !== key.evidenceCommitment) throw new ProposalSubmissionConflictError();
        throw new ProposalSubmissionAlreadyPendingError(existing.state);
      }
      const blocker = storage.active.attempts.find((attempt) => attempt.state === "reserved");
      if (blocker !== undefined) {
        throw new ProposalSubmissionBlockedByReservationError(blocker.role, blocker.authorizationId);
      }
      if (storage.active.attempts.length >= MAX_ENTRIES) throw new ProposalSubmissionCapacityError();
      const attempts = [...storage.active.attempts,
        { ...key, state: "reserved" as const, eventHash: null, ...(context === undefined ? {} : { reservationContext: context }) }];
      const projectedAttempts = storage.active.attempts.map((attempt) => attempt.state === "reserved"
        ? { ...attempt, state: "submitted", eventHash: `0x${"0".repeat(64)}` }
        : attempt);
      const submittedSize = Buffer.byteLength(JSON.stringify({
        version: 1,
        attempts: [...projectedAttempts, { ...key, state: "submitted", eventHash: `0x${"0".repeat(64)}`,
          ...(context === undefined ? {} : { reservationContext: context }) }],
      }), "utf8");
      if (submittedSize > MAX_FILE_BYTES) throw new ProposalSubmissionCapacityError();
      await this.writeActive(storage, StateSchema.parse({
        ...storage.active, attempts,
      }));
    });

    // Any failure after reservation may follow a successful submission.
    try {
      const receipt = GovernedMembershipActionReceiptSchema.parse(await execute());
      await this.withWrite(async () => {
        const storage = await this.readStorage();
        const attempt = storage.active.attempts.find((entry) => entry.role === key.role
          && entry.authorizationId === key.authorizationId);
        if (attempt === undefined || attempt.evidenceCommitment !== key.evidenceCommitment
          || (attempt.eventHash !== null && attempt.eventHash !== receipt.eventHash)) {
          throw new ProposalSubmissionConflictError();
        }
        if (attempt.state !== "observed") attempt.state = "submitted";
        attempt.eventHash = receipt.eventHash;
        await this.writeActive(storage, storage.active);
      });
      return receipt;
    } catch (error) {
      throw new ProposalSubmissionOutcomeUnknownError(error);
    }
  }

  async read(role: GovernedProposalSubmissionRole, authorizationId: string): Promise<ProposalSubmissionAttempt | null> {
    const parsedRole = ProposalRoleSchema.parse(role);
    const parsedId = AttemptSchema.shape.authorizationId.parse(authorizationId);
    return this.withWrite(async () => {
      const storage = await this.readStorage();
      const attempt = [...storage.active.attempts, ...storage.archived].find((entry) => entry.role === parsedRole
        && entry.authorizationId === parsedId);
      return attempt === undefined ? null : structuredClone(attempt);
    });
  }

  async inspectCapacity(): Promise<ProposalSubmissionJournalCapacity> {
    return this.withWrite(async () => {
      const storage = await this.readStorage();
      return {
        activeEntries: storage.active.attempts.length,
        pendingEntries: storage.active.attempts.filter((attempt) => attempt.state !== "observed").length,
        archivedEntries: storage.archived.length,
        archiveCount: storage.manifest?.archives.length ?? 0,
        activeBytes: Buffer.byteLength(JSON.stringify(storage.active), "utf8"),
        projectedActiveBytes: Buffer.byteLength(JSON.stringify({
          version: 1,
          attempts: storage.active.attempts.map((attempt) => attempt.state === "reserved"
            ? { ...attempt, state: "submitted", eventHash: `0x${"0".repeat(64)}` }
            : attempt),
        }), "utf8"),
        maxActiveEntries: MAX_ENTRIES,
        maxActiveBytes: MAX_FILE_BYTES,
        maxArchives: MAX_ARCHIVES,
      };
    });
  }

  /** Recheck every observation against a finalized reader before archiving it. */
  async rotateObserved(readFinalized: FinalizedProposalReader): Promise<{ archived: number; pending: number }> {
    return this.withWrite(async () => {
      const storage = await this.readStorage();
      const observed = storage.active.attempts.filter((attempt) => attempt.state === "observed");
      const pending = storage.active.attempts.filter((attempt) => attempt.state !== "observed");
      if (observed.length === 0) return { archived: 0, pending: pending.length };
      if ((storage.manifest?.archives.length ?? 0) >= MAX_ARCHIVES) throw new ProposalSubmissionCapacityError();
      for (const attempt of observed) {
        const rawObservation = await readFinalized(attempt.role, attempt.authorizationId);
        if (rawObservation === null) throw new ProposalSubmissionConflictError();
        const observation = GovernedProposalObservationSchema.parse(rawObservation);
        if (observation.evidenceCommitment !== attempt.evidenceCommitment
          || observation.eventHash !== attempt.eventHash) throw new ProposalSubmissionConflictError();
      }
      const archive = await this.writeSegment(StateSchema.parse({ version: 1, attempts: observed }));
      const nextActive = await this.writeSegment(StateSchema.parse({ version: 1, attempts: pending }));
      const archives = storage.manifest === null
        ? [archive]
        : [...storage.manifest.archives, archive];
      await this.writeManifest(ManifestSchema.parse({ version: 2, archives, active: nextActive }));
      if (storage.manifest !== null) {
        await rm(join(dirname(this.path), storage.manifest.active.file), { force: true });
      }
      return { archived: observed.length, pending: pending.length };
    });
  }

  async reconcile(
    role: GovernedProposalSubmissionRole,
    authorizationId: string,
    readFinalized: FinalizedProposalReader,
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
      const storage = await this.readStorage();
      const archived = storage.archived.find((entry) => entry.role === current.role
        && entry.authorizationId === current.authorizationId);
      if (archived !== undefined) {
        if (archived.evidenceCommitment !== observation.evidenceCommitment
          || archived.eventHash !== observation.eventHash) throw new ProposalSubmissionConflictError();
        return structuredClone(archived);
      }
      const attempt = storage.active.attempts.find((entry) => entry.role === current.role
        && entry.authorizationId === current.authorizationId);
      if (attempt === undefined || attempt.evidenceCommitment !== observation.evidenceCommitment
        || (attempt.eventHash !== null && attempt.eventHash !== observation.eventHash)) {
        throw new ProposalSubmissionConflictError();
      }
      if (attempt.state === "observed") return structuredClone(attempt);
      attempt.state = "observed";
      attempt.eventHash = observation.eventHash;
      await this.writeActive(storage, storage.active);
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

  private async readStorage(): Promise<JournalStorage> {
    const raw = await this.readPrivateFile(this.path, MAX_FILE_BYTES);
    if (raw === null) return { manifest: null, active: emptyState(), archived: [] };
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new InvalidProposalSubmissionJournalError();
    }
    if (parsed !== null && typeof parsed === "object" && "version" in parsed && parsed.version === 1) {
      try {
        return { manifest: null, active: StateSchema.parse(parsed), archived: [] };
      } catch {
        throw new InvalidProposalSubmissionJournalError();
      }
    }
    let manifest: Manifest;
    try {
      if (Buffer.byteLength(raw, "utf8") > MAX_MANIFEST_BYTES) throw new Error("oversized manifest");
      manifest = ManifestSchema.parse(parsed);
    } catch {
      throw new InvalidProposalSubmissionJournalError();
    }
    const files = [manifest.active.file, ...manifest.archives.map((archive) => archive.file)];
    if (new Set(files).size !== files.length) throw new InvalidProposalSubmissionJournalError();
    const active = await this.readSegment(manifest.active);
    const archived = (await Promise.all(manifest.archives.map((archive) => this.readSegment(archive))))
      .flatMap((segment) => segment.attempts);
    const keys = new Set<string>();
    for (const attempt of [...active.attempts, ...archived]) {
      const key = `${attempt.role}\0${attempt.authorizationId}`;
      if (keys.has(key)) throw new InvalidProposalSubmissionJournalError();
      keys.add(key);
    }
    if (archived.some((attempt) => attempt.state !== "observed")) throw new InvalidProposalSubmissionJournalError();
    return { manifest, active, archived };
  }

  private async readPrivateFile(path: string, maxBytes: number): Promise<string | null> {
    let handle;
    try {
      handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new InvalidProposalSubmissionJournalError();
      throw error;
    }
    try {
      const info = await handle.stat();
      if (!info.isFile() || (info.mode & 0o077) !== 0 || info.size > maxBytes) {
        throw new InvalidProposalSubmissionJournalError();
      }
      const raw = await handle.readFile({ encoding: "utf8" });
      if (Buffer.byteLength(raw, "utf8") > maxBytes) throw new InvalidProposalSubmissionJournalError();
      return raw;
    } finally {
      await handle.close();
    }
  }

  private async readSegment(segment: z.infer<typeof SegmentSchema>): Promise<JournalState> {
    if (!segment.file.startsWith(`${basename(this.path)}.`)) throw new InvalidProposalSubmissionJournalError();
    const raw = await this.readPrivateFile(join(dirname(this.path), segment.file), MAX_FILE_BYTES);
    if (raw === null || createHash("sha256").update(raw).digest("hex") !== segment.sha256) {
      throw new InvalidProposalSubmissionJournalError();
    }
    try {
      return StateSchema.parse(JSON.parse(raw));
    } catch {
      throw new InvalidProposalSubmissionJournalError();
    }
  }

  private async writeSegment(state: JournalState): Promise<z.infer<typeof SegmentSchema>> {
    const serialized = JSON.stringify(StateSchema.parse(state));
    if (Buffer.byteLength(serialized) > MAX_FILE_BYTES) throw new ProposalSubmissionCapacityError();
    const file = `${basename(this.path)}.${randomUUID()}.segment`;
    const path = join(dirname(this.path), file);
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const handle = await open(path, "wx", 0o600);
    try {
      await handle.writeFile(serialized);
      await handle.sync();
    } finally {
      await handle.close();
    }
    const directory = await open(dirname(path), "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
    return { file, sha256: createHash("sha256").update(serialized).digest("hex") };
  }

  private async writeManifest(manifest: Manifest): Promise<void> {
    const serialized = JSON.stringify(ManifestSchema.parse(manifest));
    if (Buffer.byteLength(serialized) > MAX_MANIFEST_BYTES) throw new ProposalSubmissionCapacityError();
    await this.writeAtomically(serialized);
  }

  private async writeActive(storage: JournalStorage, state: JournalState): Promise<void> {
    if (storage.manifest === null) return this.writeState(state);
    const active = await this.writeSegment(state);
    await this.writeManifest({ ...storage.manifest, active });
    await rm(join(dirname(this.path), storage.manifest.active.file), { force: true });
  }

  private async writeState(state: JournalState): Promise<void> {
    const serialized = JSON.stringify(StateSchema.parse(state));
    if (Buffer.byteLength(serialized, "utf8") > MAX_FILE_BYTES) throw new InvalidProposalSubmissionJournalError();
    await this.writeAtomically(serialized);
  }

  private async writeAtomically(serialized: string): Promise<void> {
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
