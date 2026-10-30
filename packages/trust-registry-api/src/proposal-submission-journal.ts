import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, mkdir, open, readdir, rename, rm } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { withExclusiveWorkspaceWrite, WorkspaceMutationLockedError } from "@midnight-ntwrk/trust-registry-cli";
import { canonicalizeJson, sha256Hex } from "@midnight-ntwrk/trust-registry-domain";
import { getLocalNetworkProfile } from "@midnight-ntwrk/trust-registry-integration";
import type { FinalizedRegistryLedgerView } from "@midnight-ntwrk/trust-registry-integration";
import { z } from "zod";

import { GovernedMembershipActionReceiptSchema, type GovernedMembershipActionReceipt } from "./governed-membership-actions.js";
import { GovernedProposalObservationSchema, type GovernedProposalObservation } from "./governed-proposal-observation.js";
import { readBoundedLocalApprovalFile } from "./local-reviewer-signature.js";
import { assessProposalRecoveryCandidate } from "./proposal-recovery-candidate.js";
import { loadApprovedProposalRecoveryDecision } from "./proposal-recovery-decision.js";

const MAX_ENTRIES = 10_000;
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_ARCHIVES = 64;
// Upper bound for the recovery record's fixed digests, timestamps, and 512-byte reference.
const MAX_ABANDONMENT_OVERHEAD_BYTES = 2 * 1024;
const Bytes32Schema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const CanonicalActionSequencePattern = /^(0|[1-9][0-9]{0,19})$/u;
const ActionSequenceSchema = z.string()
  .refine((value) => CanonicalActionSequencePattern.test(value) && BigInt(value) < (1n << 64n));
const ProposalRoleSchema = z.enum(["issuer", "verifier", "auditor", "maintainer", "recognition"]);
const ReservationContextSchema = z.strictObject({
  actionSequence: ActionSequenceSchema,
  actionKind: Bytes32Schema,
  actionPayloadHash: Bytes32Schema,
});
const RecoveryRecordSchema = z.strictObject({
  reservedAttemptDigest: Bytes32Schema,
  decisionSha256: z.string().regex(/^[0-9a-f]{64}$/u),
  finalityEvidenceSha256: z.string().regex(/^[0-9a-f]{64}$/u),
  evidenceReference: z.string().min(1).max(512),
  reviewerFingerprint: z.string().regex(/^[0-9A-F]{40}$/u),
  decisionDraftedAt: z.string(),
  recordedAt: z.string(),
  finalizedBlockHash: Bytes32Schema,
});
const AttemptSchema = z.strictObject({
  role: ProposalRoleSchema,
  authorizationId: z.string().trim().min(1).max(256),
  evidenceCommitment: Bytes32Schema,
  state: z.enum(["reserved", "submitted", "observed", "abandoned"]),
  eventHash: Bytes32Schema.nullable(),
  reservationContext: ReservationContextSchema.optional(),
  recovery: RecoveryRecordSchema.optional(),
}).refine((attempt) => (attempt.state === "reserved" || attempt.state === "abandoned")
  ? attempt.eventHash === null && (attempt.state === "abandoned") === (attempt.recovery !== undefined)
  : attempt.eventHash !== null && attempt.recovery === undefined);
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
  networkId: z.literal(getLocalNetworkProfile().networkId),
  expectedGenesisHash: Bytes32Schema,
  contractAddress: Bytes32Schema,
});
type DeploymentBinding = z.infer<typeof DeploymentBindingSchema>;
const sameDeploymentBinding = (left: DeploymentBinding, right: DeploymentBinding): boolean =>
  left.registryId === right.registryId && left.contractAddress === right.contractAddress
  && left.expectedGenesisHash === right.expectedGenesisHash;

export type GovernedProposalSubmissionRole = z.infer<typeof ProposalRoleSchema>;
export type ProposalReservationContext = z.infer<typeof ReservationContextSchema>;
export type ProposalSubmissionAttempt = z.infer<typeof AttemptSchema>;
export const proposalAttemptDigest = (attempt: ProposalSubmissionAttempt): string =>
  sha256Hex(`tr-proposal-attempt-v1\0${canonicalizeJson(AttemptSchema.parse(attempt))}`);
export const proposalJournalBindingDigest = (binding: z.infer<typeof DeploymentBindingSchema>): string =>
  sha256Hex(`tr-proposal-journal-binding-v1\0${canonicalizeJson(DeploymentBindingSchema.parse(binding))}`);
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
    super("Proposal authorization already has a recorded attempt");
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

export class ProposalSubmissionContextRequiredError extends Error {
  constructor() {
    super("Deployment-bound proposal reservations require the prepared action context");
    this.name = "ProposalSubmissionContextRequiredError";
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
  private expectedDeploymentBinding: DeploymentBinding | null = null;

  constructor(path: string) {
    if (path.length === 0) throw new RangeError("Proposal submission journal path is invalid");
    this.path = resolve(path);
  }

  /** A legacy journal with attempts cannot be retrospectively assigned to a deployment. */
  async bindDeployment(registryId: string, contractAddress: string, expectedGenesisHash: string): Promise<void> {
    const binding = DeploymentBindingSchema.parse({
      format: "tr-proposal-journal-binding-v1", registryId,
      networkId: getLocalNetworkProfile().networkId, contractAddress, expectedGenesisHash,
    });
    await this.withWrite(async () => {
      const current = await this.readBinding();
      if (this.expectedDeploymentBinding !== null
        && (current === null || !sameDeploymentBinding(this.expectedDeploymentBinding, current))) {
        throw new ProposalSubmissionConflictError();
      }
      if (current !== null) {
        if (!sameDeploymentBinding(current, binding)) {
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
    this.expectedDeploymentBinding = binding;
  }

  async assertDeploymentBinding(
    registryId: string, contractAddress: string, expectedGenesisHash: string,
  ): Promise<void> {
    const expected = DeploymentBindingSchema.parse({
      format: "tr-proposal-journal-binding-v1", registryId,
      networkId: getLocalNetworkProfile().networkId, contractAddress, expectedGenesisHash,
    });
    const current = await this.readBinding();
    if (current === null || !sameDeploymentBinding(current, expected)
      || (this.expectedDeploymentBinding !== null
        && !sameDeploymentBinding(this.expectedDeploymentBinding, expected))) {
      throw new ProposalSubmissionConflictError();
    }
    await this.requireExisting();
    this.expectedDeploymentBinding = expected;
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
      const binding = await this.readBinding();
      if (this.expectedDeploymentBinding !== null
        && (binding === null || !sameDeploymentBinding(binding, this.expectedDeploymentBinding))) {
        throw new ProposalSubmissionConflictError();
      }
      if (context === undefined && binding !== null) {
        throw new ProposalSubmissionContextRequiredError();
      }
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
      if (submittedSize + (context === undefined ? 0 : MAX_ABANDONMENT_OVERHEAD_BYTES) > MAX_FILE_BYTES) {
        throw new ProposalSubmissionCapacityError();
      }
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
        if (attempt === undefined || attempt.state === "abandoned"
          || attempt.evidenceCommitment !== key.evidenceCommitment
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

  /** Read one attempt and its deployment binding under the same private journal lock. */
  async readBoundAttempt(
    registryId: string, contractAddress: string, expectedGenesisHash: string,
    role: GovernedProposalSubmissionRole, authorizationId: string,
  ): Promise<{ attempt: ProposalSubmissionAttempt | null; bindingDigest: string }> {
    const expected = DeploymentBindingSchema.parse({
      format: "tr-proposal-journal-binding-v1", registryId,
      networkId: getLocalNetworkProfile().networkId, contractAddress, expectedGenesisHash,
    });
    const parsedRole = ProposalRoleSchema.parse(role);
    const parsedId = AttemptSchema.shape.authorizationId.parse(authorizationId);
    return this.withWrite(async () => {
      const current = await this.readBinding();
      if (current === null || current.registryId !== expected.registryId
        || current.contractAddress !== expected.contractAddress
        || current.expectedGenesisHash !== expected.expectedGenesisHash) throw new ProposalSubmissionConflictError();
      await this.requireExisting();
      const storage = await this.readStorage();
      const matches = [...storage.active.attempts, ...storage.archived].filter((entry) => entry.role === parsedRole
        && entry.authorizationId === parsedId);
      if (matches.length > 1) throw new ProposalSubmissionConflictError();
      const found = matches[0];
      return { attempt: found === undefined ? null : structuredClone(found),
        bindingDigest: proposalJournalBindingDigest(current) };
    });
  }

  /** Opt-in host transition; the packaged CLI supplies no finality authenticator or recovery command. */
  async abandonInvalidatedReservation(input: {
    registryId: string;
    contractAddress: string;
    expectedGenesisHash: string;
    planSourceRevision: string;
    approvedPlanSha256: string;
    role: GovernedProposalSubmissionRole;
    authorizationId: string;
    decisionPath: string;
    signaturePath: string;
    finalityEvidencePath: string;
    keyringDirectory: string;
    reviewerFingerprint: string;
    authenticateFinality: (evidence: Buffer) => Promise<{
      evidenceSha256: string;
      genesisHash: string;
      planSourceRevision: string;
      approvedPlanSha256: string;
      verifiedPlanReviewerFingerprint: string;
      view: FinalizedRegistryLedgerView;
      originalActionRejected: true;
    }>;
    now?: number;
  }): Promise<ProposalSubmissionAttempt> {
    return this.withWrite(async () => {
      const binding = await this.readBinding();
      if (binding === null || !sameDeploymentBinding(binding, {
        format: "tr-proposal-journal-binding-v1",
        registryId: input.registryId,
        networkId: getLocalNetworkProfile().networkId,
        contractAddress: input.contractAddress,
        expectedGenesisHash: input.expectedGenesisHash,
      }) || (this.expectedDeploymentBinding !== null
        && !sameDeploymentBinding(binding, this.expectedDeploymentBinding))) {
        throw new ProposalSubmissionConflictError();
      }
      const storage = await this.readStorage();
      const attempt = storage.active.attempts.find((entry) => entry.role === input.role
        && entry.authorizationId === input.authorizationId);
      if (attempt?.state !== "reserved" || attempt.reservationContext === undefined) {
        throw new ProposalSubmissionConflictError();
      }
      const evidence = await readBoundedLocalApprovalFile(input.finalityEvidencePath, 1024 * 1024);
      const authenticated = await input.authenticateFinality(evidence);
      const evidenceSha256 = createHash("sha256").update(evidence).digest("hex");
      if (authenticated.evidenceSha256 !== evidenceSha256
        || authenticated.genesisHash !== binding.expectedGenesisHash
        || authenticated.planSourceRevision !== input.planSourceRevision
        || authenticated.approvedPlanSha256 !== input.approvedPlanSha256
        || !/^[0-9A-F]{40}$/u.test(authenticated.verifiedPlanReviewerFingerprint)
        || authenticated.originalActionRejected !== true) {
        throw new ProposalSubmissionConflictError();
      }
      const candidate = await assessProposalRecoveryCandidate({
        attempt, view: authenticated.view, registryId: binding.registryId,
        contractAddress: binding.contractAddress,
        planExpectedGenesisHash: binding.expectedGenesisHash,
        planSourceRevision: input.planSourceRevision,
        approvedPlanSha256: input.approvedPlanSha256,
        journalBindingDigest: proposalJournalBindingDigest(binding),
      });
      if (!candidate.reviewCandidate || candidate.reason !== "sequence-invalidated-record-absent") {
        throw new ProposalSubmissionConflictError();
      }
      const approved = await loadApprovedProposalRecoveryDecision({
        decisionPath: input.decisionPath, signaturePath: input.signaturePath,
        finalityEvidencePath: input.finalityEvidencePath, keyringDirectory: input.keyringDirectory,
        reviewerFingerprint: input.reviewerFingerprint,
        planReviewerFingerprint: authenticated.verifiedPlanReviewerFingerprint,
        candidate, ...(input.now === undefined ? {} : { now: input.now }),
      });
      if (approved.decision.finalityEvidenceSha256 !== evidenceSha256) {
        throw new ProposalSubmissionConflictError();
      }
      attempt.state = "abandoned";
      attempt.recovery = {
        reservedAttemptDigest: candidate.attemptDigest,
        decisionSha256: approved.decisionSha256,
        finalityEvidenceSha256: evidenceSha256,
        evidenceReference: approved.decision.evidenceReference,
        reviewerFingerprint: approved.decision.reviewerFingerprint,
        decisionDraftedAt: approved.decision.draftedAt,
        recordedAt: new Date(input.now ?? Date.now()).toISOString(),
        finalizedBlockHash: candidate.finalizedBlockHash,
      };
      await this.writeAbandoned(storage, StateSchema.parse(storage.active), attempt);
      return structuredClone(attempt);
    });
  }

  async inspectCapacity(): Promise<ProposalSubmissionJournalCapacity> {
    return this.withWrite(async () => {
      const storage = await this.readStorage();
      return {
        activeEntries: storage.active.attempts.length,
        pendingEntries: storage.active.attempts.filter((attempt) => attempt.state === "reserved"
          || attempt.state === "submitted").length,
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

  /** Repack finalized history without deleting an authorization or changing pending attempts. */
  async compactObservedArchives(readFinalized: FinalizedProposalReader): Promise<{
    before: number; after: number; archivedEntries: number;
  }> {
    return this.withWrite(async () => {
      const storage = await this.readStorage();
      const before = storage.manifest?.archives.length ?? 0;
      if (before < 2 || storage.manifest === null) {
        return { before, after: before, archivedEntries: storage.archived.length };
      }
      for (const attempt of storage.archived) {
        if (attempt.state === "abandoned") continue;
        const rawObservation = await readFinalized(attempt.role, attempt.authorizationId);
        if (rawObservation === null) throw new ProposalSubmissionConflictError();
        const observation = GovernedProposalObservationSchema.parse(rawObservation);
        if (observation.evidenceCommitment !== attempt.evidenceCommitment
          || observation.eventHash !== attempt.eventHash) throw new ProposalSubmissionConflictError();
      }

      const groups: ProposalSubmissionAttempt[][] = [];
      let group: ProposalSubmissionAttempt[] = [];
      let bytes = Buffer.byteLength(JSON.stringify(emptyState()), "utf8");
      for (const attempt of storage.archived) {
        const entryBytes = Buffer.byteLength(JSON.stringify(attempt), "utf8") + (group.length === 0 ? 0 : 1);
        if (group.length === MAX_ENTRIES || bytes + entryBytes > MAX_FILE_BYTES) {
          groups.push(group);
          group = [];
          bytes = Buffer.byteLength(JSON.stringify(emptyState()), "utf8");
        }
        group.push(attempt);
        bytes += Buffer.byteLength(JSON.stringify(attempt), "utf8") + (group.length === 1 ? 0 : 1);
      }
      if (group.length > 0) groups.push(group);
      if (groups.length >= before) {
        return { before, after: before, archivedEntries: storage.archived.length };
      }

      const archives = [];
      for (const attempts of groups) {
        archives.push(await this.writeSegment(StateSchema.parse({ version: 1, attempts })));
      }
      await this.writeManifest(ManifestSchema.parse({
        version: 2, archives, active: storage.manifest.active,
      }));
      for (const segment of storage.manifest.archives) {
        await rm(join(dirname(this.path), segment.file), { force: true });
      }
      return { before, after: archives.length, archivedEntries: storage.archived.length };
    });
  }

  /** Recheck observed outcomes; retain signed abandonment records as terminal tombstones. */
  async rotateObserved(readFinalized: FinalizedProposalReader): Promise<{ archived: number; pending: number }> {
    return this.withWrite(async () => {
      const storage = await this.readStorage();
      const terminal = storage.active.attempts.filter((attempt) => attempt.state === "observed"
        || attempt.state === "abandoned");
      const pending = storage.active.attempts.filter((attempt) => attempt.state === "reserved"
        || attempt.state === "submitted");
      if (terminal.length === 0) return { archived: 0, pending: pending.length };
      if ((storage.manifest?.archives.length ?? 0) >= MAX_ARCHIVES) throw new ProposalSubmissionCapacityError();
      for (const attempt of terminal) {
        if (attempt.state === "abandoned") continue;
        const rawObservation = await readFinalized(attempt.role, attempt.authorizationId);
        if (rawObservation === null) throw new ProposalSubmissionConflictError();
        const observation = GovernedProposalObservationSchema.parse(rawObservation);
        if (observation.evidenceCommitment !== attempt.evidenceCommitment
          || observation.eventHash !== attempt.eventHash) throw new ProposalSubmissionConflictError();
      }
      const archive = await this.writeSegment(StateSchema.parse({ version: 1, attempts: terminal }));
      const nextActive = await this.writeSegment(StateSchema.parse({ version: 1, attempts: pending }));
      const archives = storage.manifest === null
        ? [archive]
        : [...storage.manifest.archives, archive];
      await this.writeManifest(ManifestSchema.parse({ version: 2, archives, active: nextActive }));
      if (storage.manifest !== null) {
        await rm(join(dirname(this.path), storage.manifest.active.file), { force: true });
      }
      return { archived: terminal.length, pending: pending.length };
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
    if (rawObservation === null) {
      const refreshed = await this.read(role, authorizationId);
      if (refreshed === null) throw new ProposalSubmissionConflictError();
      return refreshed;
    }
    const observation = GovernedProposalObservationSchema.parse(rawObservation);
    if (current.state === "abandoned") throw new ProposalSubmissionConflictError();
    if (observation.evidenceCommitment !== current.evidenceCommitment
      || (current.eventHash !== null && current.eventHash !== observation.eventHash)) {
      throw new ProposalSubmissionConflictError();
    }
    return this.withWrite(async () => {
      const storage = await this.readStorage();
      const archived = storage.archived.find((entry) => entry.role === current.role
        && entry.authorizationId === current.authorizationId);
      if (archived !== undefined) {
        if (archived.state === "abandoned"
          || archived.evidenceCommitment !== observation.evidenceCommitment
          || archived.eventHash !== observation.eventHash) throw new ProposalSubmissionConflictError();
        return structuredClone(archived);
      }
      const attempt = storage.active.attempts.find((entry) => entry.role === current.role
        && entry.authorizationId === current.authorizationId);
      if (attempt === undefined || attempt.state === "abandoned"
        || attempt.evidenceCommitment !== observation.evidenceCommitment
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
    if (raw === null) {
      if (this.expectedDeploymentBinding !== null || await this.readBinding() !== null) {
        throw new InvalidProposalSubmissionJournalError();
      }
      return { manifest: null, active: emptyState(), archived: [] };
    }
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
    if (archived.some((attempt) => attempt.state !== "observed" && attempt.state !== "abandoned")) {
      throw new InvalidProposalSubmissionJournalError();
    }
    return { manifest, active, archived };
  }

  private async readPrivateFile(path: string, maxBytes: number): Promise<string | null> {
    let handle;
    try {
      handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new InvalidProposalSubmissionJournalError();
      throw error;
    }
    try {
      const before = await handle.stat({ bigint: true });
      if (!before.isFile() || (before.mode & 0o077n) !== 0n
        || (before.nlink !== 1n && !(path === `${this.path}.binding` && before.nlink === 2n
          && await this.hasCrashLinkedBindingTemp(path, before.dev, before.ino)))
        || before.size > BigInt(maxBytes)
        || (typeof process.getuid === "function"
          && before.uid !== BigInt(process.getuid()) && before.uid !== 0n)) {
        throw new InvalidProposalSubmissionJournalError();
      }
      const bytes = Buffer.alloc(Number(before.size));
      let count = 0;
      while (count < bytes.length) {
        const result = await handle.read(bytes, count, bytes.length - count, count);
        if (result.bytesRead === 0) break;
        count += result.bytesRead;
      }
      const after = await handle.stat({ bigint: true });
      if (count !== bytes.length || after.size !== before.size || after.dev !== before.dev
        || after.ino !== before.ino || after.nlink !== before.nlink || after.mode !== before.mode
        || after.uid !== before.uid || after.mtimeNs !== before.mtimeNs
        || after.ctimeNs !== before.ctimeNs) {
        throw new InvalidProposalSubmissionJournalError();
      }
      return bytes.toString("utf8");
    } finally {
      await handle.close();
    }
  }

  private async hasCrashLinkedBindingTemp(path: string, dev: bigint, ino: bigint): Promise<boolean> {
    const prefix = `${basename(path)}.`;
    for (const name of await readdir(dirname(path))) {
      if (!name.startsWith(prefix) || !name.endsWith(".tmp")
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u
          .test(name.slice(prefix.length, -4))) continue;
      try {
        const companion = await lstat(join(dirname(path), name), { bigint: true });
        if (companion.isFile() && companion.dev === dev && companion.ino === ino) return true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    return false;
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

  /** Preserve old near-capacity journals by committing the tombstone as an archive segment. */
  private async writeAbandoned(
    storage: JournalStorage, state: JournalState, abandoned: ProposalSubmissionAttempt,
  ): Promise<void> {
    if (Buffer.byteLength(JSON.stringify(state), "utf8") <= MAX_FILE_BYTES) {
      await this.writeActive(storage, state);
      return;
    }
    if ((storage.manifest?.archives.length ?? 0) >= MAX_ARCHIVES) {
      throw new ProposalSubmissionCapacityError();
    }
    const archive = await this.writeSegment(StateSchema.parse({ version: 1, attempts: [abandoned] }));
    const active = await this.writeSegment(StateSchema.parse({
      version: 1,
      attempts: state.attempts.filter((entry) => entry.role !== abandoned.role
        || entry.authorizationId !== abandoned.authorizationId),
    }));
    await this.writeManifest(ManifestSchema.parse({
      version: 2,
      archives: [...(storage.manifest?.archives ?? []), archive],
      active,
    }));
    if (storage.manifest !== null) {
      await rm(join(dirname(this.path), storage.manifest.active.file), { force: true });
    }
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
