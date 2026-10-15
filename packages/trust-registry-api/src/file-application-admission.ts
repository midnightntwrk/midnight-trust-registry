import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, rename, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import {
  type TrustRegistryOperatorWorkspace,
  withExclusiveWorkspaceWrite,
  WorkspaceMutationLockedError,
} from "@midnight-ntwrk/trust-registry-cli";
import {
  ApplicationEvidenceSubmissionSchema,
  canonicalizeJson,
  sha256Hex,
  type ApplicationEvidenceSubmission,
  type SignedPendingApplication,
} from "@midnight-ntwrk/trust-registry-domain";
import { z } from "zod";

import { ApplicationVpReceiptSchema, type ApplicationVpReceipt } from "./application-vp-http.js";
import {
  PendingApplicationRecordSchema,
  PendingApplicationRegistrationRejectedError,
  reconcileArchivedPendingApplication,
  transitionPendingApplicationRegistration,
  type ArchivedApplicationObservation,
  type PendingApplicationRecord,
  type PendingApplicationRegistrationPort,
  type VerifyArchivedApplicationObservation,
} from "./pending-application-registration.js";
import { assertProposalAdmission, type AcceptedApplicationEvidence, type ProposalAdmissionPort } from "./proposal-admission.js";
import { computeOperatorWorkspaceCommitment } from "./workspace-commitment.js";

const MAX_ENTRIES = 10_000;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const LOCK_ATTEMPTS = 100;
const LOCK_RETRY_MS = 10;
const AcceptedSchema = z.strictObject({
  applicationId: z.string().trim().min(1).max(256),
  evidence: ApplicationEvidenceSubmissionSchema,
  receipt: ApplicationVpReceiptSchema,
});
const StateSchema = z.strictObject({
  version: z.literal(1),
  applications: z.array(PendingApplicationRecordSchema).max(MAX_ENTRIES),
  consumedNonces: z.array(z.string().min(1).max(1024)).max(MAX_ENTRIES),
  accepted: z.array(AcceptedSchema).max(MAX_ENTRIES),
}).superRefine((state, context) => {
  const applications = new Set<string>();
  const nonces = new Set<string>();
  const accepted = new Set<string>();
  for (const [index, record] of state.applications.entries()) {
    if (applications.has(record.binding.applicationId)) {
      context.addIssue({ code: "custom", path: ["applications", index], message: "Duplicate application" });
    }
    applications.add(record.binding.applicationId);
  }
  for (const [index, nonce] of state.consumedNonces.entries()) {
    if (nonces.has(nonce)) context.addIssue({ code: "custom", path: ["consumedNonces", index], message: "Duplicate nonce" });
    nonces.add(nonce);
  }
  for (const [index, record] of state.accepted.entries()) {
    if (accepted.has(record.applicationId) || !applications.has(record.applicationId)
      || record.evidence.envelope.applicationId !== record.applicationId
      || record.receipt.evidenceCommitment !== record.evidence.commitment) {
      context.addIssue({ code: "custom", path: ["accepted", index], message: "Invalid accepted evidence" });
    }
    accepted.add(record.applicationId);
  }
});

type AdmissionState = z.infer<typeof StateSchema>;
const emptyState = (): AdmissionState => ({ version: 1, applications: [], consumedNonces: [], accepted: [] });

export class InvalidApplicationAdmissionFileError extends Error {
  constructor() {
    super("Application admission file is invalid");
    this.name = "InvalidApplicationAdmissionFileError";
  }
}

export class ApplicationAdmissionStoreRejectedError extends Error {
  constructor(readonly reason: "unknown-application" | "already-accepted" | "mismatched-evidence" | "stale-policy") {
    super(`Application admission rejected: ${reason}`);
    this.name = "ApplicationAdmissionStoreRejectedError";
  }
}

/** Private local persistence. A caller must keep the file in a trusted directory and supply a live workspace view. */
export class FileApplicationAdmissionStore implements PendingApplicationRegistrationPort, ProposalAdmissionPort {
  private readonly path: string;

  constructor(
    path: string,
    private readonly evidenceVerifierDid: string,
    private readonly resolver: Parameters<typeof transitionPendingApplicationRegistration>[4],
    private readonly loadWorkspace: () => Promise<TrustRegistryOperatorWorkspace>,
  ) {
    if (path.length === 0) throw new RangeError("Application admission path is invalid");
    this.path = resolve(path);
  }

  async register(request: SignedPendingApplication, now: Date): Promise<PendingApplicationRecord> {
    return this.withWrite(async () => {
      const state = await this.readState();
      const workspace = await this.loadWorkspace();
      const next = await transitionPendingApplicationRegistration({
        workspace, applications: state.applications, consumedNonces: state.consumedNonces,
      }, request, this.evidenceVerifierDid, now, this.resolver);
      if (computeOperatorWorkspaceCommitment(await this.loadWorkspace())
        !== computeOperatorWorkspaceCommitment(workspace)) {
        throw new PendingApplicationRegistrationRejectedError("stale-workspace");
      }
      await this.writeState(StateSchema.parse({
        ...state, applications: next.applications, consumedNonces: next.consumedNonces,
      }));
      return structuredClone(next.applications.at(-1)!);
    });
  }

  async recordArchived(
    observation: ArchivedApplicationObservation,
    verify: VerifyArchivedApplicationObservation,
  ): Promise<PendingApplicationRecord> {
    return this.withWrite(async () => {
      const state = await this.readState();
      const next = await reconcileArchivedPendingApplication({
        workspace: await this.loadWorkspace(),
        applications: state.applications,
        consumedNonces: state.consumedNonces,
      }, observation, verify);
      await this.writeState(StateSchema.parse({ ...state, applications: next.applications }));
      const record = next.applications.find(
        (entry) => entry.binding.applicationId === observation.binding.applicationId,
      );
      if (record === undefined) throw new Error("Archived application disappeared");
      return structuredClone(record);
    });
  }

  async readPending(applicationId: string): Promise<PendingApplicationRecord | null> {
    const record = (await this.readState()).applications.find(
      (entry) => entry.binding.applicationId === applicationId && entry.status === "pending",
    );
    return record === undefined ? null : structuredClone(record);
  }

  async resolvePendingApplication(applicationId: string): Promise<PendingApplicationRecord | null> {
    return this.readPending(applicationId);
  }

  async resolveAcceptedEvidence(applicationId: string): Promise<AcceptedApplicationEvidence | null> {
    const record = (await this.readState()).accepted.find((entry) => entry.applicationId === applicationId);
    return record === undefined ? null : structuredClone({ evidence: record.evidence, receipt: record.receipt });
  }

  async acceptEvidence(
    applicationId: string,
    submittedEvidence: ApplicationEvidenceSubmission,
    now: Date,
  ): Promise<ApplicationVpReceipt> {
    return this.withWrite(async () => {
      const state = await this.readState();
      const pending = state.applications.find(
        (entry) => entry.binding.applicationId === applicationId && entry.status === "pending",
      );
      if (pending === undefined) throw new ApplicationAdmissionStoreRejectedError("unknown-application");
      if (state.accepted.some((entry) => entry.applicationId === applicationId)) {
        throw new ApplicationAdmissionStoreRejectedError("already-accepted");
      }
      const workspace = await this.loadWorkspace();
      if (workspace.snapshot.registry.registryId !== pending.binding.registryId
        || workspace.snapshot.policy.policyId !== pending.binding.policyId
        || workspace.snapshot.policy.version !== pending.binding.policyVersion) {
        throw new ApplicationAdmissionStoreRejectedError("stale-policy");
      }
      const evidence = ApplicationEvidenceSubmissionSchema.parse(submittedEvidence);
      const receipt = ApplicationVpReceiptSchema.parse({
        receiptId: sha256Hex(canonicalizeJson({ applicationId, commitment: evidence.commitment, at: now.toISOString() })),
        evidenceCommitment: evidence.commitment,
        acceptedAt: now.toISOString(),
      });
      try {
        await assertProposalAdmission({
          resolvePendingApplication: async () => pending,
          resolveAcceptedEvidence: async () => ({ evidence, receipt }),
        }, pending.binding.role, pending.authorizationId, evidence);
      } catch {
        throw new ApplicationAdmissionStoreRejectedError("mismatched-evidence");
      }
      if (computeOperatorWorkspaceCommitment(await this.loadWorkspace())
        !== computeOperatorWorkspaceCommitment(workspace)) {
        throw new ApplicationAdmissionStoreRejectedError("stale-policy");
      }
      await this.writeState(StateSchema.parse({
        ...state, accepted: [...state.accepted, { applicationId, evidence, receipt }],
      }));
      return structuredClone(receipt);
    });
  }

  private async withWrite<T>(operation: () => Promise<T>): Promise<T> {
    for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
      try {
        return await withExclusiveWorkspaceWrite(this.path, operation);
      } catch (error) {
        if (!(error instanceof WorkspaceMutationLockedError) || attempt === LOCK_ATTEMPTS - 1) throw error;
        await delay(LOCK_RETRY_MS);
      }
    }
    throw new WorkspaceMutationLockedError();
  }

  private async readState(): Promise<AdmissionState> {
    let handle;
    try {
      handle = await open(this.path, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return emptyState();
      if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new InvalidApplicationAdmissionFileError();
      throw error;
    }
    try {
      const info = await handle.stat();
      if (!info.isFile() || (info.mode & 0o077) !== 0 || info.size > MAX_FILE_BYTES) {
        throw new InvalidApplicationAdmissionFileError();
      }
      const raw = await handle.readFile({ encoding: "utf8" });
      if (Buffer.byteLength(raw, "utf8") > MAX_FILE_BYTES) throw new InvalidApplicationAdmissionFileError();
      try {
        return StateSchema.parse(JSON.parse(raw));
      } catch {
        throw new InvalidApplicationAdmissionFileError();
      }
    } finally {
      await handle.close();
    }
  }

  private async writeState(state: AdmissionState): Promise<void> {
    const serialized = JSON.stringify(state);
    if (Buffer.byteLength(serialized, "utf8") > MAX_FILE_BYTES) {
      throw new InvalidApplicationAdmissionFileError();
    }
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
