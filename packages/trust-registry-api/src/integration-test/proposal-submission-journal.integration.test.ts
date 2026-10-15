import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  FileProposalSubmissionJournal,
  InvalidProposalSubmissionJournalError,
  ProposalSubmissionAlreadyPendingError,
  ProposalSubmissionCapacityError,
  ProposalSubmissionConflictError,
  ProposalSubmissionOutcomeUnknownError,
  type GovernedProposalSubmissionRole,
} from "../proposal-submission-journal.js";

const evidenceCommitment = `0x${"11".repeat(32)}`;
const otherCommitment = `0x${"22".repeat(32)}`;
const eventHash = `0x${"33".repeat(32)}`;
const otherEventHash = `0x${"44".repeat(32)}`;
const authorizationId = "auth:journal:test:v1";
const roles: GovernedProposalSubmissionRole[] = ["issuer", "verifier", "auditor", "maintainer"];

describe("private governed proposal submission journal", () => {
  let directory: string;
  let path: string;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "tr-proposal-submission-"));
    path = join(directory, "journal.json");
  });
  afterEach(async () => { await rm(directory, { recursive: true, force: true }); });

  it.each(roles)("persists %s receipt without treating it as finality", async (role) => {
    const journal = new FileProposalSubmissionJournal(path);
    const privatePresentation = "raw-vp-private-claims";
    const privateSignature = "maintainer-signature";
    expect(await journal.executeOnce(role, authorizationId, evidenceCommitment,
      async () => {
        expect(privatePresentation).toContain("private");
        expect(privateSignature).toContain("signature");
        return { eventHash };
      })).toEqual({ eventHash });
    expect(await journal.read(role, authorizationId)).toMatchObject({
      role, authorizationId, evidenceCommitment, state: "submitted", eventHash,
    });
    const reopened = new FileProposalSubmissionJournal(path);
    expect(await reopened.reconcile(role, authorizationId, async () => null)).toMatchObject({ state: "submitted" });
    expect(await reopened.reconcile(role, authorizationId,
      async () => ({ eventHash, evidenceCommitment }))).toMatchObject({ state: "observed" });
    await expect(reopened.executeOnce(role, authorizationId, evidenceCommitment,
      async () => ({ eventHash }))).rejects.toBeInstanceOf(ProposalSubmissionAlreadyPendingError);
    expect((await stat(path)).mode & 0o077).toBe(0);
    const serialized = await readFile(path, "utf8");
    expect(serialized).not.toContain("raw-vp-private-claims");
    expect(serialized).not.toContain("maintainer-signature");
    expect(JSON.parse(serialized).attempts).toEqual([{
      role, authorizationId, evidenceCommitment, state: "observed", eventHash,
    }]);
  });

  it("holds an ambiguous response across restart and lagging finalized reads", async () => {
    const first = new FileProposalSubmissionJournal(path);
    let executions = 0;
    await expect(first.executeOnce("issuer", authorizationId, evidenceCommitment, async () => {
      executions += 1;
      throw new Error("response lost after submission");
    })).rejects.toBeInstanceOf(ProposalSubmissionOutcomeUnknownError);
    const reopened = new FileProposalSubmissionJournal(path);
    expect(await reopened.read("issuer", authorizationId)).toMatchObject({ state: "reserved", eventHash: null });
    await expect(reopened.executeOnce("issuer", authorizationId, evidenceCommitment, async () => {
      executions += 1;
      return { eventHash };
    })).rejects.toBeInstanceOf(ProposalSubmissionAlreadyPendingError);
    expect(executions).toBe(1);
    expect(await reopened.reconcile("issuer", authorizationId, async () => null)).toMatchObject({ state: "reserved" });
    await expect(reopened.reconcile("issuer", authorizationId, async () => {
      throw new Error("finality source unavailable");
    })).rejects.toThrow("finality source unavailable");
    expect(await reopened.read("issuer", authorizationId)).toMatchObject({ state: "reserved" });
    expect(await reopened.reconcile("issuer", authorizationId,
      async () => ({ eventHash, evidenceCommitment }))).toMatchObject({ state: "observed", eventHash });
  });

  it("rejects conflicting finalized records and different evidence on the same authorization", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.executeOnce("verifier", authorizationId, evidenceCommitment, async () => ({ eventHash }));
    await expect(journal.executeOnce("verifier", authorizationId, otherCommitment,
      async () => ({ eventHash }))).rejects.toBeInstanceOf(ProposalSubmissionConflictError);
    await expect(journal.reconcile("verifier", authorizationId,
      async () => ({ eventHash, evidenceCommitment: otherCommitment })))
      .rejects.toBeInstanceOf(ProposalSubmissionConflictError);
    await expect(journal.reconcile("verifier", authorizationId,
      async () => ({ eventHash: otherEventHash, evidenceCommitment })))
      .rejects.toBeInstanceOf(ProposalSubmissionConflictError);
    expect(await journal.read("verifier", authorizationId)).toMatchObject({ state: "submitted", eventHash });
  });

  it("allows only one writer to cross the external submission boundary", async () => {
    const left = new FileProposalSubmissionJournal(path);
    const right = new FileProposalSubmissionJournal(path);
    let executions = 0;
    const run = (journal: FileProposalSubmissionJournal) => journal.executeOnce(
      "auditor", authorizationId, evidenceCommitment, async () => {
        executions += 1;
        return { eventHash };
      },
    );
    const results = await Promise.allSettled([run(left), run(right)]);
    expect(results.map((result) => result.status).sort()).toEqual(["fulfilled", "rejected"]);
    expect(executions).toBe(1);
  });

  it("does not downgrade a finalized observation when a delayed submit receipt arrives", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    let releaseSubmission!: () => void;
    let submissionStarted!: () => void;
    const started = new Promise<void>((resolveStarted) => { submissionStarted = resolveStarted; });
    const gate = new Promise<void>((resolveGate) => { releaseSubmission = resolveGate; });
    const executing = journal.executeOnce("maintainer", authorizationId, evidenceCommitment, async () => {
      submissionStarted();
      await gate;
      return { eventHash };
    });
    await started;
    expect(await journal.reconcile("maintainer", authorizationId,
      async () => ({ eventHash, evidenceCommitment }))).toMatchObject({ state: "observed" });
    releaseSubmission();
    expect(await executing).toEqual({ eventHash });
    expect(await journal.read("maintainer", authorizationId)).toMatchObject({ state: "observed", eventHash });
  });

  it("fails closed on tampered journal state and invalid input before submission", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    let executed = false;
    await expect(journal.executeOnce("issuer", authorizationId, "0x1234", async () => {
      executed = true;
      return { eventHash };
    })).rejects.toThrow();
    expect(executed).toBe(false);
    await writeFile(path, JSON.stringify({ version: 1, attempts: [{ role: "issuer", authorizationId,
      evidenceCommitment, state: "observed", eventHash: null }] }), { mode: 0o600 });
    await expect(journal.read("issuer", authorizationId)).rejects.toBeInstanceOf(InvalidProposalSubmissionJournalError);
  });

  it("reports the explicit capacity limit without crossing the submission boundary", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await writeFile(path, JSON.stringify({ version: 1, attempts: Array.from({ length: 10_000 }, (_, index) => ({
      role: "issuer", authorizationId: `existing:${index}`, evidenceCommitment,
      state: "observed", eventHash,
    })) }), { mode: 0o600 });
    let executed = false;
    await expect(journal.executeOnce("verifier", authorizationId, evidenceCommitment, async () => {
      executed = true;
      return { eventHash };
    })).rejects.toBeInstanceOf(ProposalSubmissionCapacityError);
    expect(executed).toBe(false);
  });

  it("reserves room for the event hash before submitting when valid IDs approach 4 MiB", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    const attempts = Array.from({ length: 9_500 }, (_, index) => ({
      role: "issuer", authorizationId: `existing:${index}:${"x".repeat(198 + (index < 130 ? 44 : 0))}`,
      evidenceCommitment, state: "observed", eventHash,
    }));
    const serialized = JSON.stringify({ version: 1, attempts });
    expect(Buffer.byteLength(serialized)).toBeLessThan(4 * 1024 * 1024);
    await writeFile(path, serialized, { mode: 0o600 });
    let executed = false;
    await expect(journal.executeOnce("verifier", authorizationId, evidenceCommitment, async () => {
      executed = true;
      return { eventHash };
    })).rejects.toBeInstanceOf(ProposalSubmissionCapacityError);
    expect(executed).toBe(false);
    expect(await journal.read("verifier", authorizationId)).toBeNull();
  });
});
