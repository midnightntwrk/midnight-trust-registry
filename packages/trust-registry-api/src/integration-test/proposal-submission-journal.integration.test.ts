import { createHash } from "node:crypto";
import { fork } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  FileProposalSubmissionJournal,
  InvalidProposalSubmissionJournalError,
  ProposalSubmissionAlreadyPendingError,
  ProposalSubmissionBlockedByReservationError,
  ProposalSubmissionCapacityError,
  ProposalSubmissionConflictError,
  ProposalSubmissionOutcomeUnknownError,
  type GovernedProposalSubmissionRole,
} from "../proposal-submission-journal.js";

const evidenceCommitment = `0x${"11".repeat(32)}`;
const otherCommitment = `0x${"22".repeat(32)}`;
const eventHash = `0x${"33".repeat(32)}`;
const otherEventHash = `0x${"44".repeat(32)}`;
const reservationContext = {
  actionSequence: "7",
  actionKind: `0x${"55".repeat(32)}`,
  actionPayloadHash: `0x${"66".repeat(32)}`,
};
const authorizationId = "auth:journal:test:v1";
const roles: GovernedProposalSubmissionRole[] = ["issuer", "verifier", "auditor", "maintainer", "recognition"];

describe("private governed proposal submission journal", () => {
  let directory: string;
  let path: string;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "tr-proposal-submission-"));
    path = join(directory, "journal.json");
  });
  afterEach(async () => { await rm(directory, { recursive: true, force: true }); });

  it("reads a reservation and deployment binding atomically without releasing it", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    const contractAddress = `0x${"aa".repeat(32)}`;
    const genesisHash = `0x${"bb".repeat(32)}`;
    await journal.bindDeployment("registry:local", contractAddress, genesisHash);
    await expect(journal.executeOnce("issuer", authorizationId, evidenceCommitment,
      async () => { throw new Error("ambiguous submission"); }, reservationContext))
      .rejects.toBeInstanceOf(ProposalSubmissionOutcomeUnknownError);
    const before = await readFile(path);
    const bound = await journal.readBoundAttempt("registry:local", contractAddress, genesisHash,
      "issuer", authorizationId);
    expect(bound.attempt).toMatchObject({ state: "reserved", reservationContext });
    expect(bound.bindingDigest).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(await readFile(path)).toEqual(before);
    await expect(journal.readBoundAttempt("registry:local", contractAddress,
      `0x${"cc".repeat(32)}`, "issuer", authorizationId))
      .rejects.toBeInstanceOf(ProposalSubmissionConflictError);
    expect(await journal.readBoundAttempt("registry:local", contractAddress, genesisHash,
      "issuer", "missing")).toMatchObject({ attempt: null, bindingDigest: bound.bindingDigest });
  });

  it.each(roles)("persists %s receipt without treating it as finality", async (role) => {
    const journal = new FileProposalSubmissionJournal(path);
    const privatePresentation = "raw-vp-private-claims";
    const privateSignature = "maintainer-signature";
    expect(await journal.executeOnce(role, authorizationId, evidenceCommitment,
      async () => {
        expect(privatePresentation).toContain("private");
        expect(privateSignature).toContain("signature");
        return { eventHash };
      }, reservationContext)).toEqual({ eventHash });
    expect(await journal.read(role, authorizationId)).toMatchObject({
      role, authorizationId, evidenceCommitment, state: "submitted", eventHash, reservationContext,
    });
    const reopened = new FileProposalSubmissionJournal(path);
    expect(await reopened.reconcile(role, authorizationId, async () => null)).toMatchObject({ state: "submitted" });
    expect(await reopened.reconcile(role, authorizationId,
      async () => ({ eventHash, evidenceCommitment }))).toMatchObject({ state: "observed", reservationContext });
    await expect(reopened.executeOnce(role, authorizationId, evidenceCommitment,
      async () => ({ eventHash }))).rejects.toBeInstanceOf(ProposalSubmissionAlreadyPendingError);
    expect((await stat(path)).mode & 0o077).toBe(0);
    const serialized = await readFile(path, "utf8");
    expect(serialized).not.toContain("raw-vp-private-claims");
    expect(serialized).not.toContain("maintainer-signature");
    expect(JSON.parse(serialized).attempts).toEqual([{
      role, authorizationId, evidenceCommitment, state: "observed", eventHash, reservationContext,
    }]);
    expect(await reopened.rotateObserved(async () => ({ eventHash, evidenceCommitment })))
      .toEqual({ archived: 1, pending: 0 });
    expect(await new FileProposalSubmissionJournal(path).read(role, authorizationId))
      .toMatchObject({ state: "observed", reservationContext });
  });

  it.each(roles)("holds an ambiguous %s response across restart and lagging finalized reads", async (role) => {
    const first = new FileProposalSubmissionJournal(path);
    let executions = 0;
    await expect(first.executeOnce(role, authorizationId, evidenceCommitment, async () => {
      executions += 1;
      throw new Error("response lost after submission");
    })).rejects.toBeInstanceOf(ProposalSubmissionOutcomeUnknownError);
    const reopened = new FileProposalSubmissionJournal(path);
    expect(await reopened.read(role, authorizationId)).toMatchObject({ state: "reserved", eventHash: null });
    const otherRole = role === "issuer" ? "verifier" : "issuer";
    const submitOther = () => reopened.executeOnce(otherRole, "auth:journal:other", evidenceCommitment, async () => {
      executions += 1;
      return { eventHash: otherEventHash };
    });
    await expect(submitOther()).rejects.toMatchObject({
      blockingRole: role, blockingAuthorizationId: authorizationId,
    });
    await expect(reopened.executeOnce(role, authorizationId, evidenceCommitment, async () => {
      executions += 1;
      return { eventHash };
    })).rejects.toBeInstanceOf(ProposalSubmissionAlreadyPendingError);
    expect(executions).toBe(1);
    expect(await reopened.reconcile(role, authorizationId, async () => null)).toMatchObject({ state: "reserved" });
    await expect(submitOther()).rejects.toBeInstanceOf(ProposalSubmissionBlockedByReservationError);
    await expect(reopened.reconcile(role, authorizationId,
      async () => ({ eventHash, evidenceCommitment: otherCommitment })))
      .rejects.toBeInstanceOf(ProposalSubmissionConflictError);
    expect(await reopened.read(role, authorizationId)).toMatchObject({ state: "reserved", eventHash: null });
    await expect(submitOther()).rejects.toBeInstanceOf(ProposalSubmissionBlockedByReservationError);
    await expect(reopened.reconcile(role, authorizationId, async () => {
      throw new Error("finality source unavailable");
    })).rejects.toThrow("finality source unavailable");
    expect(await reopened.read(role, authorizationId)).toMatchObject({ state: "reserved" });
    expect(await reopened.reconcile(role, authorizationId,
      async () => ({ eventHash, evidenceCommitment }))).toMatchObject({ state: "observed", eventHash });
    await expect(submitOther()).resolves.toEqual({ eventHash: otherEventHash });
    expect(executions).toBe(2);
  });

  it("retains signed action context through an ambiguous result and restart", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await expect(journal.executeOnce("issuer", authorizationId, evidenceCommitment,
      async () => { throw new Error("submission outcome unknown"); }, reservationContext))
      .rejects.toBeInstanceOf(ProposalSubmissionOutcomeUnknownError);
    const reopened = new FileProposalSubmissionJournal(path);
    expect(await reopened.read("issuer", authorizationId)).toMatchObject({
      state: "reserved", reservationContext,
    });
    expect(JSON.parse(await readFile(path, "utf8")).attempts[0].reservationContext).toEqual(reservationContext);
    expect(await reopened.reconcile("issuer", authorizationId,
      async () => ({ eventHash, evidenceCommitment }))).toMatchObject({
      state: "observed", reservationContext,
    });
    expect(await reopened.rotateObserved(async () => ({ eventHash, evidenceCommitment })))
      .toEqual({ archived: 1, pending: 0 });
    expect(await new FileProposalSubmissionJournal(path).read("issuer", authorizationId))
      .toMatchObject({ state: "observed", reservationContext });
  });

  it("rejects invalid signed action context before creating a reservation", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    let executed = false;
    await expect(journal.executeOnce("issuer", authorizationId, evidenceCommitment, async () => {
      executed = true;
      return { eventHash };
    }, { ...reservationContext, actionSequence: (1n << 64n).toString() })).rejects.toThrow();
    expect(executed).toBe(false);
    expect(await journal.read("issuer", authorizationId)).toBeNull();
    await writeFile(path, JSON.stringify({
      version: 1,
      attempts: [{ role: "issuer", authorizationId, evidenceCommitment,
        state: "reserved", eventHash: null,
        reservationContext: { ...reservationContext, actionSequence: (1n << 64n).toString() } }],
    }), { mode: 0o600 });
    await expect(journal.read("issuer", authorizationId)).rejects
      .toBeInstanceOf(InvalidProposalSubmissionJournalError);
    await writeFile(path, JSON.stringify({
      version: 1,
      attempts: [{ role: "issuer", authorizationId, evidenceCommitment,
        state: "reserved", eventHash: null,
        reservationContext: { ...reservationContext, actionSequence: "not-a-sequence" } }],
    }), { mode: 0o600 });
    await expect(journal.read("issuer", authorizationId)).rejects
      .toBeInstanceOf(InvalidProposalSubmissionJournalError);
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

  it("blocks a distinct key while another writer holds the first reservation", async () => {
    const first = new FileProposalSubmissionJournal(path);
    const second = new FileProposalSubmissionJournal(path);
    let signalStarted!: () => void;
    let releaseSubmission!: () => void;
    const started = new Promise<void>((resolve) => { signalStarted = resolve; });
    const gate = new Promise<void>((resolve) => { releaseSubmission = resolve; });
    let executions = 0;
    const pending = first.executeOnce("issuer", authorizationId, evidenceCommitment, async () => {
      executions += 1;
      signalStarted();
      await gate;
      return { eventHash };
    });
    await started;
    await expect(second.executeOnce("verifier", "auth:another", evidenceCommitment, async () => {
      executions += 1;
      return { eventHash: otherEventHash };
    })).rejects.toMatchObject({
      blockingRole: "issuer", blockingAuthorizationId: authorizationId,
    });
    releaseSubmission();
    await expect(pending).resolves.toEqual({ eventHash });
    expect(await first.read("issuer", authorizationId)).toMatchObject({ state: "submitted", eventHash });
    await expect(second.executeOnce("verifier", "auth:after-receipt", evidenceCommitment, async () => {
      executions += 1;
      return { eventHash: otherEventHash };
    })).resolves.toEqual({ eventHash: otherEventHash });
    expect(executions).toBe(2);
  });

  it("re-reads a reserved proposal written under a different process's filesystem lock", async () => {
    const child = fork(fileURLToPath(new URL("./fixtures/seed-reserved-proposal-lock.mjs", import.meta.url)),
      [path, "issuer", authorizationId, evidenceCommitment],
      { stdio: ["ignore", "ignore", "pipe", "ipc"] });
    let diagnostic = "";
    child.stderr?.on("data", (chunk: Buffer) => { diagnostic += chunk.toString(); });
    try {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`Child lock timed out: ${diagnostic}`)), 10_000);
        const finish = () => {
          clearTimeout(timer);
          child.off("message", onMessage);
          child.off("error", onError);
          child.off("exit", onExit);
        };
        const onMessage = (message: unknown) => {
          if (message !== "locked") return;
          finish();
          resolve();
        };
        const onError = (error: Error) => { finish(); reject(error); };
        const onExit = (code: number | null) => {
          finish();
          reject(new Error(`Child exited before locking (${String(code)}): ${diagnostic}`));
        };
        child.on("message", onMessage);
        child.once("error", onError);
        child.once("exit", onExit);
      });
      let executions = 0;
      const outcome = new FileProposalSubmissionJournal(path).executeOnce("verifier", "auth:other-process",
        evidenceCommitment, async () => {
          executions += 1;
          return { eventHash: otherEventHash };
        }).then(
        () => ({ succeeded: true as const }),
        (error: unknown) => ({ succeeded: false as const, error }),
      );
      const exited = new Promise<void>((resolve, reject) => {
        child.once("exit", (code) => code === 0 ? resolve()
          : reject(new Error(`Child lock holder failed (${String(code)}): ${diagnostic}`)));
        child.once("error", reject);
      });
      child.send("release");
      await exited;
      expect(await outcome).toMatchObject({
        succeeded: false,
        error: { blockingRole: "issuer", blockingAuthorizationId: authorizationId },
      });
      expect(executions).toBe(0);
    } finally {
      if (child.exitCode === null) child.kill();
    }
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

  it("budgets the new proposal receipt at the active byte boundary", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    const attempts = Array.from({ length: 9_500 }, (_, index) => ({
      role: "issuer", authorizationId: `existing:${index}:${"x".repeat(198 + (index < 129 ? 44 : 0))}`,
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

  it("rotates observed history without freeing an authorization for resubmission", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.executeOnce("issuer", authorizationId, evidenceCommitment, async () => ({ eventHash }));
    await journal.reconcile("issuer", authorizationId, async () => ({ eventHash, evidenceCommitment }));
    await expect(journal.executeOnce("issuer", "unknown-outcome", evidenceCommitment, async () => {
      throw new Error("response lost");
    })).rejects.toBeInstanceOf(ProposalSubmissionOutcomeUnknownError);

    expect(await journal.rotateObserved(async () => ({ eventHash, evidenceCommitment })))
      .toEqual({ archived: 1, pending: 1 });
    const reopened = new FileProposalSubmissionJournal(path);
    expect(await reopened.inspectCapacity()).toMatchObject({
      activeEntries: 1, pendingEntries: 1, archivedEntries: 1, archiveCount: 1,
      maxActiveEntries: 10_000, maxActiveBytes: 4 * 1024 * 1024, maxArchives: 64,
    });
    expect(await reopened.read("issuer", authorizationId)).toMatchObject({ state: "observed", eventHash });
    expect(await reopened.read("issuer", "unknown-outcome")).toMatchObject({ state: "reserved", eventHash: null });
    await expect(reopened.executeOnce("verifier", "auth:after-rotation", evidenceCommitment,
      async () => ({ eventHash: otherEventHash })))
      .rejects.toBeInstanceOf(ProposalSubmissionBlockedByReservationError);
    let executions = 0;
    await expect(reopened.executeOnce("issuer", authorizationId, evidenceCommitment, async () => {
      executions += 1;
      return { eventHash };
    })).rejects.toBeInstanceOf(ProposalSubmissionAlreadyPendingError);
    await expect(reopened.executeOnce("issuer", "unknown-outcome", evidenceCommitment, async () => {
      executions += 1;
      return { eventHash };
    })).rejects.toBeInstanceOf(ProposalSubmissionAlreadyPendingError);
    expect(executions).toBe(0);
    expect(await reopened.reconcile("issuer", "unknown-outcome",
      async () => ({ eventHash: otherEventHash, evidenceCommitment })))
      .toMatchObject({ state: "observed", eventHash: otherEventHash });
    expect(await reopened.rotateObserved(async () => ({ eventHash: otherEventHash, evidenceCommitment })))
      .toEqual({ archived: 1, pending: 0 });
    expect(await reopened.read("issuer", "unknown-outcome")).toMatchObject({ state: "observed" });
    expect(await reopened.inspectCapacity()).toMatchObject({
      activeEntries: 0, pendingEntries: 0, archivedEntries: 2, archiveCount: 2,
    });
  });

  it("requires matching finalized evidence for every row before changing the journal", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.executeOnce("issuer", authorizationId, evidenceCommitment, async () => ({ eventHash }));
    await journal.reconcile("issuer", authorizationId, async () => ({ eventHash, evidenceCommitment }));
    const before = await readFile(path, "utf8");
    await expect(journal.rotateObserved(async () => null))
      .rejects.toBeInstanceOf(ProposalSubmissionConflictError);
    await expect(journal.rotateObserved(async () => ({ eventHash: otherEventHash, evidenceCommitment })))
      .rejects.toBeInstanceOf(ProposalSubmissionConflictError);
    await expect(journal.rotateObserved(async () => {
      throw new Error("finality reader unavailable");
    })).rejects.toThrow("finality reader unavailable");
    expect(await readFile(path, "utf8")).toBe(before);
    expect(await journal.inspectCapacity()).toMatchObject({ activeEntries: 1, archiveCount: 0 });
    let readRole: string | undefined;
    let readId: string | undefined;
    await journal.rotateObserved(async (role, id) => {
      readRole = role;
      readId = id;
      return { eventHash, evidenceCommitment };
    });
    expect([readRole, readId]).toEqual(["issuer", authorizationId]);
  });

  it("crosses the entry limit only after durable rotation and still rejects archived duplicates", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await writeFile(path, JSON.stringify({ version: 1, attempts: Array.from({ length: 10_000 }, (_, index) => ({
      role: "issuer", authorizationId: `existing:${index}`, evidenceCommitment,
      state: "observed", eventHash,
    })) }), { mode: 0o600 });
    let executions = 0;
    await expect(journal.executeOnce("verifier", authorizationId, evidenceCommitment, async () => {
      executions += 1;
      return { eventHash };
    })).rejects.toBeInstanceOf(ProposalSubmissionCapacityError);
    expect(executions).toBe(0);
    expect(await journal.rotateObserved(async () => ({ eventHash, evidenceCommitment })))
      .toEqual({ archived: 10_000, pending: 0 });
    expect(await journal.executeOnce("verifier", authorizationId, evidenceCommitment, async () => {
      executions += 1;
      return { eventHash };
    })).toEqual({ eventHash });
    await expect(journal.executeOnce("issuer", "existing:0", evidenceCommitment, async () => {
      executions += 1;
      return { eventHash };
    })).rejects.toBeInstanceOf(ProposalSubmissionAlreadyPendingError);
    expect(executions).toBe(1);
  });

  it("ignores an uncommitted segment and fails closed on a missing or altered committed archive", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.executeOnce("issuer", authorizationId, evidenceCommitment, async () => ({ eventHash }));
    await journal.reconcile("issuer", authorizationId, async () => ({ eventHash, evidenceCommitment }));
    await writeFile(join(directory, "journal.json.00000000-0000-0000-0000-000000000000.segment"),
      "orphaned before manifest commit", { mode: 0o600 });
    expect(await journal.read("issuer", authorizationId)).toMatchObject({ state: "observed" });
    await journal.rotateObserved(async () => ({ eventHash, evidenceCommitment }));
    const manifest = JSON.parse(await readFile(path, "utf8")) as {
      archives: Array<{ file: string }>;
    };
    const archivePath = join(directory, manifest.archives[0]!.file);
    await writeFile(archivePath, "tampered", { mode: 0o600 });
    let executed = false;
    await expect(journal.executeOnce("verifier", authorizationId, evidenceCommitment, async () => {
      executed = true;
      return { eventHash };
    })).rejects.toBeInstanceOf(InvalidProposalSubmissionJournalError);
    expect(executed).toBe(false);
    await rm(archivePath);
    await expect(journal.read("issuer", authorizationId)).rejects.toBeInstanceOf(InvalidProposalSubmissionJournalError);
    expect((await readdir(directory)).some((name) => name.endsWith(".segment"))).toBe(true);
  });

  it("allows one concurrent submission after rotation", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.executeOnce("issuer", authorizationId, evidenceCommitment, async () => ({ eventHash }));
    await journal.reconcile("issuer", authorizationId, async () => ({ eventHash, evidenceCommitment }));
    await journal.rotateObserved(async () => ({ eventHash, evidenceCommitment }));
    const left = new FileProposalSubmissionJournal(path);
    const right = new FileProposalSubmissionJournal(path);
    let executions = 0;
    const run = (writer: FileProposalSubmissionJournal) => writer.executeOnce(
      "auditor", "concurrent-after-rotation", evidenceCommitment, async () => {
        executions += 1;
        return { eventHash };
      },
    );
    expect((await Promise.allSettled([run(left), run(right)]))
      .map((result) => result.status).sort()).toEqual(["fulfilled", "rejected"]);
    expect(executions).toBe(1);
  });

  it("denies concurrent submissions at the rotated segment byte boundary", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.executeOnce("issuer", authorizationId, evidenceCommitment, async () => ({ eventHash }));
    await journal.reconcile("issuer", authorizationId, async () => ({ eventHash, evidenceCommitment }));
    await journal.rotateObserved(async () => ({ eventHash, evidenceCommitment }));
    const manifest = JSON.parse(await readFile(path, "utf8")) as {
      active: { file: string; sha256: string };
    };
    const active = JSON.stringify({ version: 1, attempts: Array.from({ length: 9_500 }, (_, index) => ({
      role: "issuer", authorizationId: `existing:${index}:${"x".repeat(198 + (index < 129 ? 44 : 0))}`,
      evidenceCommitment, state: "observed", eventHash,
    })) });
    expect(Buffer.byteLength(active)).toBeLessThan(4 * 1024 * 1024);
    await writeFile(join(directory, manifest.active.file), active, { mode: 0o600 });
    manifest.active.sha256 = createHash("sha256").update(active).digest("hex");
    await writeFile(path, JSON.stringify(manifest), { mode: 0o600 });
    let executions = 0;
    const run = (writer: FileProposalSubmissionJournal) => writer.executeOnce(
      "verifier", authorizationId, evidenceCommitment, async () => {
        executions += 1;
        return { eventHash };
      },
    );
    const results = await Promise.allSettled([
      run(new FileProposalSubmissionJournal(path)), run(new FileProposalSubmissionJournal(path)),
    ]);
    expect(results.map((result) => result.status)).toEqual(["rejected", "rejected"]);
    for (const result of results) {
      if (result.status === "rejected") expect(result.reason).toBeInstanceOf(ProposalSubmissionCapacityError);
    }
    expect(executions).toBe(0);
    expect(await journal.read("verifier", authorizationId)).toBeNull();
  });
});
