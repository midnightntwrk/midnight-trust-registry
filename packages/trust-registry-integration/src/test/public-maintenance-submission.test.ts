import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  FileMaintenanceTransitionJournal,
  MaintenanceTransitionAlreadyReservedError,
  MaintenanceTransitionJournalInvalidError,
  MaintenanceTransitionOutcomeUnknownError,
} from "../public-maintenance-submission.js";
import type { PreparedCommitteeTransition } from "../public-maintenance-transition.js";

const directories: string[] = [];
const path = async (): Promise<string> => {
  const directory = await mkdtemp(join(tmpdir(), "tr-maintenance-journal-"));
  directories.push(directory);
  return join(directory, "transition.json");
};
const plan = (): PreparedCommitteeTransition => ({
  networkId: "preprod",
  contractAddress: `0x${"a".repeat(64)}`,
  finalizedBlockHash: `0x${"b".repeat(64)}`,
  committeeVerifyingKeys: [`0x${"c".repeat(64)}`, `0x${"d".repeat(64)}`, `0x${"e".repeat(64)}`],
  threshold: 2,
  currentAuthorityCounter: 0n,
  nextAuthorityCounter: 1n,
  expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
  dataToSign: Uint8Array.from([1, 2, 3]),
  authorize: () => { throw new Error("not used by journal tests"); },
});

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("public maintenance submission journal", () => {
  it("reserves before submission and records the public transaction id durably", async () => {
    const journalPath = await path();
    const journal = new FileMaintenanceTransitionJournal(journalPath);
    expect(await journal.inspect()).toBeNull();
    const submit = vi.fn(async () => {
      expect((await journal.inspect())?.reservation.updateSha256).toBe(
        createHash("sha256").update(Uint8Array.from([1, 2, 3])).digest("hex"),
      );
      expect((await journal.inspect())?.reservation.expiresAt).toBeTruthy();
      return "tx-123";
    });
    await expect(journal.executeOnce(plan(), submit)).resolves.toBe("tx-123");
    expect(submit).toHaveBeenCalledOnce();
    expect((await new FileMaintenanceTransitionJournal(journalPath).inspect())?.submitted?.txId)
      .toBe("tx-123");
    expect(await readFile(journalPath, "utf8")).not.toContain("signature");
    await expect(new FileMaintenanceTransitionJournal(journalPath).executeOnce(plan(), submit))
      .rejects.toBeInstanceOf(MaintenanceTransitionAlreadyReservedError);
    expect(submit).toHaveBeenCalledOnce();
  });

  it("does not retry after a lost submission response or process restart", async () => {
    const journalPath = await path();
    const journal = new FileMaintenanceTransitionJournal(journalPath);
    const submit = vi.fn(async () => { throw new Error("connection lost after broadcast"); });
    await expect(journal.executeOnce(plan(), submit))
      .rejects.toBeInstanceOf(MaintenanceTransitionOutcomeUnknownError);
    expect((await journal.inspect())?.submitted).toBeNull();
    const restart = new FileMaintenanceTransitionJournal(journalPath);
    await expect(restart.executeOnce(plan(), submit))
      .rejects.toBeInstanceOf(MaintenanceTransitionAlreadyReservedError);
    expect(submit).toHaveBeenCalledOnce();
  });

  it("allows only one concurrent submitter for the same journal path", async () => {
    const journalPath = await path();
    const submit = vi.fn(async () => "tx-456");
    const outcomes = await Promise.allSettled([
      new FileMaintenanceTransitionJournal(journalPath).executeOnce(plan(), submit),
      new FileMaintenanceTransitionJournal(journalPath).executeOnce(plan(), submit),
    ]);
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);
    expect(submit).toHaveBeenCalledOnce();
  });

  it("fails closed on an orphaned, invalid, or world-readable record", async () => {
    const journalPath = await path();
    await writeFile(`${journalPath}.submitted`, JSON.stringify({ version: 1, txId: "tx-orphan" }), { mode: 0o600 });
    await expect(new FileMaintenanceTransitionJournal(journalPath).inspect())
      .rejects.toThrow(/without its maintenance reservation/u);
    const submit = vi.fn(async () => "tx-new");
    await expect(new FileMaintenanceTransitionJournal(journalPath).executeOnce(plan(), submit))
      .rejects.toThrow(/without its maintenance reservation/u);
    expect(submit).not.toHaveBeenCalled();
    await rm(`${journalPath}.submitted`);
    await writeFile(journalPath, "{invalid", { mode: 0o600 });
    await expect(new FileMaintenanceTransitionJournal(journalPath).inspect())
      .rejects.toBeInstanceOf(MaintenanceTransitionJournalInvalidError);
    await chmod(journalPath, 0o644);
    await expect(new FileMaintenanceTransitionJournal(journalPath).inspect())
      .rejects.toThrow(/unsafe file metadata/u);
  });

  it("refuses to reserve an attempt in a shared journal directory", async () => {
    const journalPath = await path();
    await chmod(dirname(journalPath), 0o777);
    const submit = vi.fn(async () => "tx-unsafe");
    await expect(new FileMaintenanceTransitionJournal(journalPath).executeOnce(plan(), submit))
      .rejects.toThrow(/directory must be private/u);
    expect(submit).not.toHaveBeenCalled();
  });

  it("returns the broadcast id in an error if durable id recording fails", async () => {
    const journalPath = await path();
    const journal = new FileMaintenanceTransitionJournal(journalPath);
    const submit = vi.fn(async () => {
      await writeFile(`${journalPath}.submitted`, JSON.stringify({ version: 1, txId: "other-id" }), {
        flag: "wx", mode: 0o600,
      });
      return "tx-broadcast";
    });
    await expect(journal.executeOnce(plan(), submit)).rejects.toMatchObject({
      name: "MaintenanceTransitionOutcomeUnknownError",
      txId: "tx-broadcast",
    });
    expect(submit).toHaveBeenCalledOnce();
  });

  it("requires a pre-provisioned directory and preserves a malformed returned id", async () => {
    const journalPath = await path();
    const missing = new FileMaintenanceTransitionJournal(join(dirname(journalPath), "missing", "transition.json"));
    const submit = vi.fn(async () => "tx-unexpected");
    await expect(missing.executeOnce(plan(), submit)).rejects.toMatchObject({ code: "ENOENT" });
    expect(submit).not.toHaveBeenCalled();
    const journal = new FileMaintenanceTransitionJournal(journalPath);
    await expect(journal.executeOnce(plan(), async () => ""))
      .rejects.toMatchObject({ name: "MaintenanceTransitionOutcomeUnknownError", txId: "" });
    expect((await journal.inspect())?.submitted).toBeNull();
  });
});
