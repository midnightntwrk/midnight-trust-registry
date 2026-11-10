import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, expect, it, vi } from "vitest";

import {
  FileMaintenanceTransitionJournal,
  submitLocalNetworkCommitteeTransition,
  submitPublicNetworkCommitteeTransition,
} from "../public-maintenance-submission.js";
import type { PreparedCommitteeTransition } from "../public-maintenance-transition.js";

const mocks = vi.hoisted(() => ({ prepare: vi.fn(), prepareLocal: vi.fn() }));
vi.mock("../public-maintenance-transition.js", () => ({
  preparePublicNetworkCommitteeTransition: mocks.prepare,
  prepareLocalNetworkCommitteeTransition: mocks.prepareLocal,
}));

const directories: string[] = [];
const localUpdateSha256 = createHash("sha256").update(Uint8Array.from([1, 2, 3])).digest("hex");
afterEach(async () => {
  vi.clearAllMocks();
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

it("submits the local update only after the local planner and durable reservation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-maintenance-submit-"));
  directories.push(directory);
  const journal = new FileMaintenanceTransitionJournal(join(directory, "transition.json"));
  const events: string[] = [];
  mocks.prepareLocal.mockImplementation(async () => {
    events.push("local-readback");
    return {
      networkId: "undeployed",
      contractAddress: `0x${"a".repeat(64)}`,
      finalizedBlockHash: `0x${"b".repeat(64)}`,
      committeeVerifyingKeys: [`0x${"c".repeat(64)}`, `0x${"d".repeat(64)}`, `0x${"e".repeat(64)}`],
      threshold: 2,
      currentAuthorityCounter: 0n,
      nextAuthorityCounter: 1n,
      expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
      dataToSign: Uint8Array.from([1, 2, 3]),
      authorize: () => { events.push("authorize"); return { kind: "local-maintenance" }; },
    };
  });
  const providers = {
    proofProvider: { proveTx: async () => {
      expect((await journal.inspect())?.reservation.networkId).toBe("undeployed");
      events.push("prove");
      return "proven";
    } },
    walletProvider: { balanceTx: async () => "balanced" },
    midnightProvider: { submitTx: async () => "tx-local" },
  };
  await expect(submitLocalNetworkCommitteeTransition({
    approval: {} as never, signature: {} as never, journal, providers: providers as never,
    approvedUpdateSha256: localUpdateSha256,
    approvedFinalizedBlockHash: `0x${"b".repeat(64)}`,
  })).resolves.toBe("tx-local");
  expect(events).toEqual(["local-readback", "authorize", "prove"]);
  expect(mocks.prepare).not.toHaveBeenCalled();
  expect((await journal.inspect())?.submitted?.txId).toBe("tx-local");
});

it("rejects a changed local signing request or malformed approved checkpoint before reservation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-maintenance-submit-"));
  directories.push(directory);
  const journal = new FileMaintenanceTransitionJournal(join(directory, "transition.json"));
  const authorize = vi.fn();
  mocks.prepareLocal.mockResolvedValue({
    finalizedBlockHash: `0x${"b".repeat(64)}`,
    dataToSign: Uint8Array.from([1, 2, 3]),
    authorize,
  });
  const input = {
    approval: {} as never,
    signature: {} as never,
    journal,
    providers: {} as never,
    approvedUpdateSha256: localUpdateSha256,
    approvedFinalizedBlockHash: `0x${"b".repeat(64)}`,
  };
  await expect(submitLocalNetworkCommitteeTransition({
    ...input, approvedUpdateSha256: "a".repeat(64),
  })).rejects.toThrow(/disagrees with the approved signing request/u);
  await expect(submitLocalNetworkCommitteeTransition({
    ...input, approvedFinalizedBlockHash: `0x${"0".repeat(64)}`,
  })).rejects.toThrow(/signing pins are invalid/u);
  expect(authorize).not.toHaveBeenCalled();
  expect(await journal.inspect()).toBeNull();
});

it("accepts a newer finalized head when the approved maintenance update is unchanged", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-maintenance-submit-"));
  directories.push(directory);
  const journal = new FileMaintenanceTransitionJournal(join(directory, "transition.json"));
  mocks.prepareLocal.mockResolvedValue({
    networkId: "undeployed", contractAddress: `0x${"a".repeat(64)}`,
    finalizedBlockHash: `0x${"c".repeat(64)}`,
    committeeVerifyingKeys: [`0x${"d".repeat(64)}`, `0x${"e".repeat(64)}`, `0x${"f".repeat(64)}`],
    threshold: 2, currentAuthorityCounter: 2n, nextAuthorityCounter: 3n,
    expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    dataToSign: Uint8Array.from([1, 2, 3]),
    authorize: () => ({ kind: "signed-maintenance" }),
  });
  const providers = {
    proofProvider: { proveTx: async () => "proven" },
    walletProvider: { balanceTx: async () => "balanced" },
    midnightProvider: { submitTx: async () => "tx-local" },
  };
  await submitLocalNetworkCommitteeTransition({
    approval: {} as never, signature: {} as never, journal, providers: providers as never,
    approvedUpdateSha256: localUpdateSha256,
    approvedFinalizedBlockHash: `0x${"b".repeat(64)}`,
  });
  const reservation = (await journal.inspect())?.reservation;
  expect(reservation?.approvedFinalizedBlockHash).toBe(`0x${"b".repeat(64)}`);
  expect(reservation?.finalizedBlockHash).toBe(`0x${"c".repeat(64)}`);
});

it("reserves after fresh readback and signature verification, before prove/balance/submit", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-maintenance-submit-"));
  directories.push(directory);
  const journal = new FileMaintenanceTransitionJournal(join(directory, "transition.json"));
  const events: string[] = [];
  const tx = { kind: "unproven-maintenance" };
  const plan: PreparedCommitteeTransition = {
    networkId: "preprod",
    contractAddress: `0x${"a".repeat(64)}`,
    finalizedBlockHash: `0x${"b".repeat(64)}`,
    committeeVerifyingKeys: [`0x${"c".repeat(64)}`, `0x${"d".repeat(64)}`, `0x${"e".repeat(64)}`],
    threshold: 2,
    currentAuthorityCounter: 0n,
    nextAuthorityCounter: 1n,
    expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    dataToSign: Uint8Array.from([1, 2, 3]),
    authorize: () => { events.push("authorize"); return tx as never; },
  };
  mocks.prepare.mockImplementation(async () => { events.push("readback"); return plan; });
  const providers = {
    proofProvider: { proveTx: async (value: unknown) => {
      expect(value).toBe(tx);
      expect((await journal.inspect())?.reservation.contractAddress).toBe(plan.contractAddress);
      events.push("prove");
      return "proven";
    } },
    walletProvider: { balanceTx: async (value: unknown) => {
      expect(value).toBe("proven");
      events.push("balance");
      return "balanced";
    } },
    midnightProvider: { submitTx: async (value: unknown) => {
      expect(value).toBe("balanced");
      events.push("submit");
      return "tx-public";
    } },
  };
  const input = { approval: {} as never, signature: {} as never, journal, providers: providers as never };
  await expect(submitPublicNetworkCommitteeTransition(input)).resolves.toBe("tx-public");
  expect(events).toEqual(["readback", "authorize", "prove", "balance", "submit"]);
  expect((await journal.inspect())?.submitted?.txId).toBe("tx-public");
});

it("does not reserve when finalized readback or signature authorization fails", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-maintenance-submit-"));
  directories.push(directory);
  const journal = new FileMaintenanceTransitionJournal(join(directory, "transition.json"));
  const submit = vi.fn(async () => "tx-unexpected");
  const input = {
    approval: {} as never,
    signature: {} as never,
    journal,
    providers: { midnightProvider: { submitTx: submit } } as never,
  };
  mocks.prepare.mockRejectedValueOnce(new Error("finalized image unavailable"));
  await expect(submitPublicNetworkCommitteeTransition(input))
    .rejects.toThrow(/image unavailable/u);
  expect(await journal.inspect()).toBeNull();
  mocks.prepare.mockResolvedValueOnce({
    authorize: () => { throw new Error("signature invalid"); },
  });
  await expect(submitPublicNetworkCommitteeTransition(input))
    .rejects.toThrow(/signature invalid/u);
  expect(await journal.inspect()).toBeNull();
  expect(submit).not.toHaveBeenCalled();
});
