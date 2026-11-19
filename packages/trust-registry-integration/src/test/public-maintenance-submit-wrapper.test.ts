import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, expect, it, vi } from "vitest";
import { Transaction } from "@midnightntwrk/ledger-v9";
import { LedgerTransaction } from "@midnight-ntwrk/midnight-js-types";

import {
  FileMaintenanceTransitionJournal,
  submitLocalNetworkCommitteeTransition,
  submitPublicNetworkCommitteeTransition,
} from "../public-maintenance-submission.js";
import type { PreparedCommitteeTransition } from "../public-maintenance-transition.js";

const mocks = vi.hoisted(() => ({ prepare: vi.fn(), prepareLocal: vi.fn(), submit: vi.fn() }));
vi.mock("../public-maintenance-transition.js", () => ({
  preparePublicNetworkCommitteeTransition: mocks.prepare,
  prepareLocalNetworkCommitteeTransition: mocks.prepareLocal,
}));
vi.mock("@midnight-ntwrk/midnight-js-contracts", async (importOriginal) => ({
  ...await importOriginal<typeof import("@midnight-ntwrk/midnight-js-contracts")>(),
  submitTxAsync: mocks.submit,
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
      authorize: () => { events.push("authorize"); return Transaction.fromParts("undeployed"); },
    };
  });
  const providers = { config: { networkId: "undeployed" } };
  mocks.submit.mockImplementationOnce(async (_providers, options) => {
    expect((await journal.inspect())?.reservation.networkId).toBe("undeployed");
    expect(options.unprovenTx.era).toBe("v9");
    expect(options.unprovenTx.stage).toBe("Unproven");
    events.push("submit-sdk");
    return "tx-local";
  });
  await expect(submitLocalNetworkCommitteeTransition({
    approval: { network: { networkId: "undeployed" } } as never,
    signature: {} as never, journal, providers: providers as never,
    approvedUpdateSha256: localUpdateSha256,
    approvedFinalizedBlockHash: `0x${"b".repeat(64)}`,
  })).resolves.toBe("tx-local");
  expect(events).toEqual(["local-readback", "authorize", "submit-sdk"]);
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
    approval: { network: { networkId: "undeployed" } } as never,
    signature: {} as never,
    journal,
    providers: { config: { networkId: "undeployed" } } as never,
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
    authorize: () => Transaction.fromParts("undeployed"),
  });
  const providers = { config: { networkId: "undeployed" } };
  mocks.submit.mockResolvedValueOnce("tx-local");
  await submitLocalNetworkCommitteeTransition({
    approval: { network: { networkId: "undeployed" } } as never,
    signature: {} as never, journal, providers: providers as never,
    approvedUpdateSha256: localUpdateSha256,
    approvedFinalizedBlockHash: `0x${"b".repeat(64)}`,
  });
  const reservation = (await journal.inspect())?.reservation;
  expect(reservation?.approvedFinalizedBlockHash).toBe(`0x${"b".repeat(64)}`);
  expect(reservation?.finalizedBlockHash).toBe(`0x${"c".repeat(64)}`);
});

it("reserves after fresh readback and signature verification, before SDK submission", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-maintenance-submit-"));
  directories.push(directory);
  const journal = new FileMaintenanceTransitionJournal(join(directory, "transition.json"));
  const events: string[] = [];
  const tx = Transaction.fromParts("preprod");
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
  const providers = { config: { networkId: "preprod" } };
  mocks.submit.mockImplementationOnce(async (_providers, options) => {
    expect((await journal.inspect())?.reservation.contractAddress).toBe(plan.contractAddress);
    expect(LedgerTransaction.isLedgerTransaction(options.unprovenTx)).toBe(true);
    expect(options.unprovenTx.era).toBe("v9");
    events.push("submit-sdk");
    return "tx-public";
  });
  const input = { approval: { network: { networkId: "preprod" } } as never,
    signature: {} as never, journal, providers: providers as never };
  await expect(submitPublicNetworkCommitteeTransition(input)).resolves.toBe("tx-public");
  expect(events).toEqual(["readback", "authorize", "submit-sdk"]);
  expect((await journal.inspect())?.submitted?.txId).toBe("tx-public");
});

it("does not reserve when finalized readback or signature authorization fails", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-maintenance-submit-"));
  directories.push(directory);
  const journal = new FileMaintenanceTransitionJournal(join(directory, "transition.json"));
  const submit = vi.fn(async () => "tx-unexpected");
  const input = {
    approval: { network: { networkId: "preprod" } } as never,
    signature: {} as never,
    journal,
    providers: { config: { networkId: "preprod" }, midnightProvider: { submitTx: submit } } as never,
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

it("rejects a provider configured for another network before planning or reservation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-maintenance-submit-"));
  directories.push(directory);
  const journal = new FileMaintenanceTransitionJournal(join(directory, "transition.json"));
  await expect(submitPublicNetworkCommitteeTransition({
    approval: { network: { networkId: "preprod" } } as never,
    signature: {} as never,
    journal,
    providers: { config: { networkId: "preview" } } as never,
  })).rejects.toThrow(/approved network/u);
  expect(mocks.prepare).not.toHaveBeenCalled();
  expect(mocks.submit).not.toHaveBeenCalled();
  expect(await journal.inspect()).toBeNull();
});
