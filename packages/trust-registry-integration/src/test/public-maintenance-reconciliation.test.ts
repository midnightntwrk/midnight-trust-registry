import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { sampleSigningKey, signatureVerifyingKey } from "@midnight-ntwrk/compact-runtime";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { ContractMaintenanceAuthority, MaintenanceUpdate, ReplaceAuthority } from "@midnight-ntwrk/midnight-js-protocol/ledger";

import {
  reconcileLocalNetworkCommitteeTransition,
  reconcilePublicNetworkCommitteeTransition,
} from "../public-maintenance-reconciliation.js";
import { FileMaintenanceTransitionJournal } from "../public-maintenance-submission.js";
import type {
  CommitteeTransitionApproval,
  LocalCommitteeTransitionApproval,
  PreparedCommitteeTransition,
} from "../public-maintenance-transition.js";

const mocks = vi.hoisted(() => ({ readback: vi.fn(), localReadback: vi.fn() }));
vi.mock("../public-network-deployment.js", async (importOriginal) => ({
  ...await importOriginal<typeof import("../public-network-deployment.js")>(),
  readPostDeploymentPublicTrustRegistry: mocks.readback,
  readPostDeploymentLocalTrustRegistry: mocks.localReadback,
}));

const address = `0x${"a".repeat(64)}`;
const blockHash = `0x${"b".repeat(64)}`;
const bootstrapKey = `0x${signatureVerifyingKey(sampleSigningKey())}`;
const committee = Array.from({ length: 3 }, () => `0x${signatureVerifyingKey(sampleSigningKey())}`);
const dataToSign = new MaintenanceUpdate(address.slice(2), [
  new ReplaceAuthority(new ContractMaintenanceAuthority(committee.map((key) => key.slice(2)), 2, 1n)),
], 0n).dataToSign;
const updateSha256 = createHash("sha256").update(dataToSign).digest("hex");
const directories: string[] = [];
const approval = (): CommitteeTransitionApproval => ({
  network: { networkId: "preprod" },
  receipt: { networkId: "preprod", contractAddress: address },
  bootstrap: {},
  releaseManifest: {},
  governance: {},
  maintenancePolicy: { mode: "committee", verifyingKeys: committee, threshold: 2 },
  bootstrapMaintenanceVerifyingKey: bootstrapKey,
  expiresAt: new Date(Date.now() + 5 * 60_000),
}) as unknown as CommitteeTransitionApproval;
const localApproval = (): LocalCommitteeTransitionApproval => ({
  ...approval(),
  network: { networkId: "undeployed" },
  receipt: { networkId: "undeployed", contractAddress: address },
}) as LocalCommitteeTransitionApproval;
const plan = (input: CommitteeTransitionApproval | LocalCommitteeTransitionApproval): PreparedCommitteeTransition => ({
  networkId: input.network.networkId,
  contractAddress: address,
  finalizedBlockHash: blockHash,
  committeeVerifyingKeys: committee,
  threshold: 2,
  currentAuthorityCounter: 0n,
  nextAuthorityCounter: 1n,
  expiresAt: input.expiresAt.toISOString(),
  dataToSign,
  authorize: () => { throw new Error("not used by reconciliation tests"); },
});
const journal = async (
  reserve: boolean,
  input: CommitteeTransitionApproval | LocalCommitteeTransitionApproval,
  recordTxId = true,
): Promise<FileMaintenanceTransitionJournal> => {
  const directory = await mkdtemp(join(tmpdir(), "tr-maintenance-reconcile-"));
  directories.push(directory);
  const result = new FileMaintenanceTransitionJournal(join(directory, "transition.json"));
  if (reserve && recordTxId) await result.executeOnce(plan(input), async () => "tx-123");
  if (reserve && !recordTxId) {
    await expect(result.executeOnce(plan(input), async () => { throw new Error("lost response"); }))
      .rejects.toThrow(/may have reached the network/u);
  }
  return result;
};
const image = (counter: bigint, keys: string[]) => ({
  finalizedBlockHash: `0x${"1".repeat(64)}`,
  maintenanceAuthority: { counter, threshold: keys.length === 1 ? 1 : 2, committee: keys },
});
const reconcile = (input: CommitteeTransitionApproval, file: FileMaintenanceTransitionJournal) =>
  reconcilePublicNetworkCommitteeTransition({
    approval: input, journal: file, approvedUpdateSha256: updateSha256, approvedFinalizedBlockHash: blockHash,
  });
const reconcileLocal = (input: LocalCommitteeTransitionApproval, file: FileMaintenanceTransitionJournal) =>
  reconcileLocalNetworkCommitteeTransition({
    approval: input, journal: file, approvedUpdateSha256: updateSha256, approvedFinalizedBlockHash: blockHash,
  });

beforeEach(() => {
  vi.clearAllMocks();
  setNetworkId("preprod");
});

describe("local maintenance transition reconciliation", () => {
  it("observes the finalized local committee without using public readback or inferring transaction provenance", async () => {
    setNetworkId("undeployed");
    const input = localApproval();
    const file = await journal(true, input);
    mocks.localReadback.mockResolvedValue({ status: "verified", state: image(1n, committee) });
    await expect(reconcileLocal(input, file)).resolves.toEqual({
      status: "observed", txId: "tx-123", finalizedBlockHash: `0x${"1".repeat(64)}`,
    });
    expect(mocks.localReadback).toHaveBeenCalledWith(expect.objectContaining({
      network: input.network, receipt: input.receipt, maintenancePolicy: input.maintenancePolicy,
    }));
    expect(mocks.readback).not.toHaveBeenCalled();
  });

  it("keeps a local attempt unresolved until the committee is finalized", async () => {
    setNetworkId("undeployed");
    const input = localApproval();
    const file = await journal(true, input, false);
    mocks.localReadback.mockResolvedValue({ status: "unsafe-maintenance-authority", state: image(0n, [bootstrapKey]) });
    await expect(reconcileLocal(input, file)).resolves.toMatchObject({ status: "unresolved", txId: null });
    mocks.localReadback.mockResolvedValue({ status: "pending" });
    await expect(reconcileLocal(input, file)).resolves.toEqual({
      status: "pending", txId: null, finalizedBlockHash: null,
    });
  });

  it("rejects local network and journal-pin substitution before readback", async () => {
    setNetworkId("undeployed");
    const input = localApproval();
    const file = await journal(true, input);
    await expect(reconcileLocalNetworkCommitteeTransition({
      approval: input, journal: file, approvedUpdateSha256: "0".repeat(64),
      approvedFinalizedBlockHash: blockHash,
    })).rejects.toThrow(/disagrees/u);
    input.receipt.networkId = "preprod";
    await expect(reconcileLocal(input, file)).rejects.toThrow(/network/u);
    input.receipt.networkId = "undeployed";
    setNetworkId("preprod");
    await expect(reconcileLocal(input, file)).rejects.toThrow(/network/u);
    expect(mocks.localReadback).not.toHaveBeenCalled();
    expect(mocks.readback).not.toHaveBeenCalled();
  });
});
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("public maintenance transition reconciliation", () => {
  it("does not read the network when no attempt was reserved", async () => {
    const input = approval();
    await expect(reconcile(input, await journal(false, input)))
      .resolves.toEqual({ status: "not-reserved" });
    expect(mocks.readback).not.toHaveBeenCalled();
  });

  it("reports the exact counter-one finalized committee without claiming transaction provenance", async () => {
    const input = approval();
    const file = await journal(true, input);
    mocks.readback.mockResolvedValue({ status: "verified", state: image(1n, committee) });
    await expect(reconcile(input, file)).resolves.toEqual({
      status: "observed", txId: "tx-123", finalizedBlockHash: `0x${"1".repeat(64)}`,
    });
    expect(mocks.readback).toHaveBeenCalledWith(expect.objectContaining({
      network: input.network, receipt: input.receipt, maintenancePolicy: input.maintenancePolicy,
    }));
  });

  it("keeps the reservation unresolved while the finalized bootstrap authority remains", async () => {
    const input = approval();
    const file = await journal(true, input);
    mocks.readback.mockResolvedValue({ status: "unsafe-maintenance-authority", state: image(0n, [bootstrapKey]) });
    await expect(reconcile(input, file)).resolves.toMatchObject({ status: "unresolved", txId: "tx-123" });
  });

  it("flags the approved checkpoint as stale instead of treating it as a newer unresolved read", async () => {
    const input = approval();
    const file = await journal(true, input);
    mocks.readback.mockResolvedValue({ status: "unsafe-maintenance-authority", state: {
      ...image(0n, [bootstrapKey]), finalizedBlockHash: blockHash,
    } });
    await expect(reconcile(input, file)).resolves.toMatchObject({ status: "stale-checkpoint" });
  });

  it.each(["observed", "unresolved"])("preserves a missing transaction id for %s", async (status) => {
    const input = approval();
    const file = await journal(true, input, false);
    mocks.readback.mockResolvedValue(status === "observed"
      ? { status: "verified", state: image(1n, committee) }
      : { status: "unsafe-maintenance-authority", state: image(0n, [bootstrapKey]) });
    await expect(reconcile(input, file)).resolves.toMatchObject({ status, txId: null });
  });

  it.each(["pending", "unavailable", "invalid-image"])("reports %s without inferring a retry", async (status) => {
    const input = approval();
    const file = await journal(true, input);
    mocks.readback.mockResolvedValue({ status });
    await expect(reconcile(input, file)).resolves.toEqual({ status, txId: "tx-123", finalizedBlockHash: null });
  });

  it("reports a changed counter or mismatched image as conflict", async () => {
    const input = approval();
    const file = await journal(true, input);
    mocks.readback.mockResolvedValueOnce({ status: "verified", state: image(2n, committee) });
    await expect(reconcile(input, file)).resolves.toMatchObject({ status: "conflict" });
    mocks.readback.mockResolvedValueOnce({ status: "mismatch", state: image(1n, committee) });
    await expect(reconcile(input, file)).resolves.toMatchObject({ status: "conflict" });
    mocks.readback.mockResolvedValueOnce({ status: "unsafe-maintenance-authority", state: image(0n, [committee[0]!]) });
    await expect(reconcile(input, file)).resolves.toMatchObject({ status: "conflict" });
    mocks.readback.mockResolvedValueOnce({ status: "verified", state: {
      ...image(1n, committee), finalizedBlockHash: blockHash,
    } });
    await expect(reconcile(input, file)).resolves.toMatchObject({ status: "conflict" });
  });

  it("rejects changed approval evidence or network before finalized readback", async () => {
    const input = approval();
    const file = await journal(true, input);
    await expect(reconcilePublicNetworkCommitteeTransition({
      approval: input, journal: file, approvedUpdateSha256: "0".repeat(64),
      approvedFinalizedBlockHash: blockHash,
    })).rejects.toThrow(/disagrees/u);
    await expect(reconcilePublicNetworkCommitteeTransition({
      approval: input, journal: file, approvedUpdateSha256: updateSha256,
      approvedFinalizedBlockHash: `0x${"9".repeat(64)}`,
    })).rejects.toThrow(/disagrees/u);
    input.receipt.contractAddress = `0x${"8".repeat(64)}`;
    await expect(reconcile(input, file)).rejects.toThrow(/disagrees/u);
    input.receipt.contractAddress = address;
    input.maintenancePolicy = { ...input.maintenancePolicy, threshold: 3 };
    await expect(reconcile(input, file)).rejects.toThrow(/disagrees/u);
    input.maintenancePolicy = { ...input.maintenancePolicy, threshold: 2, verifyingKeys: [...committee].reverse() };
    await expect(reconcile(input, file)).rejects.toThrow(/disagrees/u);
    input.maintenancePolicy = { mode: "committee", verifyingKeys: committee, threshold: 2 };
    input.expiresAt = new Date(input.expiresAt.getTime() + 1000);
    await expect(reconcile(input, file)).rejects.toThrow(/disagrees/u);
    input.expiresAt = new Date(input.expiresAt.getTime() - 1000);
    input.receipt.networkId = "preview";
    await expect(reconcile(input, file)).rejects.toThrow(/network/u);
    input.receipt.networkId = "preprod";
    await expect(reconcilePublicNetworkCommitteeTransition({
      approval: input, journal: file, approvedUpdateSha256: "not-a-hash",
      approvedFinalizedBlockHash: blockHash,
    })).rejects.toThrow(/pins are invalid/u);
    await expect(reconcilePublicNetworkCommitteeTransition({
      approval: input, journal: file, approvedUpdateSha256: updateSha256,
      approvedFinalizedBlockHash: `0x${"0".repeat(64)}`,
    })).rejects.toThrow(/pins are invalid/u);
    input.receipt.contractAddress = `0x${"0".repeat(64)}`;
    await expect(reconcile(input, file)).rejects.toThrow(/pins are invalid/u);
    setNetworkId("preview");
    await expect(reconcile(input, file)).rejects.toThrow(/network/u);
    expect(mocks.readback).not.toHaveBeenCalled();
  });
});
