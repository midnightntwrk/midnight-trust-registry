import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  loadPlan: vi.fn(),
  createSource: vi.fn(),
  resolveProposal: vi.fn(),
  createServer: vi.fn(),
}));

vi.mock("../local-ledger-runtime.js", () => ({
  assertLocalApiImageSourceRevision: vi.fn(),
  loadApprovedLocalLedgerRuntimePlan: mocks.loadPlan,
  createApprovedLocalLedgerRuntimeSource: mocks.createSource,
}));
vi.mock("../compact-proposal-observation.js", () => ({
  resolveCompactProposalEvidenceSnapshot: mocks.resolveProposal,
}));
vi.mock("../server.js", () => ({ createTrustRegistryApiServer: mocks.createServer }));

import { runTrustRegistryApiCli } from "../cli.js";
import { FileProposalSubmissionJournal } from "../proposal-submission-journal.js";

const authorizationId = "issuer:local:1";
const evidenceCommitment = `0x${"c".repeat(64)}`;
const eventHash = `0x${"b".repeat(64)}`;
const genesisHash = `0x${"d".repeat(64)}`;
const reservationContext = {
  actionSequence: "1", actionKind: `0x${"1".repeat(64)}`,
  actionPayloadHash: `0x${"2".repeat(64)}`,
};
let directory: string;
let path: string;
let output: string[];

const args = () => ["reconcile-local-proposal", "--local-ledger-plan", "/run/api-plan.json",
  "--local-ledger-signature", "/run/api-plan.sig",
  "--local-ledger-keyring", "/run/keyring",
  "--local-ledger-reviewer", "A".repeat(40),
  "--role", "issuer", "--authorization-id", authorizationId,
  "--submission-journal", path];

beforeEach(async () => {
  vi.clearAllMocks();
  directory = await mkdtemp(join(tmpdir(), "tr-local-reconcile-"));
  path = join(directory, "proposals.json");
  output = [];
  vi.spyOn(process.stdout, "write").mockImplementation((value) => {
    output.push(String(value));
    return true;
  });
  mocks.loadPlan.mockResolvedValue({ contractAddress: `0x${"a".repeat(64)}`, expectedGenesisHash: genesisHash });
  mocks.createSource.mockResolvedValue({
    loadSnapshot: vi.fn().mockResolvedValue({ registry: { registryId: "registry:local" } }),
    readFinalizedProposalLedger: vi.fn(),
  });
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(directory, { recursive: true, force: true });
});

describe("signed local proposal reconciliation CLI", () => {
  it("marks a submitted attempt observed only after exact verified ledger evidence", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment("registry:local", `0x${"a".repeat(64)}`, genesisHash);
    await journal.executeOnce("issuer", authorizationId, evidenceCommitment,
      async () => ({ eventHash }), reservationContext);
    mocks.resolveProposal.mockResolvedValueOnce({ eventHash, evidenceCommitment });

    await runTrustRegistryApiCli(args());
    expect(mocks.loadPlan).toHaveBeenCalledWith(expect.objectContaining({ requireApiRuntimePin: true }));
    expect(mocks.resolveProposal).toHaveBeenCalledWith(
      expect.any(Function), "registry:local", "issuer", authorizationId,
    );
    expect(await journal.read("issuer", authorizationId)).toMatchObject({ state: "observed", eventHash });
    expect(JSON.parse(output.join(""))).toMatchObject({
      format: "tr-local-proposal-reconciliation-v1", status: "observed", state: "observed",
      eventHash, evidenceCommitment, retryPermitted: false, releaseQualified: false,
    });
    expect(mocks.createServer).not.toHaveBeenCalled();
  });

  it("keeps an unknown attempt reserved when no proposal is observed", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment("registry:local", `0x${"a".repeat(64)}`, genesisHash);
    await expect(journal.executeOnce("issuer", authorizationId, evidenceCommitment, async () => {
      throw new Error("response lost");
    }, reservationContext)).rejects.toThrow(/may have reached Compact/u);
    mocks.resolveProposal.mockResolvedValueOnce(null);

    await runTrustRegistryApiCli(args());
    expect(await journal.read("issuer", authorizationId)).toMatchObject({ state: "reserved", eventHash: null });
    expect(JSON.parse(output.join(""))).toMatchObject({
      status: "not-observed", state: "reserved", eventHash: null, retryPermitted: false, releaseQualified: false,
    });
  });

  it("leaves a conflicting submission unchanged and emits no success report", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment("registry:local", `0x${"a".repeat(64)}`, genesisHash);
    await journal.executeOnce("issuer", authorizationId, evidenceCommitment,
      async () => ({ eventHash }), reservationContext);
    mocks.resolveProposal.mockResolvedValueOnce({
      eventHash: `0x${"d".repeat(64)}`, evidenceCommitment,
    });

    await expect(runTrustRegistryApiCli(args())).rejects.toThrow(/conflict/iu);
    expect(await journal.read("issuer", authorizationId)).toMatchObject({ state: "submitted", eventHash });
    expect(output).toEqual([]);
  });

  it("fails closed on mismatched evidence or unavailable finalized readback", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment("registry:local", `0x${"a".repeat(64)}`, genesisHash);
    await journal.executeOnce("issuer", authorizationId, evidenceCommitment,
      async () => ({ eventHash }), reservationContext);
    mocks.resolveProposal.mockResolvedValueOnce({ eventHash, evidenceCommitment: `0x${"f".repeat(64)}` });
    await expect(runTrustRegistryApiCli(args())).rejects.toThrow(/conflict/iu);
    mocks.resolveProposal.mockRejectedValueOnce(new Error("finalized reader unavailable"));
    await expect(runTrustRegistryApiCli(args())).rejects.toThrow(/finalized reader unavailable/u);
    expect(await journal.read("issuer", authorizationId)).toMatchObject({ state: "submitted", eventHash });
    expect(output).toEqual([]);
  });

  it("does not read or mutate the journal when the signed plan is stale", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment("registry:local", `0x${"a".repeat(64)}`, genesisHash);
    await journal.executeOnce("issuer", authorizationId, evidenceCommitment,
      async () => ({ eventHash }), reservationContext);
    mocks.createSource.mockResolvedValueOnce({
      loadSnapshot: vi.fn().mockRejectedValue(new Error("stale signed plan")),
      readFinalizedProposalLedger: vi.fn(),
    });

    await expect(runTrustRegistryApiCli(args())).rejects.toThrow(/stale signed plan/u);
    expect(mocks.resolveProposal).not.toHaveBeenCalled();
    expect(await journal.read("issuer", authorizationId)).toMatchObject({ state: "submitted", eventHash });
    expect(output).toEqual([]);
  });

  it("initializes only an empty journal against the verified deployment", async () => {
    await runTrustRegistryApiCli(["init-local-proposal-journal", ...args().slice(1, 9),
      "--submission-journal", path]);
    const journal = new FileProposalSubmissionJournal(path);
    await expect(journal.assertDeploymentBinding("registry:local", `0x${"a".repeat(64)}`, genesisHash))
      .resolves.toBeUndefined();
    expect(JSON.parse(output.join(""))).toMatchObject({ status: "bound", releaseQualified: false });
  });

  it("rejects a journal from another registry before finalized readback", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment("registry:other", `0x${"a".repeat(64)}`, genesisHash);
    await journal.executeOnce("issuer", authorizationId, evidenceCommitment,
      async () => ({ eventHash }), reservationContext);
    await expect(runTrustRegistryApiCli(args())).rejects.toThrow(/conflict/iu);
    expect(mocks.resolveProposal).not.toHaveBeenCalled();
    expect(output).toEqual([]);
  });

  it("rejects a journal from another genesis even with the same registry and address", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment("registry:local", `0x${"a".repeat(64)}`, `0x${"e".repeat(64)}`);
    await journal.executeOnce("issuer", authorizationId, evidenceCommitment,
      async () => ({ eventHash }), reservationContext);
    await expect(runTrustRegistryApiCli(args())).rejects.toThrow(/conflict/iu);
    expect(mocks.resolveProposal).not.toHaveBeenCalled();
  });

  it("rejects a missing journal before creating a lock or parent directory", async () => {
    const missingPath = join(directory, "missing", "proposals.json");
    await expect(runTrustRegistryApiCli([...args().slice(0, -1), missingPath]))
      .rejects.toThrow(/conflict/iu);
    await expect(stat(join(directory, "missing")))
      .rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects an unbound nonempty journal and a missing journal path", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.executeOnce("issuer", authorizationId, evidenceCommitment, async () => ({ eventHash }));
    await expect(runTrustRegistryApiCli(args())).rejects.toThrow(/conflict/iu);
    await expect(journal.bindDeployment("registry:local", `0x${"a".repeat(64)}`, genesisHash))
      .rejects.toThrow(/conflict/iu);
    await expect(runTrustRegistryApiCli([...args().slice(0, -1), join(directory, "typo", "missing.json")]))
      .rejects.toThrow(/conflict/iu);
    expect(output).toEqual([]);
  });
});
