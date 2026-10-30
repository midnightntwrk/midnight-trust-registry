import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  loadPlan: vi.fn(),
  createSource: vi.fn(),
  createReader: vi.fn(),
  assertImage: vi.fn(),
  assertCount: vi.fn(),
  assess: vi.fn(),
  draftDecision: vi.fn(),
  loadDecision: vi.fn(),
  digestCandidate: vi.fn(),
}));

vi.mock("@midnight-ntwrk/trust-registry-integration", async (importOriginal) => ({
  ...await importOriginal<typeof import("@midnight-ntwrk/trust-registry-integration")>(),
  createLocalNetworkDeploymentActionReader: mocks.createReader,
}));
vi.mock("../local-ledger-runtime.js", () => ({
  assertLocalApiImageSourceRevision: vi.fn(),
  loadApprovedLocalLedgerRuntimePlanWithDigest: mocks.loadPlan,
  createApprovedLocalLedgerRuntimeSource: mocks.createSource,
  assertApprovedDeploymentImage: mocks.assertImage,
  assertApprovedPlanCoversGovernanceCount: mocks.assertCount,
}));
vi.mock("../proposal-recovery-candidate.js", () => ({ assessProposalRecoveryCandidate: mocks.assess }));
vi.mock("../proposal-recovery-decision.js", () => ({
  draftProposalRecoveryDecision: mocks.draftDecision,
  loadApprovedProposalRecoveryDecision: mocks.loadDecision,
  proposalRecoveryCandidateDigest: mocks.digestCandidate,
}));
vi.mock("../server.js", () => ({ createTrustRegistryApiServer: vi.fn() }));

import { runTrustRegistryApiCli } from "../cli.js";
import { FileProposalSubmissionJournal } from "../proposal-submission-journal.js";

const registryId = "registry:local";
const authorizationId = "issuer:recovery:1";
const contractAddress = `0x${"a".repeat(64)}`;
const genesisHash = `0x${"b".repeat(64)}`;
const evidenceCommitment = `0x${"c".repeat(64)}`;
let directory: string;
let path: string;
let output: string[];

const args = () => ["inspect-local-proposal-recovery",
  "--local-ledger-plan", "/run/api-plan.json",
  "--local-ledger-signature", "/run/api-plan.sig",
  "--local-ledger-keyring", "/run/keyring",
  "--local-ledger-reviewer", "A".repeat(40),
  "--role", "issuer", "--authorization-id", authorizationId,
  "--submission-journal", path];

const reserve = async () => {
  const journal = new FileProposalSubmissionJournal(path);
  await journal.bindDeployment(registryId, contractAddress, genesisHash);
  await expect(journal.executeOnce("issuer", authorizationId, evidenceCommitment, async () => {
    throw new Error("response lost");
  }, { actionSequence: "2", actionKind: `0x${"d".repeat(64)}`,
    actionPayloadHash: `0x${"e".repeat(64)}` })).rejects.toThrow(/may have reached Compact/u);
  return journal;
};

beforeEach(async () => {
  vi.clearAllMocks();
  directory = await mkdtemp(join(tmpdir(), "tr-local-recovery-inspection-"));
  path = join(directory, "proposals.json");
  output = [];
  vi.spyOn(process.stdout, "write").mockImplementation((value) => {
    output.push(String(value));
    return true;
  });
  const plan = { contractAddress, expectedGenesisHash: genesisHash, sourceRevision: "f".repeat(40) };
  mocks.loadPlan.mockResolvedValue({ plan, planSha256: "7".repeat(64) });
  mocks.createSource.mockResolvedValue({ loadSnapshot: async () => ({ registry: { registryId } }) });
  const view = { networkId: "undeployed", contractAddress,
    finalizedBlockHash: `0x${"f".repeat(64)}`, ledger: { governanceActionCount: 3n } };
  mocks.createReader.mockResolvedValue({ readCurrentFinalizedLedger: async () => view });
  mocks.assess.mockResolvedValue({ format: "tr-local-proposal-recovery-candidate-v3",
    reason: "sequence-invalidated-record-absent", reviewCandidate: true,
    retryPermitted: false, releaseQualified: false });
  mocks.digestCandidate.mockReturnValue("9".repeat(64));
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(directory, { recursive: true, force: true });
});

describe("read-only local proposal recovery inspection CLI", () => {
  it("reads a bound private reservation and one approved finalized view without changing the journal", async () => {
    const journal = await reserve();
    const before = await readFile(path);
    await runTrustRegistryApiCli(args());
    expect(mocks.loadPlan).toHaveBeenCalledWith(expect.objectContaining({ requireApiRuntimePin: true }));
    expect(mocks.createReader).toHaveBeenCalledWith(expect.objectContaining({ expectedGenesisHash: genesisHash }));
    expect(mocks.assertImage).toHaveBeenCalledOnce();
    expect(mocks.assertCount).toHaveBeenCalledWith(expect.any(Object), 3n);
    expect(mocks.assess).toHaveBeenCalledWith(expect.objectContaining({
      attempt: expect.objectContaining({ state: "reserved", authorizationId }),
      registryId, contractAddress, planExpectedGenesisHash: genesisHash,
      approvedPlanSha256: "7".repeat(64),
      journalBindingDigest: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
      planSourceRevision: "f".repeat(40),
    }));
    expect(await readFile(path)).toEqual(before);
    expect(await journal.read("issuer", authorizationId)).toMatchObject({ state: "reserved", eventHash: null });
    expect(JSON.parse(output.join(""))).toMatchObject({ reviewCandidate: true,
      retryPermitted: false, releaseQualified: false });
  });

  it("emits no candidate when the signed plan or finalized view is unavailable", async () => {
    const journal = await reserve();
    mocks.createSource.mockResolvedValueOnce({ loadSnapshot: async () => { throw new Error("stale plan"); } });
    await expect(runTrustRegistryApiCli(args())).rejects.toThrow(/stale plan/u);
    expect(mocks.createReader).not.toHaveBeenCalled();
    mocks.createReader.mockResolvedValueOnce({ readCurrentFinalizedLedger: async () => null });
    await expect(runTrustRegistryApiCli(args())).rejects.toThrow(/view is unavailable/u);
    expect(mocks.assess).not.toHaveBeenCalled();
    expect(output).toEqual([]);
    expect(await journal.read("issuer", authorizationId)).toMatchObject({ state: "reserved" });
  });

  it("rejects a journal bound to another genesis before reading finality", async () => {
    const journal = new FileProposalSubmissionJournal(path);
    await journal.bindDeployment(registryId, contractAddress, `0x${"1".repeat(64)}`);
    await expect(runTrustRegistryApiCli(args())).rejects.toThrow(/conflict/iu);
    expect(mocks.createReader).not.toHaveBeenCalled();
    expect(output).toEqual([]);
  });

  it("drafts exact bytes for external review without changing a reserved journal", async () => {
    await reserve();
    const before = await readFile(path);
    const filesBefore = await readdir(directory);
    mocks.draftDecision.mockResolvedValue('{"reviewOnly":true}\n');
    await runTrustRegistryApiCli(["draft-local-proposal-recovery-decision", ...args().slice(1),
      "--finality-evidence", join(directory, "finality.json"),
      "--recovery-reviewer", "B".repeat(40),
      "--evidence-reference", "private-review-1"]);
    expect(mocks.draftDecision).toHaveBeenCalledWith(expect.objectContaining({
      finalityEvidencePath: join(directory, "finality.json"),
      evidenceReference: "private-review-1", reviewerFingerprint: "B".repeat(40),
      planReviewerFingerprint: "A".repeat(40),
    }));
    expect(output.join("")).toBe('{"reviewOnly":true}\n');
    expect(await readFile(path)).toEqual(before);
    expect(await readdir(directory)).toEqual(filesBefore);
  });

  it("verifies a detached decision against a fresh candidate but never releases the reservation", async () => {
    const journal = await reserve();
    const before = await readFile(path);
    const filesBefore = await readdir(directory);
    mocks.loadDecision.mockResolvedValue({ decision: { reviewerFingerprint: "B".repeat(40),
      evidenceReference: "private-review-1", finalityEvidenceSha256: "6".repeat(64),
      draftedAt: "2026-10-24T00:00:00.000Z" }, decisionSha256: "8".repeat(64),
    finalityAuthenticated: false, releaseQualified: false, retryPermitted: false });
    await runTrustRegistryApiCli(["verify-local-proposal-recovery-decision", ...args().slice(1),
      "--finality-evidence", join(directory, "finality.json"),
      "--recovery-reviewer", "B".repeat(40),
      "--recovery-keyring", "/run/recovery-keyring",
      "--recovery-decision", join(directory, "decision.json"),
      "--recovery-signature", join(directory, "decision.sig")]);
    expect(mocks.loadDecision).toHaveBeenCalledWith(expect.objectContaining({
      decisionPath: join(directory, "decision.json"),
      signaturePath: join(directory, "decision.sig"),
      finalityEvidencePath: join(directory, "finality.json"),
      keyringDirectory: "/run/recovery-keyring", reviewerFingerprint: "B".repeat(40),
      planReviewerFingerprint: "A".repeat(40),
      candidate: expect.objectContaining({ reviewCandidate: true }),
    }));
    expect(JSON.parse(output.join(""))).toMatchObject({
      format: "tr-local-proposal-recovery-verification-v1",
      finalityEvidenceSha256: "6".repeat(64), draftedAt: "2026-10-24T00:00:00.000Z",
      finalityAuthenticated: false, releaseQualified: false, retryPermitted: false,
    });
    expect(await readFile(path)).toEqual(before);
    expect(await readdir(directory)).toEqual(filesBefore);
    expect(await journal.read("issuer", authorizationId)).toMatchObject({ state: "reserved" });
  });
});
