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
  resolveCompactProposalObservation: mocks.resolveProposal,
}));
vi.mock("../server.js", () => ({ createTrustRegistryApiServer: mocks.createServer }));

import { runTrustRegistryApiCli } from "../cli.js";

const args = ["observe-local-proposal", "--local-ledger-plan", "/run/api-plan.json",
  "--local-ledger-signature", "/run/api-plan.sig",
  "--local-ledger-keyring", "/run/keyring",
  "--local-ledger-reviewer", "A".repeat(40),
  "--role", "issuer", "--authorization-id", "issuer:local:1"];

let output: string[];

beforeEach(() => {
  vi.clearAllMocks();
  output = [];
  vi.spyOn(process.stdout, "write").mockImplementation((value) => {
    output.push(String(value));
    return true;
  });
  mocks.loadPlan.mockResolvedValue({ contractAddress: `0x${"a".repeat(64)}` });
  mocks.createSource.mockResolvedValue({
    loadSnapshot: vi.fn().mockResolvedValue({ registry: { registryId: "registry:local" } }),
    readFinalizedProposalLedger: vi.fn(),
  });
});

afterEach(() => vi.restoreAllMocks());

describe("signed local proposal observation CLI", () => {
  it("emits only a matching finalized observation without starting a listener", async () => {
    const observation = { eventHash: `0x${"b".repeat(64)}`, evidenceCommitment: `0x${"c".repeat(64)}` };
    mocks.resolveProposal.mockResolvedValueOnce(observation);
    await runTrustRegistryApiCli(args);
    expect(mocks.loadPlan).toHaveBeenCalledWith(expect.objectContaining({
      planPath: "/run/api-plan.json", requireApiRuntimePin: true,
    }));
    expect(mocks.resolveProposal).toHaveBeenCalledWith(
      expect.any(Function), "registry:local", "issuer", "issuer:local:1",
    );
    expect(mocks.createServer).not.toHaveBeenCalled();
    expect(JSON.parse(output.join(""))).toMatchObject({
      format: "tr-local-proposal-observation-v1", networkId: "undeployed",
      role: "issuer", authorizationId: "issuer:local:1", status: "observed",
      observation, retryPermitted: false, releaseQualified: false,
    });
  });

  it("never treats an absent proposal as permission to retry", async () => {
    mocks.resolveProposal.mockResolvedValueOnce(null);
    await runTrustRegistryApiCli(args);
    expect(JSON.parse(output.join(""))).toMatchObject({
      status: "not-observed", observation: null, retryPermitted: false, releaseQualified: false,
    });
    expect(mocks.createServer).not.toHaveBeenCalled();
  });

  it("emits no observation if signed-plan or finalized readback fails", async () => {
    mocks.loadPlan.mockRejectedValueOnce(new Error("signature unavailable"));
    await expect(runTrustRegistryApiCli(args)).rejects.toThrow(/signature unavailable/u);
    expect(mocks.createSource).not.toHaveBeenCalled();
    expect(output).toEqual([]);

    mocks.resolveProposal.mockRejectedValueOnce(new Error("finalized reader unavailable"));
    await expect(runTrustRegistryApiCli(args)).rejects.toThrow(/finalized reader unavailable/u);
    expect(output).toEqual([]);
  });
});
