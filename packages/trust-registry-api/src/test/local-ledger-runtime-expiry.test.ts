import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ createSource: vi.fn(), createReader: vi.fn() }));
vi.mock("@midnight-ntwrk/trust-registry-integration", async (importOriginal) => ({
  ...await importOriginal<typeof import("@midnight-ntwrk/trust-registry-integration")>(),
  createLocalNetworkDeploymentActionReader: mocks.createReader,
}));
vi.mock("../local-ledger-source.js", async (importOriginal) => ({
  ...await importOriginal<typeof import("../local-ledger-source.js")>(),
  createLocalLedgerBoundSource: mocks.createSource,
}));

import { createApprovedLocalLedgerRuntimeSource, type LocalLedgerRuntimePlan } from "../local-ledger-runtime.js";

describe("approved local-ledger plan expiry during finalized reads", () => {
  it.each(["loadSnapshot", "loadCurrentLedgerSelection", "readFinalizedProposalLedger"] as const)(
    "rejects %s when the plan expires while its provider read is pending", async (method) => {
      vi.useFakeTimers();
      try {
        const now = new Date("2026-10-24T10:00:00.000Z");
        vi.setSystemTime(now);
        let resolveRead!: (value: unknown) => void;
        const pending = new Promise<unknown>((resolve) => { resolveRead = resolve; });
        mocks.createSource.mockReturnValue({ mode: "local-ledger",
          loadSnapshot: () => pending,
          loadCurrentLedgerSelection: () => pending,
          readFinalizedProposalLedger: () => pending,
        });
        mocks.createReader.mockResolvedValue({});
        const plan = {
          format: "tr-local-api-runtime-v2" as const,
          networkId: "undeployed" as const,
          sourceRevision: "d".repeat(40),
          installInventoryPath: "/unused/inventory.json",
          installInventorySha256: "e".repeat(64),
          releaseManifestPath: "/unused/release.json",
          releaseManifestSha256: "f".repeat(64),
          contractAddress: `0x${"a".repeat(64)}`,
          snapshotPath: "/unused", snapshotSha256: "b".repeat(64),
          rpcUrl: "http://127.0.0.1:29944", indexerHttpUrl: "http://127.0.0.1:28088/graphql",
          indexerWsUrl: "ws://127.0.0.1:28088/graphql/ws", allowedHosts: ["127.0.0.1"],
          verifierKeySha256: {}, maintenanceAuthority: { committee: [], threshold: 0, counter: "0" },
          notBefore: new Date(now.getTime() - 1000).toISOString(),
          notAfter: new Date(now.getTime() + 1000).toISOString(),
          sequenceTimestamps: { "0": now.toISOString() },
          expectedGenesisHash: `0x${"c".repeat(64)}`,
        } satisfies LocalLedgerRuntimePlan;
        const source = await createApprovedLocalLedgerRuntimeSource(plan);
        const read = source[method]();
        vi.setSystemTime(now.getTime() + 1001);
        resolveRead({});
        await expect(read).rejects.toMatchObject({
          cause: { message: expect.stringMatching(/not currently valid/u) },
        });
      } finally {
        vi.useRealTimers();
        vi.clearAllMocks();
      }
    },
  );
});
