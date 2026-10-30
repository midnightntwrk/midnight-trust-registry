import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ createReader: vi.fn() }));

vi.mock("@midnight-ntwrk/trust-registry-integration", async (importOriginal) => ({
  ...await importOriginal<typeof import("@midnight-ntwrk/trust-registry-integration")>(),
  createPublicNetworkDeploymentActionReader: mocks.createReader,
}));

import { runCli } from "../cli.js";

const address = `0x${"a".repeat(64)}`;
const blockHash = `0x${"b".repeat(64)}`;

const capture = async (args: string[]) => {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const code = await runCli(args, {
    stdout: (value) => stdout.push(value),
    stderr: (value) => stderr.push(value),
  });
  return { code, stdout: stdout.join(""), stderr: stderr.join("") };
};

const setEndpoints = () => {
  vi.stubEnv("TR_RPC_URL", "https://rpc.example.test/");
  vi.stubEnv("TR_INDEXER_HTTP_URL", "https://indexer.example.test/graphql");
  vi.stubEnv("TR_INDEXER_WS_URL", "wss://indexer.example.test/graphql/ws");
  vi.stubEnv("TR_EXPECTED_GENESIS_HASH", `0x${"c".repeat(64)}`);
};

afterEach(() => {
  vi.unstubAllEnvs();
  vi.clearAllMocks();
});

describe("read-only deployment inspection CLI", () => {
  it("outputs the finalized checkpoint and ledger fields without endpoint secrets", async () => {
    setEndpoints();
    const state = {
      networkId: "preview",
      finalizedBlockHash: blockHash,
      contractAddress: address,
      registryIdCommitment: `0x${"d".repeat(64)}`,
      deploymentNetworkIdCommitment: `0x${"e".repeat(64)}`,
      governancePolicyCommitment: `0x${"f".repeat(64)}`,
      governanceActionSequence: 3n,
    };
    const readCurrentFinalizedActionState = vi.fn(async () => state);
    mocks.createReader.mockResolvedValue({ readCurrentFinalizedActionState });

    const result = await capture(["inspect-deployment", "--network", "preview", "--address", address]);
    expect(result.code, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
    expect(JSON.parse(result.stdout)).toEqual({
      qualification: "read-only",
      ...state,
      governanceActionSequence: "3",
    });
    expect(result.stdout).not.toContain("rpc.example.test");
    expect(mocks.createReader).toHaveBeenCalledWith({
      networkId: "preview",
      rpcUrl: "https://rpc.example.test/",
      indexerHttpUrl: "https://indexer.example.test/graphql",
      indexerWsUrl: "wss://indexer.example.test/graphql/ws",
      expectedGenesisHash: `0x${"c".repeat(64)}`,
    });
    expect(readCurrentFinalizedActionState).toHaveBeenCalledWith(address);
  });

  it("requires explicit network pins and refuses unavailable deployment state", async () => {
    const local = await capture(["inspect-deployment", "--network", "standalone", "--address", address]);
    expect(local.code).toBe(1);
    expect(local.stderr).toContain("requires a public network profile");
    expect(mocks.createReader).not.toHaveBeenCalled();

    const absent = await capture(["inspect-deployment", "--network", "preview", "--address", address]);
    expect(absent.code).toBe(1);
    expect(absent.stderr).toContain("TR_RPC_URL is required");
    expect(mocks.createReader).not.toHaveBeenCalled();

    setEndpoints();
    mocks.createReader.mockResolvedValue({ readCurrentFinalizedActionState: async () => null });
    const missing = await capture(["inspect-deployment", "--network", "preview", "--address", address]);
    expect(missing.code).toBe(1);
    expect(missing.stderr).toContain("No Trust Registry state at the finalized checkpoint");
  });
});
