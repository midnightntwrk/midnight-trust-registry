import { beforeEach, expect, it, vi } from "vitest";

import { createLocalNetworkDeploymentActionReader } from "../local-network-deployment-action-reader.js";
import { createPublicNetworkDeploymentActionReader } from "../public-network-deployment-action-reader.js";

const mocks = vi.hoisted(() => ({ provider: vi.fn(), query: vi.fn() }));
vi.mock("@midnight-ntwrk/midnight-js-indexer-public-data-provider", () => ({
  indexerPublicDataProvider: mocks.provider,
}));

const genesis = `0x${"a".repeat(64)}`;
const finalized = `0x${"b".repeat(64)}`;
const address = `0x${"c".repeat(64)}`;
const fetchImpl: typeof fetch = vi.fn(async (_url, init) => {
  const request = JSON.parse(String(init?.body)) as { method: string };
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1,
    result: request.method === "chain_getBlockHash" ? genesis : finalized }));
});
const config = () => ({
  networkId: "undeployed" as const,
  rpcUrl: "http://node:9944",
  indexerHttpUrl: "http://indexer:8080/graphql",
  indexerWsUrl: "ws://indexer:8080/graphql/ws",
  expectedGenesisHash: genesis,
  allowedHosts: ["node", "indexer"],
  fetchImpl,
});

beforeEach(() => {
  vi.clearAllMocks();
  mocks.query.mockResolvedValue(null);
  mocks.provider.mockReturnValue({ queryContractState: mocks.query });
});

it("wires only approved local endpoints to a genesis-pinned finalized ledger read", async () => {
  const reader = await createLocalNetworkDeploymentActionReader(config());
  await expect(reader.readCurrentFinalizedActionState(address)).resolves.toBeNull();
  expect(mocks.provider).toHaveBeenCalledWith(
    "http://indexer.:8080/graphql", "ws://indexer.:8080/graphql/ws",
  );
  expect(mocks.query).toHaveBeenCalledWith(address.slice(2), {
    type: "blockHash", blockHash: finalized.slice(2),
  });
  expect(fetchImpl).toHaveBeenCalledTimes(2);
});

it("rejects public-network relabeling and non-allowlisted local services", async () => {
  await expect(createLocalNetworkDeploymentActionReader({ ...config(), networkId: "preprod" as never }))
    .rejects.toThrow(/undeployed network/u);
  await expect(createLocalNetworkDeploymentActionReader({ ...config(), indexerHttpUrl: "http://public.example/graphql" }))
    .rejects.toThrow(/allowlist/u);
  await expect(createPublicNetworkDeploymentActionReader({ ...config(), networkId: "undeployed" as never }))
    .rejects.toThrow(/Unsupported public Midnight network/u);
  expect(mocks.provider).not.toHaveBeenCalled();
});
