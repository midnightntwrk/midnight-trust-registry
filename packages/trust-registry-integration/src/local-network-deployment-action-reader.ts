import {
  createLocalCheckpointedDeploymentActionReader,
  type FinalizedRegistryBootstrapReader,
} from "./finalized-deployment-action-reader.js";
import { localNetworkEndpoint } from "./local-network-endpoints.js";
import {
  createLocalRpcFinalizedCheckpointSource,
  type LocalRpcFinalizedCheckpointConfig,
} from "./rpc-finalized-checkpoint.js";

export type LocalNetworkDeploymentActionReaderConfig = LocalRpcFinalizedCheckpointConfig & {
  networkId: "undeployed";
  indexerHttpUrl: string;
  indexerWsUrl: string;
};

/** Reads a local ledger only from approved service hosts and a pinned local genesis. */
export async function createLocalNetworkDeploymentActionReader(
  config: LocalNetworkDeploymentActionReaderConfig,
): Promise<FinalizedRegistryBootstrapReader> {
  if (config.networkId !== "undeployed") throw new Error("Local reader requires the undeployed network");
  const checkpointSource = createLocalRpcFinalizedCheckpointSource(config);
  const httpUrl = localNetworkEndpoint(config.indexerHttpUrl, config.allowedHosts, ["http:", "https:"]);
  const wsUrl = localNetworkEndpoint(config.indexerWsUrl, config.allowedHosts, ["ws:", "wss:"]);
  const { indexerPublicDataProvider } = await import(
    "@midnight-ntwrk/midnight-js-indexer-public-data-provider"
  );
  return createLocalCheckpointedDeploymentActionReader({
    publicDataProvider: indexerPublicDataProvider(httpUrl, wsUrl),
    checkpointSource,
  });
}
