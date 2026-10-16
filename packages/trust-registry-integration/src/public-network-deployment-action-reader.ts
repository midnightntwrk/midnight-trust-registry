import type { TrustedDeploymentActionReader } from "@midnight-ntwrk/trust-registry-client";

import { createCheckpointedDeploymentActionReader } from "./finalized-deployment-action-reader.js";
import {
  createRpcFinalizedCheckpointSource,
  type RpcFinalizedCheckpointConfig,
} from "./rpc-finalized-checkpoint.js";

export type PublicNetworkDeploymentActionReaderConfig = RpcFinalizedCheckpointConfig & {
  indexerHttpUrl: string;
  indexerWsUrl: string;
};

const indexerEndpoint = (value: string, secure: string, local: string): string => {
  const url = new URL(value);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== secure && !(loopback && url.protocol === local)) {
    throw new Error(`Indexer endpoint must use ${secure} or loopback ${local}`);
  }
  if (url.username !== "" || url.password !== "" || url.hash !== "") {
    throw new Error("Indexer endpoint must not contain credentials or a fragment");
  }
  return url.toString();
};

/** Wires the published Midnight indexer provider to a separately pinned node checkpoint. */
export async function createPublicNetworkDeploymentActionReader(
  config: PublicNetworkDeploymentActionReaderConfig,
): Promise<TrustedDeploymentActionReader> {
  const checkpointSource = createRpcFinalizedCheckpointSource(config);
  const httpUrl = indexerEndpoint(config.indexerHttpUrl, "https:", "http:");
  const wsUrl = indexerEndpoint(config.indexerWsUrl, "wss:", "ws:");
  const { indexerPublicDataProvider } = await import(
    "@midnight-ntwrk/midnight-js-indexer-public-data-provider"
  );
  return createCheckpointedDeploymentActionReader({
    publicDataProvider: indexerPublicDataProvider(httpUrl, wsUrl),
    checkpointSource,
  });
}
