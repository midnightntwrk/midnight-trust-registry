import type { ContractProviders } from "@midnight-ntwrk/midnight-js-contracts";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import type { MidnightProvider } from "@midnight-ntwrk/midnight-js-types";
import { SerializedTransaction } from "@midnight-ntwrk/wallet-sdk-abstractions";
import type { PolkadotNodeClient } from "@midnight-ntwrk/wallet-sdk-node-client/effect";
import type { TrustRegistryContract, TrustRegistryPrivateState } from "@midnight-ntwrk/trust-registry-contract";
import { Duration, Effect, Option, Stream } from "effect";

import { localNetworkEndpoint } from "./local-network-endpoints.js";

type RegistryContract = TrustRegistryContract.Contract<TrustRegistryPrivateState>;
type RegistryProviders = ContractProviders<RegistryContract>;

export type PinnedLocalSubmissionConfig = {
  nodeWsUrl: string;
  indexerHttpUrl: string;
  indexerWsUrl: string;
  allowedHosts: readonly string[];
  contractAddress: string;
  /** Must come from the reviewer-signed install plan, not from the node. */
  expectedGenesisHash: string;
};

/** A Node-only submitter; node genesis is rechecked on the connection that sends each transaction. */
export function createPinnedLocalSubmissionProvider(config: PinnedLocalSubmissionConfig): {
  midnightProvider: MidnightProvider;
  publicDataProvider: RegistryProviders["publicDataProvider"];
  readSubmissionProviderIdentity: (providers: RegistryProviders) => Promise<{
    contractAddress: string; genesisHash: string;
  }>;
} {
  const nodeURL = new URL(localNetworkEndpoint(config.nodeWsUrl, config.allowedHosts, ["ws:", "wss:"]));
  const indexerHttpUrl = localNetworkEndpoint(config.indexerHttpUrl, config.allowedHosts, ["http:", "https:"]);
  const indexerWsUrl = localNetworkEndpoint(config.indexerWsUrl, config.allowedHosts, ["ws:", "wss:"]);
  if (!/^0x[0-9a-f]{64}$/u.test(config.contractAddress)
    || !/^0x[0-9a-f]{64}$/u.test(config.expectedGenesisHash)
    || /^0x0{64}$/u.test(config.expectedGenesisHash)) {
    throw new Error("Pinned local submission requires a contract address and nonzero genesis hash");
  }
  const publicDataProvider = indexerPublicDataProvider(indexerHttpUrl, indexerWsUrl);

  const withPinnedNode = async <T>(
    use: (client: PolkadotNodeClient) => Effect.Effect<T, unknown>,
    timeout: Duration.Duration,
  ): Promise<T> => {
    const { PolkadotNodeClient: NodeClient } = await import("@midnight-ntwrk/wallet-sdk-node-client/effect");
    return Effect.runPromise(Effect.timeout(Effect.scoped(Effect.flatMap(
      NodeClient.make({ nodeURL, reconnectionTimeout: Duration.seconds(15) }),
      (client) => Effect.flatMap(client.ensureConnection(), () => Effect.flatMap(
        Effect.tryPromise({
          try: async () => {
            const actualGenesis = (await client.api.rpc.chain.getBlockHash(0)).toHex().toLowerCase();
            if (actualGenesis !== config.expectedGenesisHash) {
              throw new Error("Submission node genesis does not match the approved local deployment");
            }
          },
          catch: (error) => error instanceof Error ? error : new Error("Local submission node failed"),
        }),
        () => use(client),
      )),
    )), timeout));
  };

  const midnightProvider: MidnightProvider = {
    async submitTx(tx) {
      const identifiers = tx.identifiers();
      if (identifiers.length === 0 || !identifiers[0]) {
        throw new Error("Finalized Midnight transaction has no identifier");
      }
      return withPinnedNode((client) => Effect.flatMap(
        Stream.runLast(
          client.sendMidnightTransaction(SerializedTransaction.of(tx.serialize())),
        ),
        (last) => {
          if (Option.isNone(last) || last.value._tag !== "Finalized") {
            return Effect.fail(new Error("Submission node did not finalize the Midnight transaction"));
          }
          return Effect.succeed(identifiers[0]!);
        },
      ), Duration.seconds(150));
    },
  };

  return {
    midnightProvider,
    publicDataProvider,
    async readSubmissionProviderIdentity(providers) {
      if (providers.midnightProvider !== midnightProvider
        || providers.publicDataProvider !== publicDataProvider) {
        throw new Error("Issuer call is not using the pinned local node and indexer providers");
      }
      await withPinnedNode(() => Effect.succeed(undefined), Duration.seconds(30));
      return { contractAddress: config.contractAddress, genesisHash: config.expectedGenesisHash };
    },
  };
}
