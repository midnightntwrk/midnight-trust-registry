import { Buffer } from "node:buffer";

import type { ApiPromise } from "@polkadot/api";
import type { ContractProviders } from "@midnight-ntwrk/midnight-js-contracts";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import type { MidnightProvider } from "@midnight-ntwrk/midnight-js-types";
import type { TrustRegistryContract, TrustRegistryPrivateState } from "@midnight-ntwrk/trust-registry-contract";

import { localNetworkEndpoint } from "./local-network-endpoints.js";

type RegistryContract = TrustRegistryContract.Contract<TrustRegistryPrivateState>;
type RegistryProviders = ContractProviders<RegistryContract>;
type PublicDataProvider = RegistryProviders["publicDataProvider"];

type SubmissionStatus = {
  status: {
    isFinalized: boolean;
    isDropped: boolean;
    isInvalid: boolean;
    isUsurped: boolean;
    isFinalityTimeout: boolean;
  };
  dispatchError?: unknown;
};
type SubmissionExtrinsic = {
  send(callback: (result: SubmissionStatus) => void): Promise<() => void>;
};

// Same-process guards only. The durable proposal journal must reserve before every SDK submission.
const uncertainDeployments = new Set<string>();
const inFlightDeployments = new Set<string>();

export type PinnedLocalSubmissionConfig = {
  nodeWsUrl: string;
  indexerHttpUrl: string;
  indexerWsUrl: string;
  allowedHosts: readonly string[];
  contractAddress: string;
  /** Must come from the reviewer-signed install plan, not from either service. */
  expectedGenesisHash: string;
  /** Test-only shorter deadlines; production cannot exceed the built-in limits. */
  connectionDeadlineMs?: number;
  submissionDeadlineMs?: number;
  /** Bounds the SDK's otherwise indefinite indexer transaction read. */
  indexerWatchDeadlineMs?: number;
};

const boundedDeadline = (value: number | undefined, maximum: number): number => {
  const deadline = value ?? maximum;
  if (!Number.isSafeInteger(deadline) || deadline < 1 || deadline > maximum) {
    throw new RangeError("Local submission deadline is invalid");
  }
  return deadline;
};

const abortable = <T>(promise: Promise<T>, signal: AbortSignal): Promise<T> => new Promise((resolve, reject) => {
  let settled = false;
  const finish = (outcome: { ok: true; value: T } | { ok: false; error: unknown }): void => {
    if (settled) return;
    settled = true;
    signal.removeEventListener("abort", onAbort);
    if (outcome.ok) resolve(outcome.value);
    else reject(outcome.error);
  };
  const onAbort = (): void => {
    finish({ ok: false, error: signal.reason ?? new Error("Local submission deadline elapsed") });
  };
  signal.addEventListener("abort", onAbort, { once: true });
  promise.then(
    (value) => { finish({ ok: true, value }); },
    (error: unknown) => { finish({ ok: false, error }); },
  );
  if (signal.aborted) onAbort();
});

const awaitNodeFinality = (extrinsic: SubmissionExtrinsic, signal: AbortSignal): Promise<void> => new Promise(
  (resolve, reject) => {
    let settled = false;
    let unsubscribe: (() => void) | undefined;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      if (unsubscribe !== undefined) void unsubscribe();
      if (error === undefined) resolve();
      else reject(error);
    };
    const onAbort = (): void => { finish(new Error("Local submission finality deadline elapsed")); };
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) { onAbort(); return; }
    try {
      extrinsic.send((result) => {
      if (result.status.isFinalized) {
        if (result.dispatchError !== undefined) finish(new Error("Local submission finalized with a dispatch error"));
        else finish();
      }
        else if (result.status.isDropped || result.status.isInvalid || result.status.isUsurped
          || result.status.isFinalityTimeout) finish(new Error("Local submission did not finalize"));
      }).then((stop) => {
        unsubscribe = stop;
        if (settled) void stop();
      }, (error: unknown) => { finish(error instanceof Error ? error : new Error("Local submission failed")); });
    } catch (error) {
      finish(error instanceof Error ? error : new Error("Local submission failed"));
    }
  },
);

/** Node-only prototype; final release still requires deployed-ledger qualification. */
export function createPinnedLocalSubmissionProvider(config: PinnedLocalSubmissionConfig): {
  midnightProvider: MidnightProvider & {
    submitTxWithBroadcastGuard: (
      tx: Parameters<MidnightProvider["submitTx"]>[0], guard: () => Promise<void>,
    ) => ReturnType<MidnightProvider["submitTx"]>;
  };
  publicDataProvider: RegistryProviders["publicDataProvider"];
  readSubmissionProviderIdentity: (providers: RegistryProviders) => Promise<{
    contractAddress: string; genesisHash: string;
  }>;
} {
  const nodeURL = new URL(localNetworkEndpoint(config.nodeWsUrl, config.allowedHosts, ["ws:", "wss:"]));
  const indexerHttpUrl = localNetworkEndpoint(config.indexerHttpUrl, config.allowedHosts, ["http:", "https:"]);
  const indexerWsUrl = localNetworkEndpoint(config.indexerWsUrl, config.allowedHosts, ["ws:", "wss:"]);
  if (!/^0x[0-9a-f]{64}$/u.test(config.contractAddress)
    || /^0x0{64}$/u.test(config.contractAddress)
    || !/^0x[0-9a-f]{64}$/u.test(config.expectedGenesisHash)
    || /^0x0{64}$/u.test(config.expectedGenesisHash)) {
    throw new Error("Pinned local submission requires a contract address and nonzero genesis hash");
  }
  const connectionDeadlineMs = boundedDeadline(config.connectionDeadlineMs, 30_000);
  const submissionDeadlineMs = boundedDeadline(config.submissionDeadlineMs, 150_000);
  const indexerWatchDeadlineMs = boundedDeadline(config.indexerWatchDeadlineMs, 120_000);
  const deploymentKey = `${config.expectedGenesisHash}:${config.contractAddress}`;
  const assertUsable = (): void => {
    if (uncertainDeployments.has(deploymentKey)) {
      throw new Error("Local submission outcome is uncertain; reconcile and restart before further use");
    }
    if (inFlightDeployments.has(deploymentKey)) {
      throw new Error("Local submission for this deployment is still pending");
    }
  };
  assertUsable();
  const rawPublicDataProvider = indexerPublicDataProvider(indexerHttpUrl, indexerWsUrl);
  const boundedWatch: PublicDataProvider["watchForTxData"] = async (txId) => {
    assertUsable();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let result: Awaited<ReturnType<PublicDataProvider["watchForTxData"]>>;
    try {
      result = await Promise.race([
        Promise.resolve().then(() => rawPublicDataProvider.watchForTxData(txId)),
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => { reject(new Error("Local indexer transaction read deadline elapsed; reconcile before retry")); },
            indexerWatchDeadlineMs,
          );
        }),
      ]);
    } catch (error) {
      uncertainDeployments.add(deploymentKey);
      throw error;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
    return result;
  };
  const publicDataProvider: PublicDataProvider = new Proxy(rawPublicDataProvider, {
    get(target, property) {
      if (property === "watchForTxData") return boundedWatch;
      const value: unknown = Reflect.get(target, property, target);
      if (typeof value !== "function") return value;
      return (...args: unknown[]) => {
        assertUsable();
        return value.apply(target, args);
      };
    },
  });

  const readIndexerGenesis = async (): Promise<void> => {
    const response = await fetch(indexerHttpUrl, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ query: "query LocalGenesis { block(offset: {height: 0}) { height hash } }" }),
      redirect: "error", signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw new Error("Local indexer genesis query failed");
    const body: unknown = await response.json();
    if (body === null || typeof body !== "object" || Array.isArray(body)
      || "errors" in body || !("data" in body)
      || body.data === null || typeof body.data !== "object" || Array.isArray(body.data)
      || !("block" in body.data)
      || body.data.block === null || typeof body.data.block !== "object" || Array.isArray(body.data.block)
      || !("height" in body.data.block) || body.data.block.height !== 0
      || !("hash" in body.data.block) || typeof body.data.block.hash !== "string"
      || !/^[0-9a-fA-F]{64}$/u.test(body.data.block.hash)
      || `0x${body.data.block.hash.toLowerCase()}` !== config.expectedGenesisHash) {
      throw new Error("Local indexer genesis does not match the approved deployment");
    }
  };

  const withPinnedNode = async <T>(
    use: (api: ApiPromise, signal: AbortSignal) => Promise<T>, deadlineMs: number,
  ): Promise<T> => {
    const { ApiPromise: Api, WsProvider } = await import("@polkadot/api");
    const provider = new WsProvider(nodeURL.toString(), false);
    const controller = new AbortController();
    const timer = setTimeout(() => {
      controller.abort(new Error("Local submission node deadline elapsed"));
      void provider.disconnect().catch(() => undefined);
    }, deadlineMs);
    let api: ApiPromise | undefined;
    try {
      await abortable(provider.connect(), controller.signal);
      controller.signal.throwIfAborted();
      // Polkadot's published provider types disagree on optional ttl under exactOptionalPropertyTypes.
      const pending = Api.create({ provider: provider as never, throwOnConnect: true, noInitWarn: true });
      void pending.then((lateApi) => {
        if (controller.signal.aborted) void lateApi.disconnect().catch(() => undefined);
      }, () => undefined);
      api = await abortable(pending, controller.signal);
      controller.signal.throwIfAborted();
      if (!api.isConnected || !provider.isConnected) throw new Error("Local submission node disconnected");
      const genesis = await abortable(api.rpc.chain.getBlockHash(0), controller.signal);
      if (genesis.toHex().toLowerCase() !== config.expectedGenesisHash) {
        throw new Error("Submission node genesis does not match the approved local deployment");
      }
      controller.signal.throwIfAborted();
      return await abortable(use(api, controller.signal), controller.signal);
    } finally {
      clearTimeout(timer);
      const pendingClose = (api?.disconnect() ?? provider.disconnect()).catch(() => undefined);
      let closeTimer: ReturnType<typeof setTimeout> | undefined;
      await Promise.race([
        pendingClose,
        new Promise<void>((resolve) => { closeTimer = setTimeout(resolve, 5_000); }),
      ]);
      if (closeTimer !== undefined) clearTimeout(closeTimer);
    }
  };

  const submitTransaction = async (
    tx: Parameters<MidnightProvider["submitTx"]>[0], guard?: () => Promise<void>,
  ): ReturnType<MidnightProvider["submitTx"]> => {
    assertUsable();
    const txId = tx.identifiers()[0];
    if (!txId) throw new Error("Finalized Midnight transaction has no identifier");
    const serialized = `0x${Buffer.from(tx.serialize()).toString("hex")}`;
    let attemptedBroadcast = false;
    let reservedTarget = false;
    try {
      const result = await withPinnedNode(async (api, signal) => {
        signal.throwIfAborted();
        if (!api.isConnected) throw new Error("Local submission node disconnected before broadcast");
        const midnight: unknown = Reflect.get(api.tx, "midnight");
        if (midnight === null || typeof midnight !== "object"
          || !("sendMnTransaction" in midnight)
          || typeof midnight.sendMnTransaction !== "function") {
          throw new Error("Local node does not expose Midnight transaction submission");
        }
        assertUsable();
        await guard?.();
        signal.throwIfAborted();
        assertUsable();
        inFlightDeployments.add(deploymentKey);
        reservedTarget = true;
        const extrinsic = midnight.sendMnTransaction(serialized) as SubmissionExtrinsic;
        attemptedBroadcast = true;
        await awaitNodeFinality(extrinsic, signal);
        return txId;
      }, submissionDeadlineMs);
      if (reservedTarget) inFlightDeployments.delete(deploymentKey);
      assertUsable();
      return result;
    } catch (error) {
      if (attemptedBroadcast) uncertainDeployments.add(deploymentKey);
      if (reservedTarget) inFlightDeployments.delete(deploymentKey);
      throw error;
    }
  };
  const midnightProvider = {
    submitTx: (tx: Parameters<MidnightProvider["submitTx"]>[0]) => submitTransaction(tx),
    submitTxWithBroadcastGuard: (
      tx: Parameters<MidnightProvider["submitTx"]>[0], guard: () => Promise<void>,
    ) => submitTransaction(tx, guard),
  };

  return {
    midnightProvider, publicDataProvider,
    async readSubmissionProviderIdentity(providers) {
      assertUsable();
      if (providers.midnightProvider !== midnightProvider
        || providers.publicDataProvider !== publicDataProvider) {
        throw new Error("Issuer call is not using the pinned local node and indexer providers");
      }
      await withPinnedNode(async () => undefined, connectionDeadlineMs);
      await readIndexerGenesis();
      assertUsable();
      return { contractAddress: config.contractAddress, genesisHash: config.expectedGenesisHash };
    },
  };
}
