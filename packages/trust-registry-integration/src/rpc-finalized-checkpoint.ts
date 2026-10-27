import type {
  FinalizedNetworkCheckpoint,
  TrustedFinalizedCheckpointSource,
} from "./finalized-deployment-action-reader.js";
import { localNetworkEndpoint } from "./local-network-endpoints.js";

const HASH = /^0x[0-9a-fA-F]{64}$/u;
const ZERO = /^0x0{64}$/u;
const MAX_RPC_RESPONSE_BYTES = 8 * 1024;

async function boundedRpcResult(response: Response): Promise<unknown> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null && !/^\d+$/u.test(declaredLength)) {
    void response.body?.cancel().catch(() => {});
    throw new Error("Finality RPC response has malformed Content-Length");
  }
  if (declaredLength !== null && Number(declaredLength) > MAX_RPC_RESPONSE_BYTES) {
    void response.body?.cancel().catch(() => {});
    throw new Error("Finality RPC response exceeds the size limit");
  }
  const reader = response.body?.getReader();
  if (reader === undefined) throw new Error("Finality RPC response has no body");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RPC_RESPONSE_BYTES) {
        await reader.cancel().catch(() => {});
        throw new Error("Finality RPC response exceeds the size limit");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
  } catch {
    throw new Error("Finality RPC response is invalid JSON or UTF-8");
  }
}

const canonicalHash = (value: unknown, label: string): string => {
  if (typeof value !== "string" || !HASH.test(value) || ZERO.test(value)) {
    throw new Error(`${label} must be a nonzero 32-byte hex value`);
  }
  return value.toLowerCase();
};

const rpcEndpoint = (value: string): URL => {
  const url = new URL(value);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error("Finality RPC must use HTTPS or loopback HTTP");
  }
  if (url.username !== "" || url.password !== "" || url.hash !== "") {
    throw new Error("Finality RPC URL must not contain credentials or a fragment");
  }
  return url;
};

export type RpcFinalizedCheckpointConfig = {
  networkId: "preview" | "preprod" | "mainnet";
  rpcUrl: string;
  /** An approved out-of-band pin, never learned from this RPC endpoint. */
  expectedGenesisHash: string;
  fetchImpl?: typeof fetch;
};

export type LocalRpcFinalizedCheckpointConfig = {
  rpcUrl: string;
  expectedGenesisHash: string;
  allowedHosts: readonly string[];
  fetchImpl?: typeof fetch;
};

/** Trusts a pinned HTTPS node for finality and checks its genesis before reading the finalized head. */
export function createRpcFinalizedCheckpointSource(
  config: RpcFinalizedCheckpointConfig,
): TrustedFinalizedCheckpointSource {
  if (!["preview", "preprod", "mainnet"].includes(config.networkId)) {
    throw new Error("Unsupported public Midnight network");
  }
  return createPinnedCheckpointSource(config, rpcEndpoint(config.rpcUrl));
}

/** Trusts an operator-pinned local node; host isolation is a separate deployment requirement. */
export function createLocalRpcFinalizedCheckpointSource(
  config: LocalRpcFinalizedCheckpointConfig,
): TrustedFinalizedCheckpointSource {
  const endpoint = new URL(localNetworkEndpoint(config.rpcUrl, config.allowedHosts, ["http:", "https:"]));
  return createPinnedCheckpointSource({ ...config, networkId: "undeployed" }, endpoint);
}

function createPinnedCheckpointSource(
  config: { networkId: string; expectedGenesisHash: string; fetchImpl?: typeof fetch },
  endpoint: URL,
): TrustedFinalizedCheckpointSource {
  const expectedGenesisHash = canonicalHash(config.expectedGenesisHash, "Expected genesis hash");
  const fetchImpl = config.fetchImpl ?? fetch;

  const call = async (method: string, params: readonly unknown[]): Promise<string> => {
    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) {
      void response.body?.cancel().catch(() => {});
      throw new Error("Finality RPC request failed");
    }
    const body = await boundedRpcResult(response);
    if (body === null || typeof body !== "object" || Array.isArray(body)
      || !("jsonrpc" in body) || body.jsonrpc !== "2.0"
      || !("id" in body) || body.id !== 1
      || !("result" in body) || "error" in body) {
      throw new Error("Finality RPC response is invalid");
    }
    return canonicalHash(body.result, `${method} result`);
  };

  return {
    async readCurrentFinalizedCheckpoint(): Promise<FinalizedNetworkCheckpoint> {
      const genesis = await call("chain_getBlockHash", [0]);
      if (genesis !== expectedGenesisHash) throw new Error("Finality RPC genesis hash mismatch");
      const head = await call("chain_getFinalizedHead", []);
      return { networkId: config.networkId, blockHash: head.slice(2) };
    },
  };
}
