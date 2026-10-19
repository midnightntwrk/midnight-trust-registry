import { sampleSigningKey } from "@midnight-ntwrk/compact-runtime";
import { httpClientProofProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import { DustSecretKey, ZswapSecretKeys } from "@midnight-ntwrk/midnight-js-protocol/ledger";
import {
  FluentWalletBuilder,
  inMemoryPrivateStateProvider,
  MidnightWalletProvider,
  syncWallet,
  waitForFunds,
} from "@midnight-ntwrk/testkit-js";
import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import { deriveJubjubPublicKeyFromSeed } from "@midnight-ntwrk/trust-registry-contract";
import { open, lstat, readFile, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import pino from "pino";
import WebSocket from "ws";

export const PUBLIC_LOCAL_SMOKE_SEED = `${"0".repeat(63)}1`;
const KEY = /^[0-9a-f]{64}$/u;
const SILENT_LOGGER = pino({ level: "silent" });

function loopbackUrl(value, protocols) {
  const url = new URL(value);
  if (!protocols.includes(url.protocol) || url.hostname !== "127.0.0.1"
    || !url.port || url.username || url.password || url.hash) {
    throw new Error("Local smoke provider only accepts explicit 127.0.0.1 endpoints");
  }
  return url;
}

/** This module is for the documented public-genesis development wallet only. */
export function validateLocalSmokeEnvironment(network, env = process.env) {
  if (network?.networkId !== "undeployed"
    || env.TR_SMOKE_WALLET_SEED !== PUBLIC_LOCAL_SMOKE_SEED
    || !isAbsolute(env.TR_SMOKE_STATE_DIR ?? "")
    || !Array.isArray(network.allowedHosts)
    || network.allowedHosts.length !== 1 || network.allowedHosts[0] !== "127.0.0.1") {
    throw new Error("Local smoke provider requires the public test wallet, private state path, and undeployed loopback network");
  }
  loopbackUrl(network.rpcUrl, ["http:"]);
  loopbackUrl(network.indexerHttpUrl, ["http:"]);
  loopbackUrl(network.indexerWsUrl, ["ws:"]);
  loopbackUrl(env.TR_SMOKE_PROOF_URL, ["http:"]);
  return {
    walletSeed: env.TR_SMOKE_WALLET_SEED,
    stateDirectory: env.TR_SMOKE_STATE_DIR,
    proofServerUrl: env.TR_SMOKE_PROOF_URL,
  };
}

async function privateStateDirectory(path) {
  const stat = await lstat(path);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Smoke state directory must be owned by this user and mode 0700");
  }
  return realpath(path);
}

export async function loadOrCreateSmokeMaintenanceKey(directory) {
  const root = await privateStateDirectory(directory);
  const path = join(root, "smoke-maintenance-key");
  let file;
  try {
    file = await open(path, "wx", 0o600);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  if (file) {
    try {
      await file.writeFile(`${sampleSigningKey()}\n`);
      await file.sync();
    } finally {
      await file.close();
    }
  }
  const stat = await lstat(path);
  if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.size > 80
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Smoke maintenance key must be a private regular file");
  }
  const key = (await readFile(path, "utf8")).trim();
  if (!KEY.test(key)) throw new Error("Smoke maintenance key is malformed");
  return key;
}

export async function createLocalDeploymentMaterial({ network }, env = process.env) {
  const config = validateLocalSmokeEnvironment(network, env);
  const maintenanceKey = await loadOrCreateSmokeMaintenanceKey(config.stateDirectory);
  const nodeWs = new URL(network.rpcUrl);
  nodeWs.protocol = "ws:";
  const walletEnvironment = {
    walletNetworkId: "undeployed",
    networkId: "undeployed",
    indexer: network.indexerHttpUrl,
    indexerWS: network.indexerWsUrl,
    node: network.rpcUrl,
    nodeWS: nodeWs.href,
    proofServer: config.proofServerUrl,
    faucet: undefined,
  };
  globalThis.WebSocket = WebSocket;
  const built = await FluentWalletBuilder.forEnvironment(walletEnvironment)
    .withSeed(config.walletSeed).buildWithoutStarting();
  const wallet = await MidnightWalletProvider.withWallet(
    SILENT_LOGGER, walletEnvironment, built.wallet,
    ZswapSecretKeys.fromSeed(built.seeds.shielded),
    DustSecretKey.fromSeed(built.seeds.dust),
    built.keystore,
  );
  try {
    await wallet.start(false);
    await syncWallet(wallet.wallet, 1_000, 300_000);
    const nightBalance = await waitForFunds(wallet.wallet, walletEnvironment, false, built.keystore);
    if (nightBalance <= 0n) throw new Error("Public local smoke wallet is not funded on this ledger");
    const fundedState = await syncWallet(wallet.wallet, 1_000, 300_000);
    if (fundedState.dust.balance(new Date()) <= 0n) {
      throw new Error("Public local smoke wallet has no spendable DUST");
    }
    const contractDist = dirname(fileURLToPath(import.meta.resolve("@midnight-ntwrk/trust-registry-contract")));
    const zkConfig = new NodeZkConfigProvider(join(contractDist, "managed", "trust-registry"));
    const providers = {
      privateStateProvider: inMemoryPrivateStateProvider(),
      publicDataProvider: indexerPublicDataProvider(network.indexerHttpUrl, network.indexerWsUrl),
      zkConfigProvider: zkConfig,
      proofProvider: httpClientProofProvider(config.proofServerUrl, zkConfig),
      walletProvider: wallet,
      midnightProvider: wallet,
    };
    const registryId = "registry:midnight:undeployed:smoke";
    return {
      bootstrap: {
        registryId,
        registryDidCommitment: bytes32Commitment("did:midnight:undeployed:registry-smoke"),
        governancePolicyCommitment: bytes32Commitment("policy:local-development-smoke"),
        maintainerId: bytes32Commitment("maintainer:local-development-smoke"),
        maintainerDidCommitment: bytes32Commitment("did:midnight:undeployed:maintainer-smoke"),
        maintainerKeyId: bytes32Commitment("maintainer:local-development-smoke#key-1"),
        maintainerPublicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(19)),
        maintainerThreshold: 1n,
      },
      providers,
      contractMaintenanceSigningKey: maintenanceKey,
      stop: () => wallet.stop(),
    };
  } catch (error) {
    try { await wallet.stop(); } catch { /* Keep the original setup failure. */ }
    throw error;
  }
}
