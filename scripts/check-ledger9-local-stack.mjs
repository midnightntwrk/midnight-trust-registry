#!/usr/bin/env node

import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const genesisPattern = /^0x[0-9a-f]{64}$/u;

function port(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error("Local stack port must be an integer from 1 to 65535");
  }
  return parsed;
}

async function json(response) {
  if (!response.ok) throw new Error(`Local stack request failed with HTTP ${response.status}`);
  return response.json();
}

async function fetchLocal(fetchImpl, url, options, service) {
  try {
    return await fetchImpl(url, { ...options, signal: AbortSignal.timeout(5000) });
  } catch (error) {
    const timedOut = error instanceof Error && ["AbortError", "TimeoutError"].includes(error.name);
    throw new Error(`${service} ${timedOut ? "timed out after 5 seconds" : "request failed"} at ${url}`, {
      cause: error,
    });
  }
}

export async function checkLedger9LocalStack(input = {}) {
  const fetchImpl = input.fetchImpl ?? fetch;
  const nodeUrl = `http://127.0.0.1:${port(input.nodePort, 29944)}`;
  const indexerUrl = `http://127.0.0.1:${port(input.indexerPort, 28088)}/api/v4/graphql`;
  const proofUrl = `http://127.0.0.1:${port(input.proofPort, 26300)}/`;
  const request = async (method, params = []) => {
    const body = await json(await fetchLocal(fetchImpl, nodeUrl, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    }, `Node RPC ${method}`));
    if (body.jsonrpc !== "2.0" || body.error || body.result === undefined) {
      throw new Error(`Invalid node RPC response for ${method}`);
    }
    return body.result;
  };
  const query = async (source) => {
    const body = await json(await fetchLocal(fetchImpl, indexerUrl, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: source }),
    }, "Indexer GraphQL"));
    if (body.errors || !body.data) throw new Error("Indexer GraphQL query failed");
    return body.data;
  };

  const nodeVersion = await request("system_version");
  assert.match(nodeVersion, /^2\.1\.101(?:-|$)/u, "Unexpected local node version");
  const runtime = await request("state_getRuntimeVersion");
  assert.equal(runtime.specVersion, 2001100, "Unexpected local runtime protocol version");
  const genesisHash = await request("chain_getBlockHash", [0]);
  assert.match(genesisHash, genesisPattern, "Invalid node genesis hash");
  if (input.expectedGenesisHash !== undefined) {
    assert.equal(genesisHash, input.expectedGenesisHash, "Local genesis differs from the approved value");
  }
  const indexedGenesis = (await query("{ block(offset: { height: 0 }) { height hash protocolVersion } }")).block;
  assert.equal(indexedGenesis?.height, 0, "Indexer has not served genesis");
  assert.equal(`0x${indexedGenesis.hash}`, genesisHash, "Node and indexer genesis differ");
  const latest = (await query("{ block { height hash protocolVersion } }")).block;
  assert.ok(Number.isSafeInteger(latest?.height) && latest.height >= 0, "Indexer has no current block");
  assert.equal(latest.protocolVersion, 2001100, "Indexer is not serving Ledger 9 protocol blocks");
  assert.match(latest.hash, /^[0-9a-f]{64}$/u, "Indexer current block hash is malformed");
  const proof = await fetchLocal(fetchImpl, proofUrl, {}, "Proof server");
  if (!proof.ok) throw new Error(`Proof server is unavailable: HTTP ${proof.status}`);
  return { nodeVersion, protocolVersion: runtime.specVersion, genesisHash,
    indexedHeight: latest.height, proofServerReachable: true };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const result = await checkLedger9LocalStack({
      nodePort: process.env.TR_NODE_PORT,
      indexerPort: process.env.TR_INDEXER_PORT,
      proofPort: process.env.TR_PROOF_PORT,
      expectedGenesisHash: process.env.TR_EXPECTED_GENESIS_HASH,
    });
    console.log(JSON.stringify(result));
  } catch (error) {
    console.error(`Ledger 9 local stack check failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
