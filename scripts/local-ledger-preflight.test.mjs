import assert from "node:assert/strict";
import { test } from "node:test";

import { checkLocalLedgerPreflight, validateLocalLedgerPin,
  validateStandaloneGenesisPin } from "./local-ledger-preflight.mjs";

const genesis = `0x${"a".repeat(64)}`;
const finalized = `0x${"b".repeat(64)}`;
const plan = {
  format: "tr-local-ledger-pin-v1",
  networkId: "undeployed",
  sourceRevision: "c".repeat(40),
  rpcUrl: "http://127.0.0.1:29944",
  expectedGenesisHash: genesis,
  allowedHosts: ["127.0.0.1"],
};

const rpc = (actualGenesis = genesis, head = finalized) => async (_url, options) => {
  const request = JSON.parse(options.body);
  return new Response(JSON.stringify({
    jsonrpc: "2.0", id: 1,
    result: request.method === "chain_getBlockHash" ? actualGenesis : head,
  }), { status: 200 });
};

test("records a pinned progressing local node observation, not deployment evidence", async () => {
  const observed = await checkLocalLedgerPreflight(plan, rpc());
  assert.equal(observed.kind, "local-node-observation-only");
  assert.equal(observed.networkId, "undeployed");
  assert.equal(observed.finalizedBlockHash, finalized);
  assert.equal(observed.expectedGenesisHash, genesis);
});

test("rejects genesis mismatch, non-progressing finality, and public endpoints", async () => {
  await assert.rejects(checkLocalLedgerPreflight(plan, rpc(`0x${"d".repeat(64)}`)), /genesis hash mismatch/u);
  await assert.rejects(checkLocalLedgerPreflight(plan, rpc(genesis, genesis)), /no progressing finalized head/u);
  await assert.rejects(checkLocalLedgerPreflight({ ...plan, rpcUrl: "http://public.example:9944" }, rpc()), /not on the approved/u);
});

test("rejects malformed or unapproved pins before querying the node", async () => {
  let requests = 0;
  const fetchImpl = async () => { requests += 1; throw new Error("unexpected query"); };
  await assert.rejects(checkLocalLedgerPreflight({ ...plan, expectedGenesisHash: `0x${"0".repeat(64)}` }, fetchImpl), /exact approved/u);
  await assert.rejects(checkLocalLedgerPreflight({ ...plan, networkId: "preprod" }, fetchImpl), /exact approved/u);
  await assert.rejects(checkLocalLedgerPreflight({ ...plan, added: "unreviewed" }, fetchImpl), /exact approved/u);
  await assert.rejects(checkLocalLedgerPreflight({ ...plan, sourceRevision: null }, fetchImpl), /exact approved/u);
  await assert.rejects(checkLocalLedgerPreflight({ ...plan, expectedGenesisHash: null }, fetchImpl), /exact approved/u);
  await assert.rejects(checkLocalLedgerPreflight({ ...plan, allowedHosts: ["127.0.0.1", null] }, fetchImpl), /exact approved/u);
  assert.equal(requests, 0);
});

test("exact pin validation can run before selecting an installation access path", () => {
  assert.deepEqual(validateLocalLedgerPin(plan), plan);
  for (const malformed of [null, [], { ...plan, added: "unreviewed" },
    { ...plan, networkId: "preprod" },
    { ...plan, expectedGenesisHash: `0x${"0".repeat(64)}` },
    { ...plan, allowedHosts: ["127.0.0.1", null] }]) {
    assert.throws(() => validateLocalLedgerPin(malformed), /exact approved/u);
  }
});

test("standalone installation pins only one canonical loopback endpoint", () => {
  assert.deepEqual(validateStandaloneGenesisPin(plan, plan.sourceRevision), plan);
  assert.throws(() => validateStandaloneGenesisPin(plan, "d".repeat(40)), /source revision disagrees/u);
  for (const malformed of [
    { ...plan, allowedHosts: ["node"] },
    { ...plan, allowedHosts: ["127.0.0.1", "node"] },
    { ...plan, rpcUrl: "http://node:29944" },
    { ...plan, rpcUrl: "http://127.0.0.1:29944/path" },
    { ...plan, rpcUrl: "http://127.0.0.1:29944?probe=1" },
  ]) assert.throws(() => validateStandaloneGenesisPin(malformed, plan.sourceRevision), /prepared loopback host/u);
  for (const port of ["1", "99999"]) {
    assert.throws(() => validateStandaloneGenesisPin({ ...plan,
      rpcUrl: `http://127.0.0.1:${port}` }, plan.sourceRevision), /valid prepared loopback port/u);
  }
});
