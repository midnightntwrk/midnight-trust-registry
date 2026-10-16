import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createCircuitContext, createConstructorContext } from "@midnight-ntwrk/compact-runtime";
import { deriveJubjubPublicKeyFromSeed } from "@midnight-ntwrk/trust-registry-contract";
import {
  createMidnightDid,
  pinnedVcAuthority,
  vcAuthorityDomainCommitment,
  vcAuthorityDomainFields,
} from "@midnight-ntwrk/trust-registry-integration";

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+$/u.test(version ?? "")) {
  throw new Error("Expected a pinned stable Compact compiler version");
}

const fixture = fileURLToPath(import.meta.resolve(
  "@midnight-ntwrk/trust-registry-integration/fixtures/vc-authority-consumer.compact",
));
const vcCompactRoot = dirname(fileURLToPath(import.meta.resolve(
  "@midnight-ntwrk/credential-compact/credentials/composable.compact",
)));
const cacheRoot = join(process.cwd(), "node_modules/.cache");
mkdirSync(cacheRoot, { recursive: true });
const output = mkdtempSync(join(cacheRoot, "packed-vc-consumer-"));

try {
  const compile = spawnSync("compact", [
    "compile", `+${version}`, "--skip-zk", "--compact-path", vcCompactRoot, fixture, output,
  ], { encoding: "utf8" });
  if (compile.error) throw compile.error;
  assert.equal(compile.status, 0, compile.stderr);

  const compiled = await import(pathToFileURL(join(output, "contract/index.js")).href);
  const authorityDid = createMidnightDid("packed-vc-consumer-authority");
  const domain = {
    networkId: "undeployed",
    consumerContractAddress: `0x${"11".repeat(32)}`,
    registryId: "registry:packed-vc-consumer:trusted",
    registryContractAddress: `0x${"22".repeat(32)}`,
    authorityDid,
    authorityMethodId: `${authorityDid}#authority-1`,
  };
  const fields = vcAuthorityDomainFields(domain);
  assert.deepEqual(
    compiled.pureCircuits.authorityDomainCommitment(fields),
    vcAuthorityDomainCommitment(domain),
  );
  const publicKey = deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(17));
  const contract = new compiled.Contract({});
  const initial = contract.initialState(
    createConstructorContext({}, "0".repeat(64)),
    pinnedVcAuthority({ domain, publicKey }),
    fields,
  );
  const circuitContext = createCircuitContext(
    domain.consumerContractAddress.slice(2),
    initial.currentZswapLocalState,
    initial.currentContractState,
    initial.currentPrivateState,
  );
  assert.deepEqual(
    compiled.ledger(circuitContext.currentQueryContext.state).pinnedDomain.networkIdCommitment,
    fields.networkIdCommitment,
  );
  assert.throws(() => contract.initialState(
    createConstructorContext({}, "0".repeat(64)),
    pinnedVcAuthority({ domain: { ...domain, registryId: "registry:other:trusted" }, publicKey }),
    fields,
  ), /domain preimage mismatch/i);

  console.log("[packed-vc-consumer] Ledger 8 fixture compiled and pinned the package authority domain.");
} finally {
  rmSync(output, { recursive: true, force: true });
}
