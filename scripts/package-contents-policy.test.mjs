import assert from "node:assert/strict";
import test from "node:test";

import { missingFullContractArtifacts, unexpectedLightContractArtifacts } from "./package-contents-policy.mjs";

test("light contract artifacts contain only generated contract modules", () => {
  const paths = [
    "dist/managed/trust-registry/contract/index.js",
    "dist/managed/trust-registry/contract/index.d.ts",
    "dist/trust-registry.compact",
    "dist/managed/trust-registry/keys/proposeIssuerAuthorization.prover",
    "dist/managed/trust-registry/zkir/proposeIssuerAuthorization.zkir",
    "dist/managed/trust-registry/compiler/contract-info.json",
  ];
  assert.deepEqual(unexpectedLightContractArtifacts(paths), paths.slice(3));
});

test("full release artifacts require a proving key and ZK IR", () => {
  const complete = [
    "dist/managed/trust-registry/contract/index.js",
    "dist/managed/trust-registry/keys/proposeIssuerAuthorization.prover",
    "dist/managed/trust-registry/zkir/proposeIssuerAuthorization.zkir",
  ];
  assert.deepEqual(missingFullContractArtifacts(complete), []);
  assert.deepEqual(missingFullContractArtifacts(complete.slice(0, 1)), ["proving keys", "ZK IR"]);
  assert.deepEqual(missingFullContractArtifacts(complete.slice(0, 2)), ["ZK IR"]);
});
