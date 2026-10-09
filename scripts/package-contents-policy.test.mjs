import assert from "node:assert/strict";
import test from "node:test";

import { unexpectedLightContractArtifacts } from "./package-contents-policy.mjs";

test("light contract artifacts contain only generated contract modules", () => {
  const paths = [
    "dist/managed/trust-registry/contract/index.js",
    "dist/managed/trust-registry/contract/index.d.ts",
    "dist/trust-registry.compact",
    "dist/managed/trust-registry/keys/proposeIssuerAuthorization.prover",
    "dist/managed/trust-registry/zkir/proposeIssuerAuthorization.zkir",
  ];
  assert.deepEqual(unexpectedLightContractArtifacts(paths), paths.slice(3));
});
