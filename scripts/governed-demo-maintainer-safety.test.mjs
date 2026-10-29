import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import {
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { AdversarialMatrix } from "./adversarial-matrix.mjs";
import {
  maintainerSafetyCaseIds,
  runMaintainerSafetyCase,
  runMaintainerSafetyScenarios,
} from "./governed-demo-maintainer-safety.mjs";

function signCompact(maintainer, prepared, harness) {
  const ledger = harness.simulator.getLedger();
  return {
    keyId: maintainer.keyId,
    publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
    signature: signDeploymentBoundMaintainerActionFromSeed(
      maintainer.seed,
      ledger.registryId,
      ledger.deploymentNetworkIdCommitment,
      Buffer.from(harness.simulator.contractAddress, "hex"),
      ledger.governancePolicyCommitment,
      prepared.actionKind,
      prepared.actionPayloadHash,
      prepared.actionSequence,
    ),
  };
}

for (const id of maintainerSafetyCaseIds) {
  test(`isolated maintainer safety case: ${id}`, () => {
    const matrix = new AdversarialMatrix();
    runMaintainerSafetyCase(id, matrix, signCompact);
    assert.deepEqual(matrix.report().summary, { total: 1, passed: 1, failed: 0 });
    assert.equal(matrix.report().cases[0].id, id);
  });
}

test("a failed maintainer signature case does not suppress the next case", () => {
  const matrix = new AdversarialMatrix({ collectFailures: true });
  runMaintainerSafetyScenarios(matrix, () => { throw new Error("deliberately bad test signer"); });
  assert.deepEqual(matrix.report().cases.map(({ id, status }) => [id, status]), [
    ["compact-self-voted-maintainer-suspension", "passed"],
    ["compact-self-voted-maintainer-revocation", "passed"],
    ["compact-removal-below-maintainer-threshold", "failed"],
    ["compact-removed-maintainer-signer", "failed"],
  ]);
  assert.equal(JSON.stringify(matrix.report()).includes("deliberately bad"), false);
});
