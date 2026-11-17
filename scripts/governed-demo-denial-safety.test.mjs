import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import {
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { AdversarialMatrix } from "./adversarial-matrix.mjs";
import { runDenialSafetyScenario } from "./governed-demo-denial-safety.mjs";

test("denied proposal cannot confer trust and replacement requires archival", async () => {
  const matrix = new AdversarialMatrix();
  const signCompact = async (maintainer, prepared, harness) => {
    const ledger = await harness.simulator.getLedger();
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
  };
  const result = await runDenialSafetyScenario(matrix, signCompact);
  assert.equal(result.deniedBundle.authorization.status, "archived");
  assert.equal(result.denialEventHash.length, 32);
  assert.equal(result.replacementProposalEventHash.length, 32);
  assert.deepEqual(matrix.report().summary, { total: 3, passed: 3, failed: 0 });
});
