import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import {
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";

const signAction = (harness, maintainer, prepared, policyCommitment) => {
  const ledger = harness.simulator.getLedger();
  return {
    keyId: maintainer.keyId,
    publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
    signature: signDeploymentBoundMaintainerActionFromSeed(
      maintainer.seed,
      ledger.registryId,
      ledger.deploymentNetworkIdCommitment,
      Buffer.from(harness.simulator.contractAddress, "hex"),
      policyCommitment,
      prepared.actionKind,
      prepared.actionPayloadHash,
      prepared.actionSequence,
    ),
  };
};

test("snapshot publication cannot confound isolated old-policy signature replay", () => {
  const snapshotHarness = new LocalTrustRegistryIntegrationHarness("policy-snapshot-side-effect");
  const historical = createIssuerScenarioFixture("policy-snapshot-historical");
  snapshotHarness.authorizeIssuer(historical);
  const beforeSnapshot = snapshotHarness.simulator.getLedger().governanceActionCount;
  publishSimulatorSnapshot(snapshotHarness, {
    label: "policy-snapshot-side-effect",
    issuers: [{ fixture: historical, label: "historical" }],
  });
  assert.ok(snapshotHarness.simulator.getLedger().governanceActionCount > beforeSnapshot);

  const replayHarness = new LocalTrustRegistryIntegrationHarness("policy-replay-isolated");
  const second = createMaintainerScenarioFixture("policy-replay-second");
  const third = createMaintainerScenarioFixture("policy-replay-third");
  const current = createIssuerScenarioFixture("policy-replay-current");
  replayHarness.authorizeMaintainer(second);
  replayHarness.authorizeMaintainer(third);
  const formerPolicy = Buffer.from(replayHarness.simulator.getLedger().governancePolicyCommitment);
  replayHarness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  replayHarness.proposeIssuer(current, [second]);
  const prepared = replayHarness.prepareIssuerDecisionAction(current, "approve");
  const sequence = replayHarness.simulator.getLedger().governanceActionCount;
  assert.equal(prepared.actionSequence, sequence);
  const oldSignature = signAction(replayHarness, second, prepared, formerPolicy);
  const oldCoSignature = signAction(replayHarness, third, prepared, formerPolicy);
  assert.throws(() => replayHarness.simulator.authorizeIssuerAuthorization(
    oldSignature.keyId, oldSignature.publicKey, oldSignature.signature,
    current.authorizationIdCommitment, prepared.evidenceHash, [oldCoSignature],
  ), /Invalid Jubjub Schnorr signature/u);
  assert.equal(replayHarness.simulator.getLedger().governanceActionCount, sequence);

  const currentPolicy = replayHarness.simulator.getLedger().governancePolicyCommitment;
  const signature = signAction(replayHarness, second, prepared, currentPolicy);
  const coSignature = signAction(replayHarness, third, prepared, currentPolicy);
  replayHarness.simulator.authorizeIssuerAuthorization(
    signature.keyId, signature.publicKey, signature.signature,
    current.authorizationIdCommitment, prepared.evidenceHash, [coSignature],
  );
  assert.equal(replayHarness.simulator.getLedger().governanceActionCount, sequence + 1n);
});
