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

const signAction = async (harness, maintainer, prepared, policyCommitment) => {
  const ledger = await harness.simulator.getLedger();
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

test("snapshot publication cannot confound isolated old-policy signature replay", async () => {
  const snapshotHarness = new LocalTrustRegistryIntegrationHarness("policy-snapshot-side-effect");
  const historical = createIssuerScenarioFixture("policy-snapshot-historical");
  await snapshotHarness.authorizeIssuer(historical);
  const beforeSnapshot = (await snapshotHarness.simulator.getLedger()).governanceActionCount;
  await publishSimulatorSnapshot(snapshotHarness, {
    label: "policy-snapshot-side-effect",
    issuers: [{ fixture: historical, label: "historical" }],
  });
  assert.ok((await snapshotHarness.simulator.getLedger()).governanceActionCount > beforeSnapshot);

  const replayHarness = new LocalTrustRegistryIntegrationHarness("policy-replay-isolated");
  const second = createMaintainerScenarioFixture("policy-replay-second");
  const third = createMaintainerScenarioFixture("policy-replay-third");
  const current = createIssuerScenarioFixture("policy-replay-current");
  await replayHarness.authorizeMaintainer(second);
  await replayHarness.authorizeMaintainer(third);
  const formerPolicy = Buffer.from((await replayHarness.simulator.getLedger()).governancePolicyCommitment);
  await replayHarness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  await replayHarness.proposeIssuer(current, [second]);
  const prepared = await replayHarness.prepareIssuerDecisionAction(current, "approve");
  const sequence = (await replayHarness.simulator.getLedger()).governanceActionCount;
  assert.equal(prepared.actionSequence, sequence);
  const pendingAuthorization = structuredClone(await replayHarness.simulator.getIssuerAuthorization(
    current.authorizationIdCommitment,
  ));
  const oldSignature = await signAction(replayHarness, second, prepared, formerPolicy);
  const oldCoSignature = await signAction(replayHarness, third, prepared, formerPolicy);
  await assert.rejects(replayHarness.simulator.authorizeIssuerAuthorization(
    oldSignature.keyId, oldSignature.publicKey, oldSignature.signature,
    current.authorizationIdCommitment, prepared.evidenceHash, [oldCoSignature],
  ), /Invalid Jubjub Schnorr signature/u);
  assert.equal((await replayHarness.simulator.getLedger()).governanceActionCount, sequence);
  assert.deepEqual(await replayHarness.simulator.getIssuerAuthorization(
    current.authorizationIdCommitment,
  ), pendingAuthorization);

  const currentPolicy = (await replayHarness.simulator.getLedger()).governancePolicyCommitment;
  const signature = await signAction(replayHarness, second, prepared, currentPolicy);
  const coSignature = await signAction(replayHarness, third, prepared, currentPolicy);
  await replayHarness.simulator.authorizeIssuerAuthorization(
    signature.keyId, signature.publicKey, signature.signature,
    current.authorizationIdCommitment, prepared.evidenceHash, [coSignature],
  );
  assert.equal((await replayHarness.simulator.getLedger()).governanceActionCount, sequence + 1n);
  assert.notDeepEqual(await replayHarness.simulator.getIssuerAuthorization(
    current.authorizationIdCommitment,
  ), pendingAuthorization);
});
