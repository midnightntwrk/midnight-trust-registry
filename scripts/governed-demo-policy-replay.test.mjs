import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import {
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import {
  createAuditorScenarioFixture,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";
import { AdversarialMatrix } from "./adversarial-matrix.mjs";
import {
  runHistoricalPolicyClientChecks,
  runOldPolicyIssuerReplay,
  runOldPolicyRecognitionReplay,
  runRevisedPolicyRoleReplays,
} from "./governed-demo-policy-replay.mjs";

test("policy replay matrix awaits rejection and verified evidence", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-governed-policy-replay");
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  const matrix = new AdversarialMatrix();
  const second = createMaintainerScenarioFixture("isolated-governed-policy-second");
  const third = createMaintainerScenarioFixture("isolated-governed-policy-third");
  const historicalIssuer = createIssuerScenarioFixture("isolated-governed-historical-issuer");
  const historicalVerifier = createVerifierScenarioFixture("isolated-governed-historical-verifier");
  const historicalAuditor = createAuditorScenarioFixture("isolated-governed-historical-auditor");
  const historicalRecognition = createRecognitionScenarioFixture("isolated-governed-historical-recognition");
  const currentIssuer = createIssuerScenarioFixture("isolated-governed-current-issuer");
  const signCompact = async (maintainer, prepared, sourceHarness, policyCommitment) => {
    const ledger = await sourceHarness.simulator.getLedger();
    return {
      keyId: maintainer.keyId,
      publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
      signature: signDeploymentBoundMaintainerActionFromSeed(
        maintainer.seed,
        ledger.registryId,
        ledger.deploymentNetworkIdCommitment,
        Buffer.from(sourceHarness.simulator.contractAddress, "hex"),
        policyCommitment ?? ledger.governancePolicyCommitment,
        prepared.actionKind,
        prepared.actionPayloadHash,
        prepared.actionSequence,
      ),
    };
  };
  await harness.authorizeIssuer(historicalIssuer);
  await harness.authorizeVerifier(historicalVerifier);
  await harness.authorizeAuditor(historicalAuditor);
  await harness.authorizeRecognition(historicalRecognition);
  const originalVerifierBundle = await harness.evaluateCurrentVerifierDecision(historicalVerifier);
  const originalAuditorBundle = await harness.evaluateCurrentAuditorDecision(historicalAuditor);
  const originalRecognitionBundle = await harness.evaluateCurrentRecognitionDecision(historicalRecognition);
  await harness.authorizeMaintainer(second);
  await harness.authorizeMaintainer(third);
  const formerPolicyCommitment = Buffer.from((await harness.simulator.getLedger()).governancePolicyCommitment);
  await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  await harness.proposeIssuer(currentIssuer, [second]);
  const currentPolicyBundle = await runOldPolicyIssuerReplay(
    matrix, harness, currentIssuer, second, third, formerPolicyCommitment, signCompact,
  );
  await runOldPolicyRecognitionReplay(matrix, harness, second, third, formerPolicyCommitment, signCompact);
  const historicalPolicyBundle = await harness.buildIssuerHistoricalEvidence(historicalIssuer);
  await runHistoricalPolicyClientChecks(matrix, client, {
    historicalPolicyBundle,
    originalVerifierBundle,
    originalAuditorBundle,
    originalRecognitionBundle,
    currentPolicyBundle,
  }, (value) => `${value.slice(0, -1)}${value.endsWith("0") ? "1" : "0"}`);
  await runRevisedPolicyRoleReplays(matrix, harness, client, second, third, formerPolicyCommitment, signCompact);
  matrix.assertAllPassed();
  assert.ok(matrix.report().summary.total >= 20);
});
