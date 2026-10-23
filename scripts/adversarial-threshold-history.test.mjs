import assert from "node:assert/strict";
import { test } from "node:test";

import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  createAuditorScenarioFixture,
  createMaintainerScenarioFixture,
  createRecognitionScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";
import { createTrustRegistryApiServer } from "../packages/trust-registry-api/dist/index.js";

const startThresholdHistory = async (context, label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const auditor = createAuditorScenarioFixture(`${label}-auditor`);
  const recognition = createRecognitionScenarioFixture(`${label}-recognition`);
  harness.authorizeAuditor(auditor);
  harness.authorizeRecognition(recognition);
  const oldAuditor = harness.evaluateCurrentAuditorDecision(auditor);
  const oldRecognition = harness.evaluateCurrentRecognitionDecision(recognition);
  const fixtures = { label, auditors: [{ fixture: auditor, label: "auditor" }],
    recognitions: [{ fixture: recognition, label: "recognition" }] };
  const oldSnapshot = publishSimulatorSnapshot(harness, fixtures);
  const second = createMaintainerScenarioFixture(`${label}-second`);
  const third = createMaintainerScenarioFixture(`${label}-third`);
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  harness.revokeAuditor(auditor, [second]);
  harness.revokeRecognition(recognition, [second]);
  const snapshot = publishSimulatorSnapshot(harness, fixtures, oldSnapshot);
  const server = createTrustRegistryApiServer({
    source: { mode: "memory", loadSnapshot: async () => snapshot },
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  context.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const post = async (path, body) => {
    const response = await fetch(`http://127.0.0.1:${address.port}${path}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (response.status !== 200) {
      assert.fail(`Expected HTTP 200, received ${response.status}: ${await response.text()}`);
    }
    return response.json();
  };
  const auditorAt = new Date(Date.parse(oldAuditor.epoch.validFrom) + 1).toISOString();
  const recognitionAt = new Date(Date.parse(oldRecognition.epoch.validFrom) + 1).toISOString();
  const auditorRequest = { role: "auditor", subjectDid: auditor.subjectDid,
    resourceId: auditor.scopeResourceId, at: auditorAt };
  const recognitionRequest = { recognizedAuthorityDid: recognition.recognizedAuthorityDid,
    recognizedRegistryId: recognition.recognizedRegistryId,
    scopeResourceType: recognition.scopeResourceType,
    scopeResourceId: recognition.scopeResourceId, at: recognitionAt };
  const trqpRequest = { entity_id: recognition.recognizedAuthorityDid,
    authority_id: harness.registryDid, action: recognition.scopeResourceType,
    resource: recognition.scopeResourceId,
    context: { time: recognitionAt, recognized_registry_id: recognition.recognizedRegistryId } };
  return { harness, oldAuditor, oldRecognition, post, auditorRequest,
    recognitionRequest, trqpRequest };
};

test("auditor-history-survives-threshold-change", async (context) => {
  const { harness, oldAuditor } = await startThresholdHistory(context, "isolated-auditor-threshold-client");
  assert.notEqual(oldAuditor.policy.version, harness.policyRecord.version);
  assert.ok(new TrustRegistrySimulatorClient(harness.simulator)
    .verifyAuditorAuthorizationBundle(oldAuditor, {}));
});

test("recognition-history-survives-threshold-change", async (context) => {
  const { harness, oldRecognition } = await startThresholdHistory(context, "isolated-recognition-threshold-client");
  assert.notEqual(oldRecognition.policy.version, harness.policyRecord.version);
  assert.ok(new TrustRegistrySimulatorClient(harness.simulator)
    .verifyRecognitionBundle(oldRecognition, {}));
});

test("auditor-historical-api-after-threshold-change", async (context) => {
  const { harness, oldAuditor, post, auditorRequest } =
    await startThresholdHistory(context, "isolated-auditor-threshold-api");
  const decision = await post("/v1/authorizations/evaluate/evidence", auditorRequest);
  assert.equal(decision.trustedAtTime, true);
  assert.equal(decision.bundle.epoch.epochId, oldAuditor.epoch.epochId);
  assert.equal(decision.bundle.policy.version, oldAuditor.policy.version);
  assert.notEqual(decision.bundle.policy.version, harness.policyRecord.version);
});

test("recognition-historical-api-after-threshold-change", async (context) => {
  const { harness, oldRecognition, post, recognitionRequest } =
    await startThresholdHistory(context, "isolated-recognition-threshold-api");
  const decision = await post("/v1/recognitions/evaluate/evidence", recognitionRequest);
  assert.equal(decision.trustedAtTime, true);
  assert.equal(decision.bundle.epoch.epochId, oldRecognition.epoch.epochId);
  assert.equal(decision.bundle.policy.version, oldRecognition.policy.version);
  assert.notEqual(decision.bundle.policy.version, harness.policyRecord.version);
});

test("recognition-historical-trqp-after-threshold-change", async (context) => {
  const { harness, oldRecognition, post, trqpRequest } =
    await startThresholdHistory(context, "isolated-recognition-threshold-trqp");
  const decision = await post("/v1/trqp/recognitions/evidence", trqpRequest);
  assert.equal(decision.recognized, true);
  assert.equal(decision.bundle.epoch.epochId, oldRecognition.epoch.epochId);
  assert.equal(decision.bundle.policy.version, oldRecognition.policy.version);
  assert.notEqual(decision.bundle.policy.version, harness.policyRecord.version);
});
