import assert from "node:assert/strict";
import { test } from "node:test";

import { TrustRegistryTrqpAdapter } from "../adapters/trqp/dist/index.js";
import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  createRecognitionScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";
import { createTrustRegistryApiServer } from "../packages/trust-registry-api/dist/index.js";

const startRecognitionCase = async (context, label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const recognition = createRecognitionScenarioFixture(`${label}-recognition`);
  harness.authorizeRecognition(recognition);
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  const active = harness.evaluateCurrentRecognitionDecision(recognition);
  const activeAt = active.recognition.effectiveFrom;
  assert.ok(client.verifyRecognitionBundle(active, {
    expectedRegistryId: harness.registryId, evaluationTime: activeAt,
  }));
  const fixtures = { label, recognitions: [{ fixture: recognition, label: "recognition" }] };
  let snapshot = publishSimulatorSnapshot(harness, fixtures);
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
  const base = `http://127.0.0.1:${address.port}`;
  const post = async (path, body) => {
    const response = await fetch(`${base}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json();
    return { status: response.status, payload };
  };
  const selection = (at) => ({
    recognizedAuthorityDid: recognition.recognizedAuthorityDid,
    recognizedRegistryId: recognition.recognizedRegistryId,
    scopeResourceType: recognition.scopeResourceType,
    scopeResourceId: recognition.scopeResourceId,
    at,
  });
  const evaluate = async (at) => {
    const result = await post("/v1/recognitions/evaluate", selection(at));
    assert.equal(result.status, 200, JSON.stringify(result.payload));
    return result.payload;
  };
  const trqpRequest = (at) => ({
    entity_id: recognition.recognizedAuthorityDid,
    authority_id: harness.registryDid,
    action: recognition.scopeResourceType,
    resource: recognition.scopeResourceId,
    context: { time: at, recognized_registry_id: recognition.recognizedRegistryId },
  });
  const queryTrqp = async (at) => {
    const result = await post("/v1/trqp/recognitions/query", trqpRequest(at));
    assert.equal(result.status, 200, JSON.stringify(result.payload));
    return result.payload;
  };
  const change = (action) => {
    harness[action](recognition);
    snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
    return harness.buildRecognitionHistoricalEvidence(recognition);
  };
  return { harness, recognition, client, active, activeAt, post, selection,
    evaluate, trqpRequest, queryTrqp, change };
};

test("recognition-wrong-external-registry-api", async (context) => {
  const { activeAt, post, selection } = await startRecognitionCase(context, "isolated-recognition-wrong-registry-api");
  assert.equal((await post("/v1/recognitions/resolve", selection(activeAt))).status, 200);
  const wrong = await post("/v1/recognitions/resolve", {
    ...selection(activeAt), recognizedRegistryId: "registry:external:wrong:v1",
  });
  assert.equal(wrong.status, 404);
  assert.equal(wrong.payload.type.slice(wrong.payload.type.lastIndexOf("/") + 1), "recognition-not-found");
});

test("recognition-not-issuer-authorization", async (context) => {
  const { active, client } = await startRecognitionCase(context, "isolated-recognition-not-issuer");
  assert.ok(client.verifyRecognitionBundle(active, {}));
  assert.throws(() => client.verifyIssuerAuthorizationBundle(active, {}),
    /does not contain issuer authorization/iu);
});

test("trqp-wrong-recognized-registry", async (context) => {
  const { harness, recognition, active, activeAt, trqpRequest } =
    await startRecognitionCase(context, "isolated-trqp-recognition-registry");
  const adapter = new TrustRegistryTrqpAdapter({
    getRegistryRecord: async (authorityId) => authorityId === harness.registryDid
      ? harness.registryRecord : null,
    getAuthorizationDecision: async () => null,
    getRecognitionDecision: async (request) => request.entity_id === recognition.recognizedAuthorityDid
      && request.action === recognition.scopeResourceType
      && request.resource === recognition.scopeResourceId
      && request.context?.recognized_registry_id === recognition.recognizedRegistryId
      ? { bundle: active, statusAtTime: "active", trustedAtTime: true } : null,
  }, { clock: () => activeAt });
  assert.equal((await adapter.queryRecognition(trqpRequest(activeAt))).ok, true);
  const wrong = await adapter.queryRecognition({
    ...trqpRequest(activeAt),
    context: { ...trqpRequest(activeAt).context, recognized_registry_id: "registry:external:wrong:v1" },
  });
  assert.equal(wrong.ok, false);
  assert.equal(wrong.problem.status, 404);
  assert.equal(wrong.problem.type.slice(wrong.problem.type.lastIndexOf("/") + 1), "not-found");
});

test("recognition-active-api", async (context) => {
  const { activeAt, evaluate } = await startRecognitionCase(context, "isolated-recognition-active-api");
  assert.equal((await evaluate(activeAt)).trustedAtTime, true);
});

test("recognition-active-trqp", async (context) => {
  const { activeAt, evaluate, queryTrqp } = await startRecognitionCase(context, "isolated-recognition-active-trqp");
  assert.equal((await queryTrqp(activeAt)).recognized, (await evaluate(activeAt)).trustedAtTime);
});

for (const stage of [
  { name: "suspended", action: "suspendRecognition", at: "suspendedAt", suffix: "suspension" },
  { name: "revoked", action: "revokeRecognition", at: "revokedAt", suffix: "revocation" },
]) {
  const staged = async (context, label) => {
    const fixture = await startRecognitionCase(context, label);
    if (stage.name === "revoked") fixture.change("suspendRecognition");
    const changed = fixture.change(stage.action);
    assert.equal(changed.recognition.status, stage.name);
    return { ...fixture, changed };
  };

  test(`recognition-${stage.name}-api`, async (context) => {
    const { activeAt, changed, evaluate } = await staged(context, `isolated-recognition-${stage.name}-api`);
    assert.equal((await evaluate(activeAt)).trustedAtTime, true);
    assert.equal((await evaluate(changed.recognition[stage.at])).trustedAtTime, false);
  });

  test(`recognition-${stage.name}-trqp`, async (context) => {
    const { activeAt, changed, evaluate, queryTrqp } =
      await staged(context, `isolated-recognition-${stage.name}-trqp`);
    assert.equal((await queryTrqp(activeAt)).recognized, true);
    const at = changed.recognition[stage.at];
    assert.equal((await queryTrqp(at)).recognized, (await evaluate(at)).trustedAtTime);
    assert.equal((await queryTrqp(at)).recognized, false);
  });

  test(`recognition-historical-api-after-${stage.suffix}`, async (context) => {
    const { activeAt, evaluate } = await staged(context, `isolated-recognition-history-${stage.name}-api`);
    assert.equal((await evaluate(activeAt)).trustedAtTime, true);
  });

  test(`recognition-historical-after-${stage.suffix}-trqp`, async (context) => {
    const { activeAt, evaluate, queryTrqp } =
      await staged(context, `isolated-recognition-history-${stage.name}-trqp`);
    assert.equal((await queryTrqp(activeAt)).recognized, (await evaluate(activeAt)).trustedAtTime);
    assert.equal((await queryTrqp(activeAt)).recognized, true);
  });

  test(`recognition-historical-after-${stage.suffix}`, async (context) => {
    const { harness, client, active, activeAt, changed } =
      await staged(context, `isolated-recognition-history-${stage.name}-client`);
    assert.throws(() => client.verifyRecognitionBundle(changed, { expectedRegistryId: harness.registryId }),
      /not active/iu);
    assert.ok(client.verifyRecognitionBundle(active, {
      expectedRegistryId: harness.registryId, evaluationTime: activeAt,
    }));
  });
}
