import assert from "node:assert/strict";
import { test } from "node:test";

import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  createIssuerScenarioFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";
import { createTrustRegistryApiServer } from "../packages/trust-registry-api/dist/index.js";

const startIssuerApi = async (context, label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const issuer = createIssuerScenarioFixture(`${label}-issuer`);
  harness.authorizeIssuer(issuer);
  const fixtures = { label, issuers: [{ fixture: issuer, label: "issuer" }] };
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
  const evaluate = async (at) => {
    const response = await fetch(`${base}/v1/authorizations/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        role: "issuer",
        subjectDid: issuer.subjectDid,
        resourceId: issuer.resourceId,
        at,
      }),
    });
    if (response.status !== 200) {
      assert.fail(`Expected HTTP 200, received ${response.status}: ${await response.text()}`);
    }
    return response.json();
  };
  const refresh = (nextFixtures = fixtures) => {
    snapshot = publishSimulatorSnapshot(harness, nextFixtures, snapshot);
  };
  const transition = (action) => {
    harness[action](issuer);
    refresh();
    return harness.buildIssuerHistoricalEvidence(issuer);
  };
  return { harness, issuer, base, evaluate, refresh, transition };
};

test("issuer-wrong-resource-api", async (context) => {
  const { issuer, base } = await startIssuerApi(context, "isolated-wrong-issuer-resource-api");
  const resolve = (resourceId) => fetch(`${base}/v1/authorizations/resolve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ role: "issuer", subjectDid: issuer.subjectDid, resourceId }),
  });
  const correct = await resolve(issuer.resourceId);
  assert.equal(correct.status, 200);
  const wrong = await resolve(createIssuerScenarioFixture("isolated-other-issuer-scope").resourceId);
  assert.equal(wrong.status, 404);
  const problem = await wrong.json();
  assert.equal(problem.type.slice(problem.type.lastIndexOf("/") + 1), "authorization-not-found");
});

test("verifier-wrong-resource-api", async (context) => {
  const { harness, issuer, base, refresh } = await startIssuerApi(context, "isolated-wrong-verifier-resource-api");
  const verifier = createVerifierScenarioFixture("isolated-verifier-api-scope");
  harness.authorizeVerifier(verifier);
  refresh({
    label: "isolated-wrong-verifier-resource-api",
    issuers: [{ fixture: issuer, label: "issuer" }],
    verifiers: [{ fixture: verifier, label: "verifier" }],
  });
  const resolve = (resourceId) => fetch(`${base}/v1/authorizations/resolve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ role: "verifier", subjectDid: verifier.subjectDid, resourceId }),
  });
  const correct = await resolve(verifier.scopeResourceId);
  assert.equal(correct.status, 200);
  const wrong = await resolve(createVerifierScenarioFixture("isolated-other-verifier-scope").scopeResourceId);
  assert.equal(wrong.status, 404);
  const problem = await wrong.json();
  assert.equal(problem.type.slice(problem.type.lastIndexOf("/") + 1), "authorization-not-found");
});

test("issuer-active-api", async (context) => {
  const { harness, issuer, evaluate } = await startIssuerApi(context, "isolated-active-api");
  const bundle = harness.evaluateCurrentIssuerDecision(issuer);
  const decision = await evaluate(bundle.authorization.activeFrom);
  assert.equal(decision.trustedAtTime, true);
  assert.equal(decision.statusAtTime, "active");
});

test("issuer-suspended-api", async (context) => {
  const { harness, issuer, evaluate, transition } = await startIssuerApi(context, "isolated-suspended-api");
  const active = harness.evaluateCurrentIssuerDecision(issuer);
  assert.equal((await evaluate(active.authorization.activeFrom)).trustedAtTime, true);
  const suspended = transition("suspendIssuer");
  const decision = await evaluate(suspended.authorization.suspendedAt);
  assert.equal(decision.trustedAtTime, false);
  assert.equal(decision.statusAtTime, "suspended");
});

test("issuer-historical-api-after-suspension", async (context) => {
  const { harness, issuer, evaluate, transition } = await startIssuerApi(context, "isolated-suspension-history-api");
  const active = harness.evaluateCurrentIssuerDecision(issuer);
  transition("suspendIssuer");
  const decision = await evaluate(active.authorization.activeFrom);
  assert.equal(decision.trustedAtTime, true);
  assert.equal(decision.statusAtTime, "active");
});

test("issuer-revoked-api", async (context) => {
  const { harness, issuer, evaluate, transition } = await startIssuerApi(context, "isolated-revoked-api");
  const active = harness.evaluateCurrentIssuerDecision(issuer);
  assert.equal((await evaluate(active.authorization.activeFrom)).trustedAtTime, true);
  transition("suspendIssuer");
  const revoked = transition("revokeIssuer");
  const decision = await evaluate(revoked.authorization.revokedAt);
  assert.equal(decision.trustedAtTime, false);
  assert.equal(decision.statusAtTime, "revoked");
});

test("issuer-historical-api-after-revocation", async (context) => {
  const { harness, issuer, evaluate, transition } = await startIssuerApi(context, "isolated-revocation-history-api");
  const active = harness.evaluateCurrentIssuerDecision(issuer);
  transition("suspendIssuer");
  transition("revokeIssuer");
  const decision = await evaluate(active.authorization.activeFrom);
  assert.equal(decision.trustedAtTime, true);
  assert.equal(decision.statusAtTime, "active");
});
