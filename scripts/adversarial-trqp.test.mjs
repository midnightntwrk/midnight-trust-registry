import assert from "node:assert/strict";
import { test } from "node:test";

import { TrustRegistryTrqpAdapter } from "../adapters/trqp/dist/index.js";
import {
  createIssuerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";

const activeIssuerAdapter = (label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const issuer = createIssuerScenarioFixture(`${label}-issuer`);
  harness.authorizeIssuer(issuer);
  const activeAt = harness.evaluateCurrentIssuerDecision(issuer).authorization.activeFrom;
  const request = {
    entity_id: issuer.subjectDid,
    authority_id: harness.registryRecord.registryDid,
    action: "issue",
    resource: issuer.resourceId,
    context: { time: activeAt },
  };
  const ports = {
    getRegistryRecord: async (authorityId) => authorityId === harness.registryRecord.registryDid
      ? harness.registryRecord : null,
    getAuthorizationDecision: async (candidate) => candidate.resource === issuer.resourceId
      ? { statusAtTime: "active", trustedAtTime: true } : null,
    getRecognitionDecision: async () => null,
  };
  return { harness, issuer, request, ports, activeAt };
};

const assertProblem = (result, status, slug) => {
  assert.equal(result.ok, false);
  assert.equal(result.problem.status, status);
  assert.equal(result.problem.type.slice(result.problem.type.lastIndexOf("/") + 1), slug);
};

test("trqp-unknown-issuer-scope", async () => {
  const { request, ports, activeAt } = activeIssuerAdapter("isolated-trqp-unknown");
  const adapter = new TrustRegistryTrqpAdapter(ports, { clock: () => activeAt });
  const valid = await adapter.queryAuthorization(request);
  assert.equal(valid.ok, true);
  assert.equal(valid.value.authorized, true);
  assertProblem(await adapter.queryAuthorization({
    ...request, resource: "credential-family:unknown",
  }), 404, "not-found");
});

test("trqp-missing-epoch-evidence", async () => {
  const { request, ports, activeAt } = activeIssuerAdapter("isolated-trqp-missing-evidence");
  const adapter = new TrustRegistryTrqpAdapter(ports, { clock: () => activeAt });
  assert.equal((await adapter.queryAuthorization(request)).ok, true);
  assertProblem(await adapter.getAuthorizationEvidence(request), 424, "epoch-evidence-unavailable");
});

test("trqp-contradictory-source", async () => {
  const { harness, request, ports, activeAt } = activeIssuerAdapter("isolated-trqp-contradiction");
  const valid = new TrustRegistryTrqpAdapter(ports, { clock: () => activeAt });
  assert.equal((await valid.queryAuthorization(request)).ok, true);
  const inconsistent = new TrustRegistryTrqpAdapter({
    getRegistryRecord: async () => harness.registryRecord,
    getAuthorizationDecision: async () => ({ statusAtTime: "suspended", trustedAtTime: true }),
    getRecognitionDecision: async () => null,
  }, { clock: () => activeAt });
  assertProblem(await inconsistent.queryAuthorization(request), 500, "invalid-source-data");
});
