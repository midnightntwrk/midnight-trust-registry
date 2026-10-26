import assert from "node:assert/strict";
import { test } from "node:test";

import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  createAuditorScenarioFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";
import { createTrustRegistryApiServer } from "../packages/trust-registry-api/dist/index.js";

const roles = [
  {
    name: "verifier",
    fixture: createVerifierScenarioFixture,
    authorize: "authorizeVerifier",
    active: "evaluateCurrentVerifierDecision",
    historical: "buildVerifierHistoricalEvidence",
    suspend: "suspendVerifier",
    revoke: "revokeVerifier",
    verify: "verifyVerifierAuthorizationBundle",
    fixtureKey: "verifiers",
    trqpAction: "verify",
  },
  {
    name: "auditor",
    fixture: createAuditorScenarioFixture,
    authorize: "authorizeAuditor",
    active: "evaluateCurrentAuditorDecision",
    historical: "buildAuditorHistoricalEvidence",
    suspend: "suspendAuditor",
    revoke: "revokeAuditor",
    verify: "verifyAuditorAuthorizationBundle",
    fixtureKey: "auditors",
  },
];

const startTemporalCase = async (context, role, label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const fixture = role.fixture(`${label}-${role.name}`);
  harness[role.authorize](fixture);
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  const active = harness[role.active](fixture);
  const activeAt = active.authorization.activeFrom;
  assert.ok(client[role.verify](active, { expectedRegistryId: harness.registryId, evaluationTime: activeAt }));
  const fixtures = { label, [role.fixtureKey]: [{ fixture, label: role.name }] };
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
    if (response.status !== 200) {
      assert.fail(`Expected HTTP 200, received ${response.status}: ${await response.text()}`);
    }
    return response.json();
  };
  const evaluate = (at) => post("/v1/authorizations/evaluate", {
    role: role.name, subjectDid: fixture.subjectDid, resourceId: fixture.scopeResourceId, at,
  });
  const queryTrqp = role.trqpAction ? (at) => post("/v1/trqp/authorizations/query", {
    entity_id: fixture.subjectDid,
    authority_id: harness.registryDid,
    action: role.trqpAction,
    resource: fixture.scopeResourceId,
    context: { time: at },
  }) : undefined;
  const change = (action) => {
    harness[action](fixture);
    snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
    return harness[role.historical](fixture);
  };
  return { harness, fixture, client, active, activeAt, evaluate, queryTrqp, change };
};

for (const role of roles) {
  test(`${role.name}-active-api`, async (context) => {
    const { activeAt, evaluate } = await startTemporalCase(context, role, `isolated-${role.name}-active-api`);
    assert.equal((await evaluate(activeAt)).trustedAtTime, true);
  });

  test(`${role.name}-suspended-api`, async (context) => {
    const { activeAt, evaluate, change } = await startTemporalCase(context, role, `isolated-${role.name}-suspended-api`);
    assert.equal((await evaluate(activeAt)).trustedAtTime, true);
    const suspended = change(role.suspend);
    assert.equal(suspended.authorization.status, "suspended");
    assert.equal((await evaluate(suspended.authorization.suspendedAt)).trustedAtTime, false);
  });

  test(`${role.name}-historical-api-after-suspension`, async (context) => {
    const { activeAt, evaluate, change } = await startTemporalCase(context, role, `isolated-${role.name}-history-suspend-api`);
    change(role.suspend);
    assert.equal((await evaluate(activeAt)).trustedAtTime, true);
  });

  test(`${role.name}-historical-after-suspension`, async (context) => {
    const { harness, client, active, activeAt, change } =
      await startTemporalCase(context, role, `isolated-${role.name}-history-suspend-client`);
    const suspended = change(role.suspend);
    assert.throws(() => client[role.verify](suspended, { expectedRegistryId: harness.registryId }), /not active/iu);
    assert.ok(client[role.verify](active, { expectedRegistryId: harness.registryId, evaluationTime: activeAt }));
  });

  test(`${role.name}-revoked-api`, async (context) => {
    const { activeAt, evaluate, change } = await startTemporalCase(context, role, `isolated-${role.name}-revoked-api`);
    assert.equal((await evaluate(activeAt)).trustedAtTime, true);
    change(role.suspend);
    const revoked = change(role.revoke);
    assert.equal(revoked.authorization.status, "revoked");
    assert.equal((await evaluate(revoked.authorization.revokedAt)).trustedAtTime, false);
  });

  test(`${role.name}-historical-api-after-revocation`, async (context) => {
    const { activeAt, evaluate, change } = await startTemporalCase(context, role, `isolated-${role.name}-history-revoke-api`);
    change(role.suspend);
    change(role.revoke);
    assert.equal((await evaluate(activeAt)).trustedAtTime, true);
  });

  test(`${role.name}-historical-after-revocation`, async (context) => {
    const { harness, client, active, activeAt, change } =
      await startTemporalCase(context, role, `isolated-${role.name}-history-revoke-client`);
    change(role.suspend);
    const revoked = change(role.revoke);
    assert.throws(() => client[role.verify](revoked, { expectedRegistryId: harness.registryId }), /not active/iu);
    assert.ok(client[role.verify](active, { expectedRegistryId: harness.registryId, evaluationTime: activeAt }));
  });

  if (role.trqpAction) {
    test(`${role.name}-active-trqp`, async (context) => {
      const { activeAt, evaluate, queryTrqp } = await startTemporalCase(context, role, "isolated-verifier-active-trqp");
      assert.equal((await queryTrqp(activeAt)).authorized, (await evaluate(activeAt)).trustedAtTime);
    });

    for (const stage of [
      { name: "suspended", action: role.suspend, at: "suspendedAt" },
      { name: "revoked", action: role.revoke, at: "revokedAt" },
    ]) {
      test(`${role.name}-${stage.name}-trqp`, async (context) => {
        const { activeAt, evaluate, queryTrqp, change } =
          await startTemporalCase(context, role, `isolated-verifier-${stage.name}-trqp`);
        assert.equal((await queryTrqp(activeAt)).authorized, true);
        if (stage.name === "revoked") change(role.suspend);
        const changed = change(stage.action);
        const at = changed.authorization[stage.at];
        assert.equal((await queryTrqp(at)).authorized, (await evaluate(at)).trustedAtTime);
        assert.equal((await queryTrqp(at)).authorized, false);
      });

      test(`${role.name}-historical-after-${stage.name === "suspended" ? "suspension" : "revocation"}-trqp`, async (context) => {
        const { activeAt, evaluate, queryTrqp, change } =
          await startTemporalCase(context, role, `isolated-verifier-history-${stage.name}-trqp`);
        if (stage.name === "revoked") change(role.suspend);
        change(stage.action);
        assert.equal((await queryTrqp(activeAt)).authorized, (await evaluate(activeAt)).trustedAtTime);
        assert.equal((await queryTrqp(activeAt)).authorized, true);
      });
    }
  }
}
