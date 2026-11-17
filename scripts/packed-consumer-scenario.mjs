import assert from "node:assert/strict";

import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";
import {
  LocalTrustRegistryIntegrationHarness,
  createIssuerScenarioFixture,
  createVerifierScenarioFixture,
} from "@midnight-ntwrk/trust-registry-integration";

const harness = new LocalTrustRegistryIntegrationHarness("packed-consumer");
const client = new TrustRegistrySimulatorClient(harness.simulator);

const issuer = createIssuerScenarioFixture("packed-consumer-issuer");
await harness.authorizeIssuer(issuer);
const issuerEvidence = await harness.evaluateCurrentIssuerDecision(issuer, {
  expectedRegistryId: harness.registryId,
});
assert.equal(issuerEvidence.authorization?.status, "active");
assert.equal(issuerEvidence.authorization?.authorizationId, issuer.authorizationId);
assert.equal(
  (await client.verifyIssuerAuthorizationBundle(issuerEvidence, {
    expectedResourceId: issuer.resourceId,
  })).authorization?.authorizationId,
  issuer.authorizationId,
);
await assert.rejects(
  () => client.verifyIssuerAuthorizationBundle(issuerEvidence, {
    expectedResourceId: "schema:unrelated",
  }),
  /resource mismatch/i,
);

const verifier = createVerifierScenarioFixture("packed-consumer-verifier");
await harness.authorizeVerifier(verifier);
const verifierEvidence = await harness.evaluateCurrentVerifierDecision(verifier, {
  expectedRegistryId: harness.registryId,
});
assert.equal(verifierEvidence.authorization?.status, "active");
assert.equal(verifierEvidence.authorization?.authorizationId, verifier.authorizationId);
assert.equal(
  (await client.verifyVerifierAuthorizationBundle(verifierEvidence, {
    expectedResourceId: verifier.scopeResourceId,
  })).authorization?.authorizationId,
  verifier.authorizationId,
);

console.log("[smoke-packed-artifacts] Packed issuer and verifier evidence verified by public packages.");
