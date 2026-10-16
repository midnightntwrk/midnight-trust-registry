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
harness.authorizeIssuer(issuer);
const issuerEvidence = harness.evaluateCurrentIssuerDecision(issuer, {
  expectedRegistryId: harness.registryId,
});
assert.equal(issuerEvidence.authorization?.status, "active");
assert.equal(issuerEvidence.authorization?.authorizationId, issuer.authorizationId);
assert.equal(
  client.verifyIssuerAuthorizationBundle(issuerEvidence, {
    expectedResourceId: issuer.resourceId,
  }).authorization?.authorizationId,
  issuer.authorizationId,
);
assert.throws(
  () => client.verifyIssuerAuthorizationBundle(issuerEvidence, {
    expectedResourceId: "schema:unrelated",
  }),
  /resource mismatch/i,
);

const verifier = createVerifierScenarioFixture("packed-consumer-verifier");
harness.authorizeVerifier(verifier);
const verifierEvidence = harness.evaluateCurrentVerifierDecision(verifier, {
  expectedRegistryId: harness.registryId,
});
assert.equal(verifierEvidence.authorization?.status, "active");
assert.equal(verifierEvidence.authorization?.authorizationId, verifier.authorizationId);
assert.equal(
  client.verifyVerifierAuthorizationBundle(verifierEvidence, {
    expectedResourceId: verifier.scopeResourceId,
  }).authorization?.authorizationId,
  verifier.authorizationId,
);

console.log("[smoke-packed-artifacts] Packed issuer and verifier evidence verified by public packages.");
