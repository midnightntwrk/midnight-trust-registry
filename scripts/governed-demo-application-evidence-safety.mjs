import assert from "node:assert/strict";

import { computeApplicationEvidenceCommitment } from "../packages/trust-registry-domain/dist/index.js";
import {
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";

/** Runs signed-evidence rejections against a ledger fixture independent of the main journey. */
export function runApplicationEvidenceSafetyScenarios(matrix) {
  const harness = new LocalTrustRegistryIntegrationHarness("governed-demo-evidence-boundaries");
  const policyIdIssuer = createIssuerScenarioFixture("governed-demo-wrong-policy-id");
  const expiringIssuer = createIssuerScenarioFixture("governed-demo-expired-evidence");
  const policyIdEvidence = harness.createApplicationEvidence({
    applicationId: policyIdIssuer.authorizationId,
    subjectDid: policyIdIssuer.subjectDid,
    role: "issuer",
    scope: createIssuerAuthorizationScopeFixture(policyIdIssuer),
    governedResource: { type: "credentialFamily", id: policyIdIssuer.resourceId },
  });
  const wrongPolicyEnvelope = { ...policyIdEvidence.envelope, policyId: "policy:wrong:v1" };
  const wrongPolicyCommitment = computeApplicationEvidenceCommitment(wrongPolicyEnvelope);
  const wrongPolicyEvidence = {
    envelope: wrongPolicyEnvelope,
    commitment: wrongPolicyCommitment,
    signature: harness.signApplicationEvidenceCommitment(wrongPolicyCommitment),
  };
  assert.equal(harness.verifyApplicationEvidenceSignature(
    wrongPolicyEvidence.commitment,
    wrongPolicyEvidence.signature,
    harness.evidenceVerifier,
  ), true);
  const actionsBeforeRejections = harness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => harness.proposeIssuerWithApplicationEvidence(
    policyIdIssuer, wrongPolicyEvidence,
  ), {
    id: "issuer-signed-wrong-policy-id",
    invariant: "Even validly signed applicant evidence cannot substitute another governance policy ID",
    boundary: "integration",
    messagePattern: /policyId does not match/iu,
    category: "policy-id-mismatch",
  });
  const expiringEvidence = harness.createApplicationEvidence({
    applicationId: expiringIssuer.authorizationId,
    subjectDid: expiringIssuer.subjectDid,
    role: "issuer",
    scope: createIssuerAuthorizationScopeFixture(expiringIssuer),
    governedResource: { type: "credentialFamily", id: expiringIssuer.resourceId },
  });
  harness.advanceEvidenceTimeBy(24 * 60 * 60 * 1000 + 1);
  matrix.expectThrown(() => harness.proposeIssuerWithApplicationEvidence(
    expiringIssuer, expiringEvidence,
  ), {
    id: "issuer-expired-signed-application-evidence",
    invariant: "A validly signed evidence receipt expires before a later governed transition",
    boundary: "integration",
    messagePattern: /evidence is expired/iu,
    category: "expired-application-evidence",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, actionsBeforeRejections);
}
