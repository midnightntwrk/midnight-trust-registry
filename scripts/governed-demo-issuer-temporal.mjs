import assert from "node:assert/strict";
import { verifyGovernedIssuerStatusUpdate } from "./demo-vc-issuer-consumer.mjs";
import { createIssuerScenarioFixture } from "../packages/trust-registry-integration/dist/index.js";

export async function runIssuerTemporalLifecycle(adversarialMatrix, {
  base, harness, issuer, candidate, client, publishSnapshot, issuerVpFixture,
  vcAuthorityAnchor, vcAuthoritySeed, vcAuthorityKeyIdCommitment, vcConsumer,
  issuerBundle, activeAt, evaluateIssuerAt, queryTrqpIssuerAt, expectHttp,
}) {
  const candidateCoSignedProposal = harness.proposeIssuer(
    createIssuerScenarioFixture("governed-demo-candidate-proposal"), [candidate],
  );
  harness.suspendIssuer(issuer);
  publishSnapshot();
  const suspendedBundle = await expectHttp(await fetch(
    `${base}/v1/authorizations/issuer/${issuer.authorizationId}/evidence`,
  ), 200);
  assert.equal(suspendedBundle.authorization.status, "suspended");
  await expectHttp(await fetch(
    `${base}/v1/decision-evidence/issuer/${encodeURIComponent(issuer.authorizationId)}`,
  ), 503);
  const suspendedConsumer = await verifyGovernedIssuerStatusUpdate({
    harness, issuer, applicantVp: issuerVpFixture, authorityAnchor: vcAuthorityAnchor,
    authoritySeed: vcAuthoritySeed, authorityKeyIdCommitment: vcAuthorityKeyIdCommitment,
    apiBundle: suspendedBundle, state: "suspended", previousJourney: vcConsumer,
    apiBase: base,
  });
  adversarialMatrix.expectThrown(() => client.verifyIssuerAuthorizationBundle(suspendedBundle, {
    expectedRegistryId: harness.registryId,
  }), {
    id: "issuer-suspended",
    invariant: "Suspended issuer authorization cannot establish current trust",
    boundary: "client",
    messagePattern: /not active/iu,
    category: "inactive-authorization",
  });
  const suspendedEvaluation = await expectHttp(await evaluateIssuerAt(
    suspendedBundle.authorization.suspendedAt,
  ), 200);
  assert.equal(suspendedEvaluation.trustedAtTime, false);
  assert.equal(suspendedEvaluation.statusAtTime, "suspended");
  adversarialMatrix.expectDecision(suspendedEvaluation, {
    id: "issuer-suspended-api",
    invariant: "Public lookup denies issuer trust at suspension",
    boundary: "api", trusted: false, statusAtTime: "suspended",
  });
  adversarialMatrix.expectDecision(await expectHttp(await queryTrqpIssuerAt(
    suspendedBundle.authorization.suspendedAt,
  ), 200), {
    id: "issuer-suspended-trqp",
    invariant: "TRQP denies issuer trust at the same suspension instant",
    boundary: "adapter", trusted: suspendedEvaluation.trustedAtTime,
  });
  const historicalAfterSuspension = await expectHttp(await evaluateIssuerAt(activeAt), 200);
  assert.equal(historicalAfterSuspension.trustedAtTime, true);
  adversarialMatrix.expectDecision(historicalAfterSuspension, {
    id: "issuer-historical-api-after-suspension",
    invariant: "Public lookup retains active issuer trust before later suspension",
    boundary: "api", trusted: true, statusAtTime: "active",
  });
  adversarialMatrix.expectDecision(await expectHttp(await queryTrqpIssuerAt(activeAt), 200), {
    id: "issuer-historical-trqp-after-suspension",
    invariant: "TRQP agrees with the earlier active issuer decision after suspension",
    boundary: "adapter", trusted: historicalAfterSuspension.trustedAtTime,
  });
  adversarialMatrix.expectVerified(() => client.verifyIssuerAuthorizationBundle(issuerBundle, {
    expectedRegistryId: harness.registryId,
    evaluationTime: activeAt,
  }), {
    id: "issuer-historical-after-suspension",
    invariant: "A later suspension does not erase the issuer's earlier active authorization",
    boundary: "client",
  });
  harness.revokeIssuer(issuer);
  publishSnapshot();
  const revokedBundle = await expectHttp(await fetch(
    `${base}/v1/authorizations/issuer/${issuer.authorizationId}/evidence`,
  ), 200);
  assert.equal(revokedBundle.authorization.status, "revoked");
  await expectHttp(await fetch(
    `${base}/v1/decision-evidence/issuer/${encodeURIComponent(issuer.authorizationId)}`,
  ), 503);
  const revokedConsumer = await verifyGovernedIssuerStatusUpdate({
    harness, issuer, applicantVp: issuerVpFixture, authorityAnchor: vcAuthorityAnchor,
    authoritySeed: vcAuthoritySeed, authorityKeyIdCommitment: vcAuthorityKeyIdCommitment,
    apiBundle: revokedBundle, state: "revoked", previousJourney: suspendedConsumer,
    apiBase: base,
  });
  adversarialMatrix.expectThrown(() => client.verifyIssuerAuthorizationBundle(revokedBundle, {
    expectedRegistryId: harness.registryId,
  }), {
    id: "issuer-revoked",
    invariant: "Revoked issuer authorization cannot establish current trust",
    boundary: "client",
    messagePattern: /not active/iu,
    category: "inactive-authorization",
  });
  const revokedEvaluation = await expectHttp(await evaluateIssuerAt(
    revokedBundle.authorization.revokedAt,
  ), 200);
  assert.equal(revokedEvaluation.trustedAtTime, false);
  assert.equal(revokedEvaluation.statusAtTime, "revoked");
  adversarialMatrix.expectDecision(revokedEvaluation, {
    id: "issuer-revoked-api",
    invariant: "Public lookup denies issuer trust at revocation",
    boundary: "api", trusted: false, statusAtTime: "revoked",
  });
  adversarialMatrix.expectDecision(await expectHttp(await queryTrqpIssuerAt(
    revokedBundle.authorization.revokedAt,
  ), 200), {
    id: "issuer-revoked-trqp",
    invariant: "TRQP denies issuer trust at the same revocation instant",
    boundary: "adapter", trusted: revokedEvaluation.trustedAtTime,
  });
  const historicalAfterRevocation = await expectHttp(await evaluateIssuerAt(activeAt), 200);
  assert.equal(historicalAfterRevocation.trustedAtTime, true);
  adversarialMatrix.expectDecision(historicalAfterRevocation, {
    id: "issuer-historical-api-after-revocation",
    invariant: "Public lookup retains active issuer trust before later revocation",
    boundary: "api", trusted: true, statusAtTime: "active",
  });
  adversarialMatrix.expectDecision(await expectHttp(await queryTrqpIssuerAt(activeAt), 200), {
    id: "issuer-historical-trqp-after-revocation",
    invariant: "TRQP agrees with the earlier active issuer decision after revocation",
    boundary: "adapter", trusted: historicalAfterRevocation.trustedAtTime,
  });
  adversarialMatrix.expectVerified(() => client.verifyIssuerAuthorizationBundle(issuerBundle, {
    expectedRegistryId: harness.registryId,
    evaluationTime: activeAt,
  }), {
    id: "issuer-historical-after-revocation",
    invariant: "A later revocation does not erase the issuer's earlier active authorization",
    boundary: "client",
  });

  return {
    candidateCoSignedProposal, suspendedConsumer, revokedConsumer,
    suspendedEvaluation, revokedEvaluation, historicalAfterSuspension,
    historicalAfterRevocation, revokedBundle,
  };
}
