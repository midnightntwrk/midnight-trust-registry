import assert from "node:assert/strict";

import {
  verifyGovernedIssuerCredential,
  verifyGovernedVerifierRequest,
} from "./demo-vc-issuer-consumer.mjs";
import { createVerifierAuthorizationScopeFixture } from "../packages/trust-registry-integration/dist/index.js";

export async function runGovernedConsumerEvidence(matrix, {
  base, client, harness, issuer, verifier, recognition, issuerVpFixture, verifierVpFixture,
  vcAuthorityAnchor, vcAuthoritySeed, vcAuthorityKeyIdCommitment,
  verifiedRecognition, publishDecisionEvidence, expectHttp, changeLastHexNibble,
}) {
  const issuerBundle = await expectHttp(await fetch(
    `${base}/v1/authorizations/issuer/${issuer.authorizationId}/evidence`,
  ), 200);
  client.verifyIssuerAuthorizationBundle(issuerBundle, {
    expectedRegistryId: harness.registryId,
    expectedSubjectDid: issuer.subjectDid,
    expectedResourceId: issuer.resourceId,
  });
  assert.ok(issuerVpFixture);
  const vcConsumer = await verifyGovernedIssuerCredential({
    harness, issuer, apiBundle: issuerBundle, applicantVp: issuerVpFixture,
    authorityAnchor: vcAuthorityAnchor, authoritySeed: vcAuthoritySeed,
    authorityKeyIdCommitment: vcAuthorityKeyIdCommitment, apiBase: base,
    publishDecisionEvidence,
  });
  const issuerDecision = await expectHttp(await fetch(
    `${base}/v1/decision-evidence/issuer/${encodeURIComponent(issuer.authorizationId)}`,
  ), 200);
  assert.equal(issuerDecision.verification, "client-required");
  assert.equal(issuerDecision.evidence.grant.authorizationId, issuer.authorizationId);
  await expectHttp(await fetch(
    `${base}/v1/decision-evidence/verifier/${encodeURIComponent(issuer.authorizationId)}`,
  ), 404);
  matrix.expectThrown(() => client.verifyIssuerAuthorizationBundle({
    ...issuerBundle,
    inclusionProof: {
      ...issuerBundle.inclusionProof,
      path: [changeLastHexNibble(issuerBundle.inclusionProof.path[0])],
    },
  }, { expectedRegistryId: harness.registryId }), {
    id: "issuer-tampered-merkle-path",
    invariant: "A changed Merkle sibling cannot verify against the anchored epoch",
    boundary: "client", messagePattern: /event sibling/iu,
    category: "tampered-merkle-path",
  });
  matrix.expectThrown(() => client.verifyIssuerAuthorizationBundle(issuerBundle, {
    expectedResourceId: "credential-family:unknown",
  }), {
    id: "issuer-wrong-credential-family",
    invariant: "Issuer authorization is bound to the exact credential family",
    boundary: "client", messagePattern: /issuer authorization resource mismatch/iu,
    category: "issuer-scope-mismatch",
  });
  const verifierBundle = await expectHttp(await fetch(
    `${base}/v1/authorizations/verifier/${verifier.authorizationId}/evidence`,
  ), 200);
  assert.ok(verifierVpFixture);
  const verifierConsumer = await verifyGovernedVerifierRequest({
    harness, verifier, scope: createVerifierAuthorizationScopeFixture(verifier),
    apiBundle: verifierBundle, applicantVp: verifierVpFixture,
    authorityAnchor: vcAuthorityAnchor, authoritySeed: vcAuthoritySeed,
    authorityKeyIdCommitment: vcAuthorityKeyIdCommitment, apiBase: base,
    publishDecisionEvidence,
  });
  const verifierDecision = await expectHttp(await fetch(
    `${base}/v1/decision-evidence/verifier/${encodeURIComponent(verifier.authorizationId)}`,
  ), 200);
  assert.equal(verifierDecision.verification, "client-required");
  assert.equal(verifierDecision.evidence.grant.authorizationId, verifier.authorizationId);
  matrix.expectThrown(() => client.verifyVerifierAuthorizationBundle(verifierBundle, {
    expectedResourceId: "request-profile:unknown",
  }), {
    id: "verifier-wrong-request-profile",
    invariant: "Verifier authorization is bound to the exact request profile",
    boundary: "client", messagePattern: /verifier authorization resource mismatch/iu,
    category: "verifier-scope-mismatch",
  });
  const recognitionBundle = await expectHttp(await fetch(
    `${base}/v1/recognitions/${recognition.recognitionId}/evidence`,
  ), 200);
  const locallyVerifiedRecognition = harness.evaluateCurrentRecognitionDecision(recognition);
  const trustedRecognitionEpoch = {
    epochId: locallyVerifiedRecognition.epoch.epochId,
    policyVersion: locallyVerifiedRecognition.policy.version,
  };
  assert.equal(recognitionBundle.epoch.epochId, trustedRecognitionEpoch.epochId);
  assert.equal(recognitionBundle.recognition.evidenceHash, verifiedRecognition.evidenceCommitment);
  matrix.expectThrown(() => client.verifyIssuerAuthorizationBundle(recognitionBundle, {}), {
    id: "recognition-not-issuer-authorization",
    invariant: "External registry recognition cannot authorize local VC issuance",
    boundary: "client", messagePattern: /does not contain issuer authorization/iu,
    category: "recognition-not-authorization",
  });
  return { issuerBundle, verifierBundle, recognitionBundle, vcConsumer, verifierConsumer,
    trustedRecognitionEpoch };
}
