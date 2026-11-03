import assert from "node:assert/strict";

import { createTrustRegistryApiServer } from "../packages/trust-registry-api/dist/index.js";

export async function runHistoricalPolicyHttpChecks(matrix, {
  originalPolicySnapshot, revisedPolicySnapshot, historicalIssuer, historicalVerifier,
  historicalAuditor, historicalRecognition, originalAuditorBundle,
  originalRecognitionBundle, registryDid,
}) {
  const server = createTrustRegistryApiServer({
    source: { mode: "memory", loadSnapshot: async () => revisedPolicySnapshot },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const base = `http://127.0.0.1:${address.port}`;
    const post = (path, body) => globalThis.fetch(`${base}${path}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    });
    const expectHttp = async (response, status) => {
      const payload = await response.json();
      assert.equal(response.status, status, JSON.stringify(payload));
      return payload;
    };

    const oldEvidence = originalPolicySnapshot.issuerEntries[0]?.evidence;
    assert.ok(oldEvidence?.authorization);
    const historicalIssuerEntry = revisedPolicySnapshot.issuerEntries.find((entry) =>
      entry.authorization.authorizationId === historicalIssuer.authorizationId);
    assert.equal(historicalIssuerEntry?.authorization.status, "revoked");
    assert.ok(revisedPolicySnapshot.evidenceArchive.some((bundle) =>
      bundle.authorization?.authorizationId === oldEvidence.authorization.authorizationId
        && bundle.epoch.epochId === oldEvidence.epoch.epochId));
    const historicalInstant = new Date(Date.parse(oldEvidence.epoch.validFrom) + 1).toISOString();
    assert.ok(Date.parse(historicalInstant) < Date.parse(historicalIssuerEntry.evidence.epoch.validFrom));
    const historicalDecision = await expectHttp(await post("/v1/authorizations/evaluate/evidence", {
      role: "issuer", subjectDid: historicalIssuer.subjectDid,
      resourceId: historicalIssuer.resourceId, at: historicalInstant,
    }), 200);
    assert.equal(historicalDecision.bundle.epoch.epochId, oldEvidence.epoch.epochId);
    assert.equal(historicalDecision.bundle.policy.version, oldEvidence.policy.version);
    assert.notEqual(historicalDecision.bundle.policy.version, revisedPolicySnapshot.policy.version);
    matrix.expectDecision(historicalDecision, {
      id: "issuer-historical-api-after-threshold-change",
      invariant: "A policy threshold revision retains the old issuer decision at its original epoch",
      boundary: "api", trusted: true, statusAtTime: "active",
    });
    const historicalTrqpDecision = await expectHttp(await post("/v1/trqp/authorizations/evidence", {
      entity_id: historicalIssuer.subjectDid,
      authority_id: revisedPolicySnapshot.registry.registryDid,
      action: "issue", resource: historicalIssuer.resourceId,
      context: { time: historicalInstant },
    }), 200);
    assert.equal(historicalTrqpDecision.bundle.epoch.epochId, oldEvidence.epoch.epochId);
    assert.equal(historicalTrqpDecision.bundle.policy.version, oldEvidence.policy.version);
    matrix.expectDecision(historicalTrqpDecision, {
      id: "issuer-historical-trqp-after-threshold-change",
      invariant: "TRQP retains the old issuer policy and epoch after a threshold revision",
      boundary: "adapter", trusted: historicalDecision.trustedAtTime,
    });

    const oldVerifierEvidence = originalPolicySnapshot.verifierEntries[0]?.evidence;
    assert.ok(oldVerifierEvidence?.authorization);
    assert.ok(revisedPolicySnapshot.evidenceArchive.some((bundle) =>
      bundle.authorization?.authorizationId === oldVerifierEvidence.authorization.authorizationId
        && bundle.epoch.epochId === oldVerifierEvidence.epoch.epochId));
    const historicalVerifierEntry = revisedPolicySnapshot.verifierEntries.find((entry) =>
      entry.authorization.authorizationId === historicalVerifier.authorizationId);
    assert.equal(historicalVerifierEntry?.authorization.status, "revoked");
    const verifierInstant = new Date(Date.parse(oldVerifierEvidence.epoch.validFrom) + 1).toISOString();
    assert.ok(Date.parse(verifierInstant) < Date.parse(historicalVerifierEntry.evidence.epoch.validFrom));
    const historicalVerifierDecision = await expectHttp(await post("/v1/authorizations/evaluate/evidence", {
      role: "verifier", subjectDid: historicalVerifier.subjectDid,
      resourceId: historicalVerifier.scopeResourceId, at: verifierInstant,
    }), 200);
    assert.equal(historicalVerifierDecision.bundle.epoch.epochId, oldVerifierEvidence.epoch.epochId);
    assert.equal(historicalVerifierDecision.bundle.policy.version, oldVerifierEvidence.policy.version);
    matrix.expectDecision(historicalVerifierDecision, {
      id: "verifier-historical-api-after-threshold-change",
      invariant: "A threshold revision and later revocation retain the verifier decision at its original epoch",
      boundary: "api", trusted: true, statusAtTime: "active",
    });
    const historicalVerifierTrqpDecision = await expectHttp(await post("/v1/trqp/authorizations/evidence", {
      entity_id: historicalVerifier.subjectDid,
      authority_id: revisedPolicySnapshot.registry.registryDid,
      action: "verify", resource: historicalVerifier.scopeResourceId,
      context: { time: verifierInstant },
    }), 200);
    assert.equal(historicalVerifierTrqpDecision.bundle.epoch.epochId, oldVerifierEvidence.epoch.epochId);
    assert.equal(historicalVerifierTrqpDecision.bundle.policy.version, oldVerifierEvidence.policy.version);
    matrix.expectDecision(historicalVerifierTrqpDecision, {
      id: "verifier-historical-trqp-after-threshold-change",
      invariant: "TRQP retains the old verifier policy and epoch after a threshold revision",
      boundary: "adapter", trusted: historicalVerifierDecision.trustedAtTime,
    });

    const auditorAt = new Date(Date.parse(originalAuditorBundle.epoch.validFrom) + 1).toISOString();
    const auditorDecision = await expectHttp(await post("/v1/authorizations/evaluate/evidence", {
      role: "auditor", subjectDid: historicalAuditor.subjectDid,
      resourceId: historicalAuditor.scopeResourceId, at: auditorAt,
    }), 200);
    assert.equal(auditorDecision.bundle.epoch.epochId, originalAuditorBundle.epoch.epochId);
    assert.equal(auditorDecision.bundle.policy.version, originalAuditorBundle.policy.version);
    assert.notEqual(auditorDecision.bundle.policy.version, revisedPolicySnapshot.policy.version);
    matrix.expectDecision(auditorDecision, {
      id: "auditor-historical-api-after-threshold-change",
      invariant: "The former auditor policy and epoch remain queryable after threshold revision and revocation",
      boundary: "api", trusted: true, statusAtTime: "active",
    });

    const recognitionAt = new Date(Date.parse(originalRecognitionBundle.epoch.validFrom) + 1).toISOString();
    const recognitionDecision = await expectHttp(await post("/v1/recognitions/evaluate/evidence", {
      recognizedAuthorityDid: historicalRecognition.recognizedAuthorityDid,
      recognizedRegistryId: historicalRecognition.recognizedRegistryId,
      scopeResourceType: historicalRecognition.scopeResourceType,
      scopeResourceId: historicalRecognition.scopeResourceId,
      at: recognitionAt,
    }), 200);
    assert.equal(recognitionDecision.bundle.epoch.epochId, originalRecognitionBundle.epoch.epochId);
    assert.equal(recognitionDecision.bundle.policy.version, originalRecognitionBundle.policy.version);
    assert.notEqual(recognitionDecision.bundle.policy.version, revisedPolicySnapshot.policy.version);
    matrix.expectDecision(recognitionDecision, {
      id: "recognition-historical-api-after-threshold-change",
      invariant: "The former recognition policy and epoch remain queryable after threshold revision and revocation",
      boundary: "api", trusted: true, statusAtTime: "active",
    });
    const recognitionTrqpDecision = await expectHttp(await post("/v1/trqp/recognitions/evidence", {
      entity_id: historicalRecognition.recognizedAuthorityDid,
      authority_id: registryDid,
      action: historicalRecognition.scopeResourceType,
      resource: historicalRecognition.scopeResourceId,
      context: { time: recognitionAt,
        recognized_registry_id: historicalRecognition.recognizedRegistryId },
    }), 200);
    assert.equal(recognitionTrqpDecision.bundle.epoch.epochId, originalRecognitionBundle.epoch.epochId);
    assert.equal(recognitionTrqpDecision.bundle.policy.version, originalRecognitionBundle.policy.version);
    matrix.expectDecision(recognitionTrqpDecision, {
      id: "recognition-historical-trqp-after-threshold-change",
      invariant: "TRQP retains the former recognition policy and epoch after threshold revision",
      boundary: "adapter", trusted: true, recognition: true,
    });
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}
