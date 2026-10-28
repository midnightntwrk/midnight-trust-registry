import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { verifyGovernedVerifierStatusUpdate } from "./demo-vc-issuer-consumer.mjs";
import {
  defaultSequenceToTimestamp,
  verifyHistoricalRecognitionEvidenceFromApi,
  verifyHistoricalRecognitionEvidenceResponse,
} from "../packages/trust-registry-client/dist/index.js";
import {
  createAuditorAuthorizationScopeFixture,
  createVerifierAuthorizationScopeFixture,
  resolveCompactHistoricalEpochAnchor,
} from "../packages/trust-registry-integration/dist/index.js";
import { verifyTrqpRecognitionEvidenceFromApi } from "../adapters/trqp/dist/index.js";

export async function runOtherTemporalLifecycles(adversarialMatrix, {
  base, harness, verifier, auditor, recognition, client, expectHttp,
  trustedRecognitionEpoch, verifierVpFixture, vcAuthorityAnchor,
  vcAuthoritySeed, vcAuthorityKeyIdCommitment, verifierConsumer, publishSnapshot,
}) {
  const temporalTargets = [
    {
      role: "verifier",
      path: `/v1/authorizations/verifier/${verifier.authorizationId}/evidence`,
      suspend: () => harness.suspendVerifier(verifier),
      revoke: () => harness.revokeVerifier(verifier),
      verify: (bundle, options) => client.verifyVerifierAuthorizationBundle(bundle, options),
      evaluationBody: (at) => ({
        role: "verifier", subjectDid: verifier.subjectDid, resourceId: verifier.scopeResourceId, at,
      }),
      trqpRequest: (at) => ({
        entity_id: verifier.subjectDid, authority_id: harness.registryDid,
        action: "verify", resource: verifier.scopeResourceId, context: { time: at },
      }),
    },
    {
      role: "auditor",
      path: `/v1/authorizations/auditor/${auditor.authorizationId}/evidence`,
      suspend: () => harness.suspendAuditor(auditor),
      revoke: () => harness.revokeAuditor(auditor),
      verify: (bundle, options) => client.verifyAuditorAuthorizationBundle(bundle, options),
      evaluationBody: (at) => ({
        role: "auditor", subjectDid: auditor.subjectDid, resourceId: auditor.scopeResourceId, at,
      }),
    },
    {
      role: "recognition",
      path: `/v1/recognitions/${recognition.recognitionId}/evidence`,
      suspend: () => harness.suspendRecognition(recognition),
      revoke: () => harness.revokeRecognition(recognition),
      verify: (bundle, options) => client.verifyRecognitionBundle(bundle, options),
      evaluationBody: (at) => ({
        recognizedAuthorityDid: recognition.recognizedAuthorityDid,
        recognizedRegistryId: recognition.recognizedRegistryId,
        scopeResourceType: recognition.scopeResourceType,
        scopeResourceId: recognition.scopeResourceId,
        at,
      }),
      trqpRequest: (at) => ({
        entity_id: recognition.recognizedAuthorityDid, authority_id: harness.registryDid,
        action: recognition.scopeResourceType, resource: recognition.scopeResourceId,
        context: { time: at, recognized_registry_id: recognition.recognizedRegistryId },
      }),
    },
  ];
  const temporalChecks = [];
  const verifierLifecycle = [];
  let verifierJourney = verifierConsumer;
  for (const target of temporalTargets) {
    const recognitionTarget = target.role === "recognition";
    const statusRecord = (bundle) => recognitionTarget ? bundle.recognition : bundle.authorization;
    const evaluateAt = (at) => fetch(`${base}/v1/${recognitionTarget ? "recognitions" : "authorizations"}/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(target.evaluationBody(at)),
    });
    const verifyNativeRecognitionAt = async (at) => {
      if (!recognitionTarget) return;
      const selection = target.evaluationBody(at);
      const response = await expectHttp(await fetch(`${base}/v1/recognitions/evaluate/evidence`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(selection),
      }), 200);
      const anchor = resolveCompactHistoricalEpochAnchor({
        ledger: harness.simulator.getLedger(), registryId: harness.registryId,
        expectedNetworkId: harness.registryDid.split(":")[2],
        contractAddress: Buffer.from(harness.simulator.contractAddress, "hex"),
        ...trustedRecognitionEpoch,
        sequenceToTimestamp: defaultSequenceToTimestamp,
      });
      const { epochRecord } = anchor;
      assert.equal(verifyHistoricalRecognitionEvidenceResponse(response, selection, anchor).trustedAtTime, true);
      assert.equal((await verifyHistoricalRecognitionEvidenceFromApi(base, selection, anchor)).trustedAtTime, true);
      const trqpRequest = target.trqpRequest(at);
      assert.equal((await verifyTrqpRecognitionEvidenceFromApi(
        base, trqpRequest, harness.registryDid, anchor,
      )).recognized, true);
      assert.throws(() => verifyHistoricalRecognitionEvidenceResponse(response, {
        ...selection, recognizedRegistryId: `${selection.recognizedRegistryId}:other`,
      }, anchor), /scope mismatch/iu);
      assert.throws(() => verifyHistoricalRecognitionEvidenceResponse(response, selection, {
        ...anchor, epochRecord: { ...epochRecord, stateRoot: new Uint8Array(32) },
      }), /state root mismatch/iu);
    };
    const queryTrqpAt = target.trqpRequest === undefined ? undefined : (at) => fetch(
      `${base}/v1/trqp/${recognitionTarget ? "recognitions" : "authorizations"}/query`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(target.trqpRequest(at)),
      },
    );
    const expectTrqpDecision = async (at, suffix, trusted) => {
      if (queryTrqpAt === undefined) return;
      adversarialMatrix.expectDecision(await expectHttp(await queryTrqpAt(at), 200), {
        id: `${target.role}-${suffix}-trqp`,
        invariant: `TRQP agrees with public ${target.role} trust at ${suffix.replaceAll("-", " ")}`,
        boundary: "adapter", trusted, recognition: recognitionTarget,
      });
    };
    const activeBundle = await expectHttp(await fetch(`${base}${target.path}`), 200);
    const roleActiveAt = recognitionTarget
      ? activeBundle.recognition.effectiveFrom : activeBundle.authorization.activeFrom;
    target.verify(activeBundle, { expectedRegistryId: harness.registryId, evaluationTime: roleActiveAt });
    const active = await expectHttp(await evaluateAt(roleActiveAt), 200);
    assert.equal(active.trustedAtTime, true, `${target.role} must be trusted at activation`);
    adversarialMatrix.expectDecision(active, {
      id: `${target.role}-active-api`,
      invariant: `Public lookup trusts ${target.role} at its activation instant`,
      boundary: "api", trusted: true,
    });
    await expectTrqpDecision(roleActiveAt, "active", active.trustedAtTime);

    target.suspend();
    publishSnapshot();
    const suspendedBundle = await expectHttp(await fetch(`${base}${target.path}`), 200);
    assert.equal(statusRecord(suspendedBundle).status, "suspended");
    if (target.role === "auditor") {
      assert.throws(() => client.verifyAuditorRequestMandate(
        suspendedBundle, createAuditorAuthorizationScopeFixture(auditor),
        {
          expectedRegistryId: harness.registryId,
          expectedSubjectDid: auditor.subjectDid,
          evaluationTime: suspendedBundle.generatedAt,
        },
      ), /not active/u);
    }
    if (target.role === "verifier") {
      await expectHttp(await fetch(
        `${base}/v1/decision-evidence/verifier/${encodeURIComponent(verifier.authorizationId)}`,
      ), 503);
      verifierJourney = await verifyGovernedVerifierStatusUpdate({
        harness, verifier, scope: createVerifierAuthorizationScopeFixture(verifier),
        applicantVp: verifierVpFixture, authorityAnchor: vcAuthorityAnchor,
        authoritySeed: vcAuthoritySeed, authorityKeyIdCommitment: vcAuthorityKeyIdCommitment,
        apiBundle: suspendedBundle, state: "suspended", previousJourney: verifierJourney,
        apiBase: base,
      });
      verifierLifecycle.push(verifierJourney.report);
    }
    assert.throws(() => target.verify(suspendedBundle, {
      expectedRegistryId: harness.registryId,
    }), /not active/i);
    const suspended = await expectHttp(await evaluateAt(statusRecord(suspendedBundle).suspendedAt), 200);
    assert.equal(suspended.trustedAtTime, false, `${target.role} must be denied while suspended`);
    adversarialMatrix.expectDecision(suspended, {
      id: `${target.role}-suspended-api`,
      invariant: `Public lookup denies ${target.role} at suspension`,
      boundary: "api", trusted: false,
    });
    await expectTrqpDecision(statusRecord(suspendedBundle).suspendedAt, "suspended", suspended.trustedAtTime);
    const historicalAfterSuspension = await expectHttp(await evaluateAt(roleActiveAt), 200);
    assert.equal(historicalAfterSuspension.trustedAtTime, true);
    adversarialMatrix.expectDecision(historicalAfterSuspension, {
      id: `${target.role}-historical-api-after-suspension`,
      invariant: `Public lookup retains earlier ${target.role} trust after suspension`,
      boundary: "api", trusted: true,
    });
    await expectTrqpDecision(roleActiveAt, "historical-after-suspension", historicalAfterSuspension.trustedAtTime);
    await verifyNativeRecognitionAt(roleActiveAt);
    adversarialMatrix.expectVerified(() => target.verify(activeBundle, {
      expectedRegistryId: harness.registryId,
      evaluationTime: roleActiveAt,
    }), {
      id: `${target.role}-historical-after-suspension`,
      invariant: `A later suspension does not erase ${target.role} trust at its active instant`,
      boundary: "client",
    });

    target.revoke();
    publishSnapshot();
    const revokedBundle = await expectHttp(await fetch(`${base}${target.path}`), 200);
    assert.equal(statusRecord(revokedBundle).status, "revoked");
    if (target.role === "auditor") {
      assert.throws(() => client.verifyAuditorRequestMandate(
        revokedBundle, createAuditorAuthorizationScopeFixture(auditor),
        {
          expectedRegistryId: harness.registryId,
          expectedSubjectDid: auditor.subjectDid,
          evaluationTime: revokedBundle.generatedAt,
        },
      ), /not active/u);
    }
    if (target.role === "verifier") {
      await expectHttp(await fetch(
        `${base}/v1/decision-evidence/verifier/${encodeURIComponent(verifier.authorizationId)}`,
      ), 503);
      verifierJourney = await verifyGovernedVerifierStatusUpdate({
        harness, verifier, scope: createVerifierAuthorizationScopeFixture(verifier),
        applicantVp: verifierVpFixture, authorityAnchor: vcAuthorityAnchor,
        authoritySeed: vcAuthoritySeed, authorityKeyIdCommitment: vcAuthorityKeyIdCommitment,
        apiBundle: revokedBundle, state: "revoked", previousJourney: verifierJourney,
        apiBase: base,
      });
      verifierLifecycle.push(verifierJourney.report);
    }
    assert.throws(() => target.verify(revokedBundle, {
      expectedRegistryId: harness.registryId,
    }), /not active/i);
    const revoked = await expectHttp(await evaluateAt(statusRecord(revokedBundle).revokedAt), 200);
    assert.equal(revoked.trustedAtTime, false, `${target.role} must be denied after revocation`);
    adversarialMatrix.expectDecision(revoked, {
      id: `${target.role}-revoked-api`,
      invariant: `Public lookup denies ${target.role} at revocation`,
      boundary: "api", trusted: false,
    });
    await expectTrqpDecision(statusRecord(revokedBundle).revokedAt, "revoked", revoked.trustedAtTime);
    const historicalAfterRevocation = await expectHttp(await evaluateAt(roleActiveAt), 200);
    assert.equal(historicalAfterRevocation.trustedAtTime, true);
    adversarialMatrix.expectDecision(historicalAfterRevocation, {
      id: `${target.role}-historical-api-after-revocation`,
      invariant: `Public lookup retains earlier ${target.role} trust after revocation`,
      boundary: "api", trusted: true,
    });
    await expectTrqpDecision(roleActiveAt, "historical-after-revocation", historicalAfterRevocation.trustedAtTime);
    await verifyNativeRecognitionAt(roleActiveAt);
    adversarialMatrix.expectVerified(() => target.verify(activeBundle, {
      expectedRegistryId: harness.registryId,
      evaluationTime: roleActiveAt,
    }), {
      id: `${target.role}-historical-after-revocation`,
      invariant: `A later revocation does not erase ${target.role} trust at its active instant`,
      boundary: "client",
    });
    temporalChecks.push({
      role: target.role,
      activeAt: roleActiveAt,
      activeAfterSuspension: historicalAfterSuspension.trustedAtTime,
      activeAfterRevocation: historicalAfterRevocation.trustedAtTime,
      suspendedAtSuspension: suspended.trustedAtTime,
      revokedAtRevocation: revoked.trustedAtTime,
    });
  }

  return { temporalChecks, verifierLifecycle };
}
