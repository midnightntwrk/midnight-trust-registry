import assert from "node:assert/strict";
import { Buffer } from "node:buffer";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signPolicyBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  ApplicationChallengeBindingSchema,
  computeAuthorizationScopeCommitment,
  createScopedIdentifier,
} from "../packages/trust-registry-domain/dist/index.js";
import {
  createApplicationVpIntakePorts,
  createApplicationVpScenarioFixture,
  createAuditorAuthorizationScopeFixture,
  createAuditorScenarioFixture,
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createMaintainerAuthorizationScopeFixture,
  createMaintainerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierAuthorizationScopeFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  VP_FIXTURE_TIME_MS,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  ApplicationChallengeService,
  InMemoryApplicationChallengeStore,
  consumeChallengeAndSubmitApplication,
  createTrustRegistryApiServer,
  GovernedAuditorProposalRejectedError,
  GovernedIssuerProposalRejectedError,
  GovernedMaintainerProposalRejectedError,
  GovernedMembershipActionRejectedError,
  GovernedVerifierProposalRejectedError,
} from "../packages/trust-registry-api/dist/index.js";

const asHex = (value) => `0x${Buffer.from(value).toString("hex")}`;
const fromHex = (value) => Buffer.from(value.slice(2), "hex");
const sign = (maintainer, prepared) => {
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const signature = signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    fromHex(prepared.registryId),
    fromHex(prepared.policyCommitment),
    fromHex(prepared.actionKind),
    fromHex(prepared.actionPayloadHash),
    BigInt(prepared.actionSequence),
  );
  return {
    keyId: asHex(maintainer.keyId),
    publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
    signature: asHex(encodeJubjubSignature(signature)),
  };
};

const expectHttp = async (response, status) => {
  const payload = await response.json();
  assert.equal(response.status, status, JSON.stringify(payload));
  return payload;
};

const harness = new LocalTrustRegistryIntegrationHarness("governed-registry-demo");
const second = createMaintainerScenarioFixture("governed-demo-second");
const third = createMaintainerScenarioFixture("governed-demo-third");
const candidate = createMaintainerScenarioFixture("governed-demo-candidate");
const issuer = createIssuerScenarioFixture("governed-demo-issuer");
const verifier = createVerifierScenarioFixture("governed-demo-verifier");
const auditor = createAuditorScenarioFixture("governed-demo-auditor");
const recognition = createRecognitionScenarioFixture("governed-demo-recognition");
harness.authorizeMaintainer(second);
harness.authorizeMaintainer(third);
harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
harness.advanceEvidenceTimeBy(60_000);

// Recognition still uses a fixture assertion; the four membership proposals cross HTTP below.
harness.proposeRecognition(recognition);
const challengeService = new ApplicationChallengeService(
  new InMemoryApplicationChallengeStore(), () => VP_FIXTURE_TIME_MS,
);
const verifiedApplicationEvidence = async ({ role, id, subjectDid, scope, governedResource }) => {
  const binding = ApplicationChallengeBindingSchema.parse({
    registryId: harness.registryId,
    applicationId: createScopedIdentifier("application", role, id),
    subjectDid,
    evidenceVerifierDid: harness.evidenceVerifier.did,
    role,
    policyId: harness.policyId,
    policyVersion: harness.policyRecord.version,
    scope,
    scopeCommitment: computeAuthorizationScopeCommitment(scope),
    governedResource,
  });
  const challenge = await challengeService.issue(binding);
  const proof = await createApplicationVpScenarioFixture(challenge.nonce, {
    subjectDid,
    evidenceVerifierDid: harness.evidenceVerifier.did,
    evidenceVerifierMethodId: harness.evidenceVerifier.keyIds[0].split("#")[1],
    scope,
  });
  const vpPorts = await createApplicationVpIntakePorts({
    resolver: proof.input.resolver,
    family: proof.input.family,
    signer: proof.signer,
  });
  const intake = {
    challengeService,
    binding,
    expectedBinding: binding,
    nonce: challenge.nonce,
    challengeHash: challenge.challengeHash,
    presentation: proof.input.submission,
    ...vpPorts,
    authorizedVerifiers: [harness.evidenceVerifier],
    evaluatedAt: new Date(VP_FIXTURE_TIME_MS).toISOString(),
    propose: async ({ evidence: submitted }) => submitted,
  };
  const evidence = await consumeChallengeAndSubmitApplication(intake);
  assert.equal(await challengeService.isLive({
    binding, nonce: challenge.nonce, challengeHash: challenge.challengeHash,
  }), false);
  await assert.rejects(consumeChallengeAndSubmitApplication(intake), /already consumed/);
  assert.equal(JSON.stringify(evidence).includes(proof.input.submission.rawCredentialBody), false);
  assert.equal(JSON.stringify(evidence).includes(proof.input.submission.rawPresentationBody), false);
  return { evidence, expected: { scope, challengeHash: challenge.challengeHash, governedResource } };
};
const issuerScope = createIssuerAuthorizationScopeFixture(issuer);
const { evidence: issuerEvidence, expected: expectedIssuerEvidence } = await verifiedApplicationEvidence({
  role: "issuer",
  id: issuer.authorizationId,
  subjectDid: issuer.subjectDid,
  scope: issuerScope,
  governedResource: { type: "credentialFamily", id: issuer.resourceId },
});
const { evidence: verifierEvidence, expected: expectedVerifierEvidence } = await verifiedApplicationEvidence({
  role: "verifier",
  id: verifier.authorizationId,
  subjectDid: verifier.subjectDid,
  scope: createVerifierAuthorizationScopeFixture(verifier),
  governedResource: { type: "requestProfile", id: verifier.scopeResourceId },
});
const { evidence: auditorEvidence, expected: expectedAuditorEvidence } = await verifiedApplicationEvidence({
  role: "auditor",
  id: auditor.authorizationId,
  subjectDid: auditor.subjectDid,
  scope: createAuditorAuthorizationScopeFixture(auditor),
  governedResource: { type: "requestProfile", id: auditor.scopeResourceId },
});
const { evidence: candidateEvidence, expected: expectedMaintainerEvidence } = await verifiedApplicationEvidence({
  role: "maintainer",
  id: candidate.maintainerId,
  subjectDid: candidate.subjectDid,
  scope: createMaintainerAuthorizationScopeFixture(harness.registryId),
  governedResource: { type: "registry", id: harness.registryId },
});

const fixtures = {
  label: "governed-registry-demo",
  issuers: [{ label: "issuer", fixture: issuer }],
  verifiers: [{ label: "verifier", fixture: verifier }],
  auditors: [{ label: "auditor", fixture: auditor }],
  recognitions: [{ label: "recognition", fixture: recognition }],
};
const projectedRoles = new Set();
let snapshot = publishSimulatorSnapshot(harness, {
  label: fixtures.label,
  recognitions: fixtures.recognitions,
});
const publishCurrentSnapshot = () => {
  snapshot = publishSimulatorSnapshot(harness, {
    label: fixtures.label,
    issuers: projectedRoles.has("issuer") ? fixtures.issuers : [],
    verifiers: projectedRoles.has("verifier") ? fixtures.verifiers : [],
    auditors: projectedRoles.has("auditor") ? fixtures.auditors : [],
    recognitions: fixtures.recognitions,
  }, snapshot);
};
const targets = new Map([
  ["issuer", {
    id: issuer.authorizationId,
    prepare: (action) => harness.prepareIssuerDecisionAction(issuer, action),
    execute: (action, signers) => harness.executeIssuerDecisionWithSignatures(issuer, action, signers),
  }],
  ["verifier", {
    id: verifier.authorizationId,
    prepare: (action) => harness.prepareVerifierDecisionAction(verifier, action),
    execute: (action, signers) => harness.executeVerifierDecisionWithSignatures(verifier, action, signers),
  }],
  ["auditor", {
    id: auditor.authorizationId,
    prepare: (action) => harness.prepareAuditorDecisionAction(auditor, action),
    execute: (action, signers) => harness.executeAuditorDecisionWithSignatures(auditor, action, signers),
  }],
  ["maintainer", {
    id: candidate.maintainerId,
    prepare: (action) => {
      const prepared = harness.prepareMaintainerDecisionAction(candidate, action);
      return { ...prepared, authorizationId: prepared.maintainerId };
    },
    execute: (action, signers) => harness.executeMaintainerDecisionWithSignatures(candidate, action, signers),
  }],
  ["recognition", {
    id: recognition.recognitionId,
    prepare: (action) => {
      const prepared = harness.prepareRecognitionDecisionAction(recognition, action);
      return { ...prepared, authorizationId: prepared.recognitionId };
    },
    execute: (action, signers) => harness.executeRecognitionDecisionWithSignatures(recognition, action, signers),
  }],
]);
const findTarget = (role, id) => {
  const target = targets.get(role);
  if (target === undefined || target.id !== id) {
    throw new GovernedMembershipActionRejectedError("unknown-authorization");
  }
  return target;
};
const proposalTargets = new Map([
  ["verifier", {
    id: verifier.authorizationId,
    evidence: verifierEvidence,
    prepare: (evidence) => harness.prepareVerifierProposalAction(verifier, evidence, expectedVerifierEvidence),
    execute: (evidence, signers, signature) =>
      harness.executeVerifierProposalWithSignatures(
        verifier, evidence, signers, signature, expectedVerifierEvidence,
      ),
    signEvidence: (prepared) => harness.signVerifierProposalEvidence(prepared),
    rejected: GovernedVerifierProposalRejectedError,
    missing: "unknown-authorization",
  }],
  ["auditor", {
    id: auditor.authorizationId,
    evidence: auditorEvidence,
    prepare: (evidence) => harness.prepareAuditorProposalAction(auditor, evidence, expectedAuditorEvidence),
    execute: (evidence, signers, signature) =>
      harness.executeAuditorProposalWithSignatures(
        auditor, evidence, signers, signature, expectedAuditorEvidence,
      ),
    signEvidence: (prepared) => harness.signAuditorProposalEvidence(prepared),
    rejected: GovernedAuditorProposalRejectedError,
    missing: "unknown-authorization",
  }],
  ["maintainer", {
    id: candidate.maintainerId,
    evidence: candidateEvidence,
    prepare: (evidence) => harness.prepareMaintainerProposalAction(candidate, evidence, expectedMaintainerEvidence),
    execute: (evidence, signers, signature) =>
      harness.executeMaintainerProposalWithSignatures(
        candidate, evidence, signers, signature, expectedMaintainerEvidence,
      ),
    signEvidence: (prepared) => harness.signMaintainerProposalEvidence(prepared),
    rejected: GovernedMaintainerProposalRejectedError,
    missing: "unknown-maintainer",
  }],
]);
const proposalPort = (role, target) => ({
  async prepare(id, evidence) {
    if (id !== target.id) throw new target.rejected(target.missing);
    try {
      return target.prepare(evidence);
    } catch {
      throw new target.rejected("invalid-evidence");
    }
  },
  async execute(id, evidence, signers, verifierSignature) {
    if (id !== target.id) throw new target.rejected(target.missing);
    let eventHash;
    try {
      eventHash = target.execute(evidence, signers, verifierSignature);
    } catch {
      throw new target.rejected("invalid-signers");
    }
    projectedRoles.add(role);
    publishCurrentSnapshot();
    return { eventHash: asHex(eventHash) };
  },
});
const server = createTrustRegistryApiServer({
  source: { mode: "memory", loadSnapshot: async () => snapshot },
  governedIssuerProposals: {
    async prepare(authorizationId, evidence) {
      if (authorizationId !== issuer.authorizationId) {
        throw new GovernedIssuerProposalRejectedError("unknown-authorization");
      }
      try {
        return harness.prepareIssuerProposalAction(issuer, evidence, expectedIssuerEvidence);
      } catch {
        throw new GovernedIssuerProposalRejectedError("invalid-evidence");
      }
    },
    async execute(authorizationId, evidence, signers, verifierSignature) {
      if (authorizationId !== issuer.authorizationId) {
        throw new GovernedIssuerProposalRejectedError("unknown-authorization");
      }
      let eventHash;
      try {
        eventHash = harness.executeIssuerProposalWithSignatures(
          issuer, evidence, signers, verifierSignature, expectedIssuerEvidence,
        );
      } catch {
        throw new GovernedIssuerProposalRejectedError("invalid-signers");
      }
      projectedRoles.add("issuer");
      publishCurrentSnapshot();
      return { eventHash: asHex(eventHash) };
    },
  },
  governedVerifierProposals: proposalPort("verifier", proposalTargets.get("verifier")),
  governedAuditorProposals: proposalPort("auditor", proposalTargets.get("auditor")),
  governedMaintainerProposals: proposalPort("maintainer", proposalTargets.get("maintainer")),
  governedMembershipActions: {
    async prepare(role, authorizationId, action) {
      return findTarget(role, authorizationId).prepare(action);
    },
    async execute(role, authorizationId, action, signers) {
      const target = findTarget(role, authorizationId);
      let eventHash;
      try {
        eventHash = target.execute(action, signers);
      } catch {
        throw new GovernedMembershipActionRejectedError("invalid-signers");
      }
      snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
      return { eventHash: asHex(eventHash) };
    },
  },
});

try {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address unavailable");
  const base = `http://127.0.0.1:${address.port}`;
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  const proposalEndpoint = `${base}/v1/governed/issuer/${issuer.authorizationId}/proposal`;
  const proposalPrepared = await expectHttp(await fetch(`${proposalEndpoint}/prepare`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ evidence: issuerEvidence }),
  }), 200);
  const verifierSignature = harness.signIssuerProposalEvidence(
    harness.prepareIssuerProposalAction(issuer, issuerEvidence, expectedIssuerEvidence),
  );
  const proposalBody = {
    evidence: issuerEvidence,
    prepared: proposalPrepared,
    signers: [sign(second, proposalPrepared), sign(third, proposalPrepared)],
    evidenceVerifierSignature: asHex(encodeJubjubSignature(verifierSignature)),
  };
  const submitProposal = (body) => fetch(`${proposalEndpoint}/submit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  await expectHttp(await submitProposal({ ...proposalBody, signers: proposalBody.signers.slice(0, 1) }), 403);
  const issuerProposal = await expectHttp(await submitProposal(proposalBody), 202);
  await expectHttp(await submitProposal(proposalBody), 409);
  assert.equal(harness.simulator.getLedger().issuerAuthorizationCount, 1n);
  const otherProposals = [];
  for (const [role, target] of proposalTargets) {
    const endpoint = `${base}/v1/governed/${role}/${target.id}/proposal`;
    const prepared = await expectHttp(await fetch(`${endpoint}/prepare`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ evidence: target.evidence }),
    }), 200);
    const signature = target.signEvidence(target.prepare(target.evidence));
    const body = {
      evidence: target.evidence,
      prepared,
      signers: [sign(second, prepared), sign(third, prepared)],
      evidenceVerifierSignature: asHex(encodeJubjubSignature(signature)),
    };
    const submit = (payload) => fetch(`${endpoint}/submit`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
    });
    await expectHttp(await submit({ ...body, signers: body.signers.slice(0, 1) }), 403);
    const accepted = await expectHttp(await submit(body), 202);
    await expectHttp(await submit(body), 409);
    otherProposals.push({
      role,
      eventHash: accepted.eventHash,
      evidenceCommitment: target.evidence.commitment,
      source: "published VC/VP fixture and one-use challenge via HTTP proposal",
    });
  }
  const decisions = [];
  for (const [role, target] of targets) {
    const events = {};
    for (const action of ["approve", "activate"]) {
      const endpoint = `${base}/v1/governed/${role}/${target.id}/actions/${action}`;
      const prepared = await expectHttp(await fetch(endpoint), 200);
      const submit = (preparedAction, signers) => fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ prepared: preparedAction, signers }),
      });
      const signers = [sign(second, prepared), sign(third, prepared)];
      await expectHttp(await submit(prepared, signers.slice(0, 1)), 403);
      if (role === "maintainer") {
        await expectHttp(await submit(prepared, [signers[0], sign(candidate, prepared)]), 403);
      }
      const accepted = await expectHttp(await submit(prepared, signers), 202);
      await expectHttp(await submit(prepared, signers), 409);
      events[action] = accepted.eventHash;
    }
    decisions.push({ role, id: target.id, events });
  }

  for (const [role, target] of targets) {
    if (role === "maintainer") continue;
    const evidencePath = role === "recognition"
      ? `/v1/recognitions/${target.id}/evidence`
      : `/v1/authorizations/${role}/${target.id}/evidence`;
    const bundle = await expectHttp(await fetch(`${base}${evidencePath}`), 200);
    if (role === "recognition") {
      assert.equal(bundle.recognition.status, "active");
      assert.equal(bundle.authorization, undefined);
      client.verifyRecognitionBundle(bundle, {});
    } else {
      assert.equal(bundle.authorization.status, "active");
      if (role === "issuer") client.verifyIssuerAuthorizationBundle(bundle, {});
      if (role === "verifier") client.verifyVerifierAuthorizationBundle(bundle, {});
      if (role === "auditor") client.verifyAuditorAuthorizationBundle(bundle, {});
    }
  }
  await expectHttp(await fetch(
    `${base}/v1/governed/issuer/${recognition.recognitionId}/actions/approve`,
  ), 404);
  await expectHttp(await fetch(`${base}/v1/authorizations/resolve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      role: "issuer", subjectDid: issuer.subjectDid,
      resourceId: createIssuerScenarioFixture("wrong-scope").resourceId,
    }),
  }), 404);
  const issuerBundle = await expectHttp(await fetch(
    `${base}/v1/authorizations/issuer/${issuer.authorizationId}/evidence`,
  ), 200);
  client.verifyIssuerAuthorizationBundle(issuerBundle, {
    expectedRegistryId: harness.registryId,
    expectedSubjectDid: issuer.subjectDid,
    expectedResourceId: issuer.resourceId,
  });
  const evaluateIssuerAt = (at) => fetch(`${base}/v1/authorizations/evaluate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ role: "issuer", subjectDid: issuer.subjectDid, resourceId: issuer.resourceId, at }),
  });
  const activeAt = issuerBundle.authorization.activeFrom;
  const activeEvaluation = await expectHttp(await evaluateIssuerAt(activeAt), 200);
  assert.equal(activeEvaluation.trustedAtTime, true);
  assert.equal(activeEvaluation.statusAtTime, "active");
  assert.throws(() => client.verifyIssuerAuthorizationBundle(issuerBundle, {
    expectedRegistryId: "registry:wrong",
  }), /registry mismatch/i);
  const afterEpochExpiry = new Date(Date.parse(issuerBundle.epoch.validUntil) + 1).toISOString();
  assert.throws(() => client.verifyIssuerAuthorizationBundle(issuerBundle, {
    expectedRegistryId: harness.registryId,
    evaluationTime: afterEpochExpiry,
  }), /epoch|expired|valid/i);

  const candidateCoSignedProposal = harness.proposeIssuer(
    createIssuerScenarioFixture("governed-demo-candidate-proposal"), [candidate],
  );
  harness.suspendIssuer(issuer);
  snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
  const suspendedBundle = await expectHttp(await fetch(
    `${base}/v1/authorizations/issuer/${issuer.authorizationId}/evidence`,
  ), 200);
  assert.equal(suspendedBundle.authorization.status, "suspended");
  assert.throws(() => client.verifyIssuerAuthorizationBundle(suspendedBundle, {
    expectedRegistryId: harness.registryId,
  }), /not active/i);
  const suspendedEvaluation = await expectHttp(await evaluateIssuerAt(
    suspendedBundle.authorization.suspendedAt,
  ), 200);
  assert.equal(suspendedEvaluation.trustedAtTime, false);
  assert.equal(suspendedEvaluation.statusAtTime, "suspended");
  const historicalAfterSuspension = await expectHttp(await evaluateIssuerAt(activeAt), 200);
  assert.equal(historicalAfterSuspension.trustedAtTime, true);
  harness.revokeIssuer(issuer);
  snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
  const revokedBundle = await expectHttp(await fetch(
    `${base}/v1/authorizations/issuer/${issuer.authorizationId}/evidence`,
  ), 200);
  assert.equal(revokedBundle.authorization.status, "revoked");
  assert.throws(() => client.verifyIssuerAuthorizationBundle(revokedBundle, {
    expectedRegistryId: harness.registryId,
  }), /not active/i);
  const revokedEvaluation = await expectHttp(await evaluateIssuerAt(
    revokedBundle.authorization.revokedAt,
  ), 200);
  assert.equal(revokedEvaluation.trustedAtTime, false);
  assert.equal(revokedEvaluation.statusAtTime, "revoked");
  const historicalAfterRevocation = await expectHttp(await evaluateIssuerAt(activeAt), 200);
  assert.equal(historicalAfterRevocation.trustedAtTime, true);
  client.verifyIssuerAuthorizationBundle(issuerBundle, {
    expectedRegistryId: harness.registryId,
    evaluationTime: activeAt,
  });

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
    },
  ];
  const temporalChecks = [];
  for (const target of temporalTargets) {
    const recognitionTarget = target.role === "recognition";
    const statusRecord = (bundle) => recognitionTarget ? bundle.recognition : bundle.authorization;
    const evaluateAt = (at) => fetch(`${base}/v1/${recognitionTarget ? "recognitions" : "authorizations"}/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(target.evaluationBody(at)),
    });
    const activeBundle = await expectHttp(await fetch(`${base}${target.path}`), 200);
    const roleActiveAt = recognitionTarget
      ? activeBundle.recognition.effectiveFrom : activeBundle.authorization.activeFrom;
    target.verify(activeBundle, { expectedRegistryId: harness.registryId, evaluationTime: roleActiveAt });
    const active = await expectHttp(await evaluateAt(roleActiveAt), 200);
    assert.equal(active.trustedAtTime, true, `${target.role} must be trusted at activation`);

    target.suspend();
    snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
    const suspendedBundle = await expectHttp(await fetch(`${base}${target.path}`), 200);
    assert.equal(statusRecord(suspendedBundle).status, "suspended");
    assert.throws(() => target.verify(suspendedBundle, {
      expectedRegistryId: harness.registryId,
    }), /not active/i);
    const suspended = await expectHttp(await evaluateAt(statusRecord(suspendedBundle).suspendedAt), 200);
    assert.equal(suspended.trustedAtTime, false, `${target.role} must be denied while suspended`);
    const historicalAfterSuspension = await expectHttp(await evaluateAt(roleActiveAt), 200);
    assert.equal(historicalAfterSuspension.trustedAtTime, true);

    target.revoke();
    snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
    const revokedBundle = await expectHttp(await fetch(`${base}${target.path}`), 200);
    assert.equal(statusRecord(revokedBundle).status, "revoked");
    assert.throws(() => target.verify(revokedBundle, {
      expectedRegistryId: harness.registryId,
    }), /not active/i);
    const revoked = await expectHttp(await evaluateAt(statusRecord(revokedBundle).revokedAt), 200);
    assert.equal(revoked.trustedAtTime, false, `${target.role} must be denied after revocation`);
    const historicalAfterRevocation = await expectHttp(await evaluateAt(roleActiveAt), 200);
    assert.equal(historicalAfterRevocation.trustedAtTime, true);
    target.verify(activeBundle, { expectedRegistryId: harness.registryId, evaluationTime: roleActiveAt });
    temporalChecks.push({
      role: target.role,
      activeAt: roleActiveAt,
      activeAfterSuspension: historicalAfterSuspension.trustedAtTime,
      activeAfterRevocation: historicalAfterRevocation.trustedAtTime,
      suspendedAtSuspension: suspended.trustedAtTime,
      revokedAtRevocation: revoked.trustedAtTime,
    });
  }

  process.stdout.write(`${JSON.stringify({
    mode: "Compact simulator fixture; not network finality",
    registryId: harness.registryId,
    governance: "2-of-3 external JubJub signatures for all decisions",
    issuerProposal: {
      eventHash: issuerProposal.eventHash,
      evidenceCommitment: issuerEvidence.commitment,
      source: "published VC/VP fixture and one-use challenge via HTTP proposal",
    },
    otherProposals,
    recognitionProposal: "fixture-signed; external authority accreditation proof not yet implemented",
    decisions,
    activeEvidence: "issuer, verifier, auditor, and recognition independently verified",
    issuerEvidenceEpoch: {
      epochId: issuerBundle.epoch.epochId,
      stateRoot: issuerBundle.epoch.stateRoot,
      validFrom: issuerBundle.epoch.validFrom,
      validUntil: issuerBundle.epoch.validUntil,
    },
    issuerTemporalChecks: {
      activeAt,
      activeAtProposal: activeEvaluation.trustedAtTime,
      activeAfterSuspension: historicalAfterSuspension.trustedAtTime,
      activeAfterRevocation: historicalAfterRevocation.trustedAtTime,
      suspendedAtSuspension: suspendedEvaluation.trustedAtTime,
      revokedAtRevocation: revokedEvaluation.trustedAtTime,
      currentStatus: revokedBundle.authorization.status,
    },
    otherTemporalChecks: temporalChecks,
    candidateCoSignedProposalEventHash: asHex(candidateCoSignedProposal),
    expectedRejections: ["proposal-one-signer:403", "proposal-replay:409", "decision-one-signer:403", "candidate-self-vote:403", "replayed-context:409", "cross-role:404", "wrong-scope:404", "wrong-registry:client", "expired-epoch:client", "suspended:client", "revoked:client"],
  }, null, 2)}\n`);
} finally {
  await new Promise((resolve) => server.close(resolve));
}
