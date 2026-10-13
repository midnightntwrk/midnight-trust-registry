import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { randomBytes, timingSafeEqual } from "node:crypto";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signIssuerProposalEvidenceFromSeed,
  signPolicyBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  ApplicationChallengeBindingSchema,
  computeAuthorizationScopeCommitment,
  createScopedIdentifier,
  sha256Hex,
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
  VP_FIXTURE_NONCE,
  VP_FIXTURE_TIME_MS,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  InMemoryApplicationChallengeStore,
  createTrustRegistryApiServer,
  GovernedAuditorProposalRejectedError,
  GovernedIssuerProposalRejectedError,
  GovernedMaintainerProposalRejectedError,
  GovernedMembershipActionRejectedError,
  GovernedVerifierProposalRejectedError,
} from "../packages/trust-registry-api/dist/index.js";
import { AdversarialMatrix } from "./adversarial-matrix.mjs";
import { TrustRegistryTrqpAdapter } from "../adapters/trqp/dist/index.js";

const asHex = (value) => `0x${Buffer.from(value).toString("hex")}`;
const fromHex = (value) => Buffer.from(value.slice(2), "hex");
const changeLastHexNibble = (value) => `${value.slice(0, -1)}${value.endsWith("0") ? "1" : "0"}`;
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
const signCompact = (maintainer, prepared) => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    prepared.registryId,
    prepared.policyCommitment,
    prepared.actionKind,
    prepared.actionPayloadHash,
    prepared.actionSequence,
  ),
});

const expectHttp = async (response, status) => {
  const payload = await response.json();
  assert.equal(response.status, status, JSON.stringify(payload));
  return payload;
};
const adversarialMatrix = new AdversarialMatrix();

const lastActiveHarness = new LocalTrustRegistryIntegrationHarness("governed-demo-last-active");
const bootstrapMembership = {
  maintainerIdCommitment: lastActiveHarness.maintainerIdCommitment,
  maintainerId: lastActiveHarness.maintainerId,
  subjectDidCommitment: lastActiveHarness.maintainerDidCommitment,
  keyId: lastActiveHarness.simulator.getLedger().lastAuthorizedMaintainerKeyId,
  seed: new Uint8Array(32),
  subjectDid: lastActiveHarness.maintainerDid,
  trustLevel: "bootstrap-maintainer",
};
const lastActiveActionCount = lastActiveHarness.simulator.getLedger().governanceActionCount;
adversarialMatrix.expectThrown(() => lastActiveHarness.suspendMaintainer(bootstrapMembership), {
  id: "compact-last-active-maintainer",
  invariant: "The final active maintainer cannot be suspended",
  boundary: "compact",
  messagePattern: /threshold policy/iu,
  category: "last-active-maintainer-protected",
});
assert.equal(lastActiveHarness.simulator.getLedger().activeMaintainerCount, 1n);
assert.equal(lastActiveHarness.simulator.getLedger().governanceActionCount, lastActiveActionCount);

const removedSignerHarness = new LocalTrustRegistryIntegrationHarness("governed-demo-removed-signer");
const removedSigner = createMaintainerScenarioFixture("governed-demo-removed-signer");
const removedSignerIssuer = createIssuerScenarioFixture("governed-demo-removed-signer-issuer");
removedSignerHarness.authorizeMaintainer(removedSigner);
removedSignerHarness.suspendMaintainer(removedSigner);
removedSignerHarness.proposeIssuer(removedSignerIssuer);
const removedSignerApproval = removedSignerHarness.prepareIssuerDecisionAction(removedSignerIssuer, "approve");
const removedSignerActionCount = removedSignerHarness.simulator.getLedger().governanceActionCount;
adversarialMatrix.expectThrown(() => removedSignerHarness.executeIssuerDecisionWithSignatures(
  removedSignerIssuer, "approve", [signCompact(removedSigner, removedSignerApproval)],
), {
  id: "compact-removed-maintainer-signer",
  invariant: "A suspended maintainer key cannot approve a new issuer",
  boundary: "compact",
  messagePattern: /active|authorized|maintainer|signature|assert/iu,
  category: "removed-signer-rejected",
});
assert.equal(removedSignerHarness.simulator.getLedger().governanceActionCount, removedSignerActionCount);

const policyHarness = new LocalTrustRegistryIntegrationHarness("governed-demo-policy-replay");
const policySecond = createMaintainerScenarioFixture("governed-demo-policy-second");
const policyThird = createMaintainerScenarioFixture("governed-demo-policy-third");
const historicalIssuer = createIssuerScenarioFixture("governed-demo-historical-issuer");
const pendingPolicyIssuer = createIssuerScenarioFixture("governed-demo-pending-policy-issuer");
const currentPolicyIssuer = createIssuerScenarioFixture("governed-demo-current-policy-issuer");
const policyClient = new TrustRegistrySimulatorClient(policyHarness.simulator);
policyHarness.authorizeIssuer(historicalIssuer);
const originalPolicyBundle = policyHarness.evaluateCurrentIssuerDecision(historicalIssuer);
policyHarness.authorizeMaintainer(policySecond);
policyHarness.authorizeMaintainer(policyThird);
policyHarness.proposeIssuer(pendingPolicyIssuer);
const oldPolicyAction = policyHarness.prepareIssuerDecisionAction(pendingPolicyIssuer, "approve");
const oldPolicySignature = signCompact(policySecond, oldPolicyAction);
const oldPolicyCoSignature = signCompact(policyThird, oldPolicyAction);
policyHarness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
const policyActionCountBeforeReplay = policyHarness.simulator.getLedger().governanceActionCount;
adversarialMatrix.expectThrown(() => policyHarness.prepareIssuerDecisionAction(
  pendingPolicyIssuer, "approve",
), {
  id: "integration-old-policy-application-preflight",
  invariant: "An application attested under the former policy cannot be approved after a revision",
  boundary: "integration",
  messagePattern: /policyVersion does not match/iu,
  category: "old-policy-application-rejected",
});
adversarialMatrix.expectThrown(() => policyHarness.simulator.authorizeIssuerAuthorization(
  oldPolicySignature.keyId,
  oldPolicySignature.publicKey,
  oldPolicySignature.signature,
  pendingPolicyIssuer.authorizationIdCommitment,
  oldPolicyAction.evidenceHash,
  [oldPolicyCoSignature],
), {
  id: "compact-old-policy-signature-replay",
  invariant: "A signed action from the former policy cannot satisfy the revised maintainer quorum",
  boundary: "compact",
  messagePattern: /signature|policy|assert|maintainer/iu,
  category: "old-policy-signature-rejected",
});
assert.equal(policyHarness.simulator.getLedger().governanceActionCount, policyActionCountBeforeReplay);
policyHarness.proposeIssuer(currentPolicyIssuer, [policySecond]);
policyHarness.approveIssuer(currentPolicyIssuer, [policySecond]);
policyHarness.activateIssuer(currentPolicyIssuer, [policySecond]);
const currentPolicyBundle = policyHarness.evaluateCurrentIssuerDecision(currentPolicyIssuer);
const historicalPolicyBundle = policyHarness.buildIssuerHistoricalEvidence(historicalIssuer);
assert.equal(originalPolicyBundle.policy.version, historicalPolicyBundle.policy.version);
assert.notEqual(historicalPolicyBundle.policy.version, currentPolicyBundle.policy.version);
adversarialMatrix.expectVerified(() => policyClient.verifyIssuerAuthorizationBundle(
  historicalPolicyBundle, {},
), {
  id: "issuer-history-survives-threshold-change",
  invariant: "Old issuer authorization remains verifiable under its original policy snapshot",
  boundary: "client",
});
adversarialMatrix.expectVerified(() => policyClient.verifyIssuerAuthorizationBundle(
  currentPolicyBundle, {},
), {
  id: "issuer-current-policy-after-threshold-change",
  invariant: "New issuer authorization verifies under the revised policy snapshot",
  boundary: "client",
});
adversarialMatrix.expectThrown(() => policyClient.verifyIssuerAuthorizationBundle(
  historicalPolicyBundle, { evaluationTime: currentPolicyBundle.policy.effectiveFrom },
), {
  id: "issuer-old-policy-current-time-replay",
  invariant: "Historical issuer evidence cannot establish trust after its policy is superseded",
  boundary: "client",
  messagePattern: /policy snapshot is superseded/iu,
  category: "superseded-policy-rejected",
});
adversarialMatrix.expectThrown(() => policyClient.verifyIssuerAuthorizationBundle(
  { ...historicalPolicyBundle, policy: { ...historicalPolicyBundle.policy, version: "v9" } }, {},
), {
  id: "issuer-uncommitted-policy-version",
  invariant: "Changing the evidence policy version cannot create an uncommitted authorization",
  boundary: "client",
  messagePattern: /not committed to the ledger/iu,
  category: "uncommitted-policy-version-rejected",
});

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
const applicantSpecs = [
  {
    role: "issuer",
    id: issuer.authorizationId,
    subjectDid: issuer.subjectDid,
    scope: createIssuerAuthorizationScopeFixture(issuer),
    governedResource: { type: "credentialFamily", id: issuer.resourceId },
  },
  {
    role: "verifier",
    id: verifier.authorizationId,
    subjectDid: verifier.subjectDid,
    scope: createVerifierAuthorizationScopeFixture(verifier),
    governedResource: { type: "requestProfile", id: verifier.scopeResourceId },
  },
  {
    role: "auditor",
    id: auditor.authorizationId,
    subjectDid: auditor.subjectDid,
    scope: createAuditorAuthorizationScopeFixture(auditor),
    governedResource: { type: "requestProfile", id: auditor.scopeResourceId },
  },
  {
    role: "maintainer",
    id: candidate.maintainerId,
    subjectDid: candidate.subjectDid,
    scope: createMaintainerAuthorizationScopeFixture(harness.registryId),
    governedResource: { type: "registry", id: harness.registryId },
  },
];
const bindings = new Map(applicantSpecs.map((spec) => {
  const binding = ApplicationChallengeBindingSchema.parse({
    registryId: harness.registryId,
    applicationId: createScopedIdentifier("application", spec.role, spec.id),
    subjectDid: spec.subjectDid,
    evidenceVerifierDid: harness.evidenceVerifier.did,
    role: spec.role,
    policyId: harness.policyId,
    policyVersion: harness.policyRecord.version,
    scope: spec.scope,
    scopeCommitment: computeAuthorizationScopeCommitment(spec.scope),
    governedResource: spec.governedResource,
  });
  return [binding.applicationId, binding];
}));
const registeredApplications = new Map(applicantSpecs.map((spec) => {
  const applicationId = createScopedIdentifier("application", spec.role, spec.id);
  return [applicationId, {
    authorizationId: spec.id,
    binding: bindings.get(applicationId),
    status: "pending",
    createdAt: new Date(VP_FIXTURE_TIME_MS).toISOString(),
  }];
}));
const pendingApplications = new Set(bindings.keys());
const applicantTokens = new Map([...bindings.keys()].map((id) => [id, randomBytes(32).toString("hex")]));
const vpPortsByApplication = new Map();
const evidenceByRole = new Map();
const expectedEvidenceByRole = new Map();
const persistedEvidence = new Map();
const evidenceReceipts = new Map();
const signerFixture = await createApplicationVpScenarioFixture(VP_FIXTURE_NONCE, {
  evidenceVerifierDid: harness.evidenceVerifier.did,
  evidenceVerifierMethodId: harness.evidenceVerifier.keyIds[0].split("#")[1],
});
const signingPorts = await createApplicationVpIntakePorts({
  resolver: signerFixture.input.resolver,
  family: signerFixture.input.family,
  signer: signerFixture.signer,
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
    prepare: (action) => harness.prepareMaintainerDecisionAction(candidate, action),
    execute: (action, signers) => harness.executeMaintainerDecisionWithSignatures(candidate, action, signers),
  }],
  ["recognition", {
    id: recognition.recognitionId,
    prepare: (action) => harness.prepareRecognitionDecisionAction(recognition, action),
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
    evidence: () => evidenceByRole.get("verifier"),
    prepare: (evidence) => harness.prepareVerifierProposalAction(
      verifier, evidence, expectedEvidenceByRole.get("verifier"),
    ),
    execute: (evidence, signers, signature) =>
      harness.executeVerifierProposalWithSignatures(
        verifier, evidence, signers, signature, expectedEvidenceByRole.get("verifier"),
      ),
    resolve: () => harness.simulator.getVerifierProposalEvidence(verifier.authorizationIdCommitment),
    signEvidence: (prepared) => harness.signVerifierProposalEvidence(prepared),
    rejected: GovernedVerifierProposalRejectedError,
    missing: "unknown-authorization",
  }],
  ["auditor", {
    id: auditor.authorizationId,
    evidence: () => evidenceByRole.get("auditor"),
    prepare: (evidence) => harness.prepareAuditorProposalAction(
      auditor, evidence, expectedEvidenceByRole.get("auditor"),
    ),
    execute: (evidence, signers, signature) =>
      harness.executeAuditorProposalWithSignatures(
        auditor, evidence, signers, signature, expectedEvidenceByRole.get("auditor"),
      ),
    resolve: () => harness.simulator.getAuditorProposalEvidence(auditor.authorizationIdCommitment),
    signEvidence: (prepared) => harness.signAuditorProposalEvidence(prepared),
    rejected: GovernedAuditorProposalRejectedError,
    missing: "unknown-authorization",
  }],
  ["maintainer", {
    id: candidate.maintainerId,
    evidence: () => evidenceByRole.get("maintainer"),
    prepare: (evidence) => harness.prepareMaintainerProposalAction(
      candidate, evidence, expectedEvidenceByRole.get("maintainer"),
    ),
    execute: (evidence, signers, signature) =>
      harness.executeMaintainerProposalWithSignatures(
        candidate, evidence, signers, signature, expectedEvidenceByRole.get("maintainer"),
      ),
    resolve: () => harness.simulator.getMaintainerProposalEvidence(candidate.maintainerIdCommitment),
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
  async resolve(id) {
    if (id !== target.id) throw new target.rejected(target.missing);
    const record = target.resolve();
    return {
      eventHash: asHex(record.proposalGovernanceEventHash),
      evidenceCommitment: asHex(record.evidenceCommitment),
    };
  },
});
const server = createTrustRegistryApiServer({
  source: { mode: "memory", loadSnapshot: async () => snapshot },
  clock: () => new Date(VP_FIXTURE_TIME_MS).toISOString(),
  proposalAdmission: {
    resolvePendingApplication: async (applicationId) => registeredApplications.get(applicationId) ?? null,
    resolveAcceptedEvidence: async (applicationId) => {
      const evidence = persistedEvidence.get(applicationId);
      const receipt = evidenceReceipts.get(applicationId);
      return evidence === undefined || receipt === undefined ? null : { evidence, receipt };
    },
  },
  applicationVp: {
    challengeStore: new InMemoryApplicationChallengeStore(),
    authorizeRequest: async (applicationId, request) => {
      const expected = applicantTokens.get(applicationId);
      const supplied = request.headers.authorization?.replace(/^Bearer /u, "");
      if (
        expected === undefined || supplied === undefined || supplied.length !== expected.length
        || !timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))
      ) {
        throw new Error("Demo applicant authorization failed");
      }
    },
    resolvePendingApplication: async (applicationId) => {
      const binding = bindings.get(applicationId);
      return binding === undefined || !pendingApplications.has(applicationId) ? null : {
        binding,
        authorizedVerifiers: [harness.evidenceVerifier],
      };
    },
    verifyPresentation: async (presentation, context) => {
      const ports = vpPortsByApplication.get(context.binding.applicationId);
      if (ports === undefined) throw new Error("Demo VP verifier is unavailable");
      return ports.verifyPresentation(presentation, context);
    },
    signEvidence: signingPorts.signEvidence,
    verifyEvidenceSignature: signingPorts.verifyEvidenceSignature,
    persistRedactedEvidence: async (applicationId, evidence) => {
      if (!pendingApplications.has(applicationId) || persistedEvidence.has(applicationId)) {
        throw new Error("Demo application is no longer pending");
      }
      pendingApplications.delete(applicationId);
      persistedEvidence.set(applicationId, evidence);
      const receipt = {
        receiptId: sha256Hex(`receipt:${applicationId}:${evidence.commitment}`),
        evidenceCommitment: evidence.commitment,
        acceptedAt: new Date(VP_FIXTURE_TIME_MS).toISOString(),
      };
      evidenceReceipts.set(applicationId, receipt);
      return receipt;
    },
    resolveAcceptedEvidence: async (applicationId) => {
      const evidence = persistedEvidence.get(applicationId);
      const receipt = evidenceReceipts.get(applicationId);
      return evidence === undefined || receipt === undefined ? null : { evidence, receipt };
    },
  },
  governedIssuerProposals: {
    async prepare(authorizationId, evidence) {
      if (authorizationId !== issuer.authorizationId) {
        throw new GovernedIssuerProposalRejectedError("unknown-authorization");
      }
      try {
        return harness.prepareIssuerProposalAction(
          issuer, evidence, expectedEvidenceByRole.get("issuer"),
        );
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
          issuer, evidence, signers, verifierSignature, expectedEvidenceByRole.get("issuer"),
        );
      } catch {
        throw new GovernedIssuerProposalRejectedError("invalid-signers");
      }
      projectedRoles.add("issuer");
      publishCurrentSnapshot();
      return { eventHash: asHex(eventHash) };
    },
    async resolve(authorizationId) {
      if (authorizationId !== issuer.authorizationId) {
        throw new GovernedIssuerProposalRejectedError("unknown-authorization");
      }
      const record = harness.simulator.getIssuerProposalEvidence(issuer.authorizationIdCommitment);
      return {
        eventHash: asHex(record.proposalGovernanceEventHash),
        evidenceCommitment: asHex(record.evidenceCommitment),
      };
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
  for (const spec of applicantSpecs) {
    const applicationId = createScopedIdentifier("application", spec.role, spec.id);
    const endpoint = `${base}/v1/application-evidence/${applicationId}`;
    const headers = {
      "content-type": "application/json",
      authorization: `Bearer ${applicantTokens.get(applicationId)}`,
    };
    const post = (suffix, body, requestHeaders = headers) => fetch(`${endpoint}/${suffix}`, {
      method: "POST",
      headers: requestHeaders,
      body: JSON.stringify(body),
    });
    const getReceipt = (requestHeaders = headers) => fetch(`${endpoint}/receipt`, { headers: requestHeaders });
    await expectHttp(await getReceipt({}), 403);
    await expectHttp(await getReceipt(), 404);
    await adversarialMatrix.expectHttp(await post("challenges", {}, {
      "content-type": "application/json",
    }), {
      id: `${spec.role}-unauthorized-vp-challenge`,
      invariant: "Only the authenticated applicant may request an evidence challenge",
      boundary: "api",
      status: 403,
      problemType: "application-vp-forbidden",
    });
    const other = applicantSpecs.find((candidateSpec) => candidateSpec.role !== spec.role);
    const otherId = createScopedIdentifier("application", other.role, other.id);
    await expectHttp(await post("challenges", {}, {
      "content-type": "application/json",
      authorization: `Bearer ${applicantTokens.get(otherId)}`,
    }), 403);
    const challenge = await expectHttp(await post("challenges", {}), 201);
    if (spec.role === "issuer") {
      for (const [caseId, invariant, invalid] of [
        ["issuer-wrong-signed-vp-scope", "VP credential scope must match the pending issuer application",
          { scope: { ...spec.scope, credentialFamilyId: "credential-family:wrong" } }],
        ["issuer-unbound-vp-credential", "VP must bind the submitted credential body",
          { presentationCredentialBodyRoot: sha256Hex("unbound-credential-body") }],
        ["issuer-revoked-vp-credential", "Revoked evidence credentials cannot satisfy eligibility",
          { statusDecision: { active: false } }],
      ]) {
        const wrongProof = await createApplicationVpScenarioFixture(challenge.nonce, {
          subjectDid: spec.subjectDid,
          evidenceVerifierDid: harness.evidenceVerifier.did,
          evidenceVerifierMethodId: harness.evidenceVerifier.keyIds[0].split("#")[1],
          scope: spec.scope,
          ...invalid,
        });
        vpPortsByApplication.set(applicationId, await createApplicationVpIntakePorts({
          resolver: wrongProof.input.resolver,
          family: wrongProof.input.family,
          signer: wrongProof.signer,
        }));
        await adversarialMatrix.expectHttp(await post("submissions", {
          nonce: challenge.nonce,
          challengeHash: challenge.challengeHash,
          presentation: wrongProof.input.submission,
        }), {
          id: caseId,
          invariant,
          boundary: "api",
          status: 403,
          problemType: "application-vp-rejected",
        });
        assert.equal(persistedEvidence.has(applicationId), false);
      }
    }
    const proof = await createApplicationVpScenarioFixture(challenge.nonce, {
      subjectDid: spec.subjectDid,
      evidenceVerifierDid: harness.evidenceVerifier.did,
      evidenceVerifierMethodId: harness.evidenceVerifier.keyIds[0].split("#")[1],
      scope: spec.scope,
    });
    vpPortsByApplication.set(applicationId, await createApplicationVpIntakePorts({
      resolver: proof.input.resolver,
      family: proof.input.family,
      signer: proof.signer,
    }));
    const submission = {
      nonce: challenge.nonce,
      challengeHash: challenge.challengeHash,
      presentation: proof.input.submission,
    };
    // Recovery reads the accepted record; it must not repeat VP verification.
    assert.equal((await post("submissions", submission)).status, 202);
    const submitted = await expectHttp(await getReceipt(), 200);
    assert.equal(submitted.receipt.evidenceCommitment, submitted.evidence.commitment);
    assert.deepEqual(persistedEvidence.get(applicationId), submitted.evidence);
    assert.equal(JSON.stringify(submitted).includes(proof.input.submission.rawCredentialBody), false);
    assert.equal(JSON.stringify(submitted).includes(proof.input.submission.rawPresentationBody), false);
    await adversarialMatrix.expectHttp(await post("submissions", submission), {
      id: `${spec.role}-vp-challenge-replay`,
      invariant: "A consumed application challenge cannot accept a second VP",
      boundary: "api",
      status: 404,
      problemType: "application-vp-not-found",
    });
    await expectHttp(await post("challenges", {}), 404);
    evidenceByRole.set(spec.role, submitted.evidence);
    expectedEvidenceByRole.set(spec.role, {
      scope: spec.scope,
      challengeHash: challenge.challengeHash,
      governedResource: spec.governedResource,
    });
  }
  const issuerEvidence = evidenceByRole.get("issuer");
  const expectedIssuerEvidence = expectedEvidenceByRole.get("issuer");
  assert.ok(issuerEvidence);
  assert.ok(expectedIssuerEvidence);
  const proposalEndpoint = `${base}/v1/governed/issuer/${issuer.authorizationId}/proposal`;
  const proposePrepare = (endpoint, evidence) => fetch(`${endpoint}/prepare`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ evidence }),
  });
  const alteredIssuerEvidence = {
    ...issuerEvidence,
    commitment: changeLastHexNibble(issuerEvidence.commitment),
  };
  await adversarialMatrix.expectHttp(await proposePrepare(proposalEndpoint, alteredIssuerEvidence), {
    id: "issuer-altered-evidence-commitment-api",
    invariant: "A governed proposal cannot use a commitment different from the accepted VP envelope",
    boundary: "api",
    status: 403,
    problemType: "unadmitted-proposal",
  });
  adversarialMatrix.expectThrown(() => harness.prepareIssuerProposalAction(
    issuer, alteredIssuerEvidence, expectedIssuerEvidence,
  ), {
    id: "issuer-altered-evidence-commitment-integration-preflight",
    invariant: "Simulator preflight rejects evidence whose commitment is not its envelope hash before Compact execution",
    boundary: "integration",
    messagePattern: /commitment|evidence/iu,
    category: "evidence-commitment-rejected",
  });
  for (const spec of applicantSpecs) {
    const endpoint = `${base}/v1/governed/${spec.role}/${spec.id}/proposal`;
    const applicationId = createScopedIdentifier("application", spec.role, spec.id);
    const evidence = evidenceByRole.get(spec.role);
    const other = applicantSpecs.find((candidateSpec) => candidateSpec.role !== spec.role);
    await adversarialMatrix.expectHttp(await proposePrepare(endpoint, evidenceByRole.get(other.role)), {
      id: `${spec.role}-cross-role-evidence`,
      invariant: "A proposal must use an accepted VP receipt for its own role and target",
      boundary: "api",
      status: 403,
      problemType: "unadmitted-proposal",
    });
    await adversarialMatrix.expectHttp(await proposePrepare(
      `${base}/v1/governed/${spec.role}/${createScopedIdentifier("wrong", spec.id)}/proposal`, evidence,
    ), {
      id: `${spec.role}-wrong-proposal-target`,
      invariant: "A proposal target must match the accepted VP receipt",
      boundary: "api",
      status: 403,
      problemType: "unadmitted-proposal",
    });
    const receipt = evidenceReceipts.get(applicationId);
    evidenceReceipts.delete(applicationId);
    await adversarialMatrix.expectHttp(await proposePrepare(endpoint, evidence), {
      id: `${spec.role}-missing-vp-receipt`,
      invariant: "A proposal cannot bypass accepted VP evidence",
      boundary: "api",
      status: 403,
      problemType: "unadmitted-proposal",
    });
    evidenceReceipts.set(applicationId, receipt);
    const pending = registeredApplications.get(applicationId);
    assert.ok(pending);
    registeredApplications.set(applicationId, { ...pending, authorizationId: "auth:substituted:target" });
    await expectHttp(await proposePrepare(endpoint, evidence), 403);
    registeredApplications.set(applicationId, pending);
  }
  const issuerApplicationId = createScopedIdentifier("application", "issuer", issuer.authorizationId);
  const issuerReceipt = evidenceReceipts.get(issuerApplicationId);
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
  const wrongVerifierSignature = signIssuerProposalEvidenceFromSeed(
    second.seed,
    fromHex(proposalPrepared.registryId),
    fromHex(proposalPrepared.evidenceVerifierKeyIdCommitment),
    fromHex(proposalPrepared.actionPayloadHash),
  );
  const submitProposal = (body) => fetch(`${proposalEndpoint}/submit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  evidenceReceipts.delete(issuerApplicationId);
  await expectHttp(await submitProposal(proposalBody), 403);
  evidenceReceipts.set(issuerApplicationId, issuerReceipt);
  await adversarialMatrix.expectHttp(await submitProposal({
    ...proposalBody,
    evidenceVerifierSignature: asHex(encodeJubjubSignature(wrongVerifierSignature)),
  }), {
    id: "issuer-unauthorized-evidence-verifier-api",
    invariant: "An unregistered evidence-verifier key cannot attest issuer eligibility",
    boundary: "api",
    status: 403,
    problemType: "governed-proposal-rejected",
  });
  const compactIssuerProposal = harness.prepareIssuerProposalAction(
    issuer, issuerEvidence, expectedIssuerEvidence,
  );
  const actionCountBeforeWrongVerifier = harness.simulator.getLedger().governanceActionCount;
  adversarialMatrix.expectThrown(() => harness.executeIssuerProposalWithSignatures(
    issuer,
    issuerEvidence,
    [signCompact(second, compactIssuerProposal), signCompact(third, compactIssuerProposal)],
    wrongVerifierSignature,
    expectedIssuerEvidence,
  ), {
    id: "issuer-unauthorized-evidence-verifier-compact",
    invariant: "Compact rejects a proposal signed by an unregistered evidence-verifier key",
    boundary: "compact",
    messagePattern: /signature|verifier|assert|authorized/iu,
    category: "unauthorized-verifier-rejected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, actionCountBeforeWrongVerifier);
  await adversarialMatrix.expectHttp(
    await submitProposal({ ...proposalBody, signers: proposalBody.signers.slice(0, 1) }),
    {
      id: "issuer-proposal-insufficient-quorum",
      invariant: "Issuer proposal requires the active maintainer quorum",
      boundary: "api",
      status: 403,
      problemType: "governed-proposal-rejected",
    },
  );
  assert.equal((await submitProposal(proposalBody)).status, 202);
  const issuerProposal = await expectHttp(await fetch(`${proposalEndpoint}/resolve`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ evidence: issuerEvidence }),
  }), 200);
  assert.equal(issuerProposal.state, "observed");
  await expectHttp(await submitProposal(proposalBody), 409);
  assert.equal(harness.simulator.getLedger().issuerAuthorizationCount, 1n);
  const compactApproval = harness.prepareIssuerDecisionAction(issuer, "approve");
  const compactSigner = signCompact(second, compactApproval);
  const governanceActionsBeforeRejections = harness.simulator.getLedger().governanceActionCount;
  adversarialMatrix.expectThrown(() => harness.executeIssuerDecisionWithSignatures(
    issuer, "approve", [compactSigner],
  ), {
    id: "compact-issuer-insufficient-quorum",
    invariant: "Compact rejects issuer approval without the active maintainer quorum",
    boundary: "compact",
    messagePattern: /quorum|threshold|assert|signature|maintainer/iu,
    category: "quorum-rejected",
  });
  adversarialMatrix.expectThrown(() => harness.executeIssuerDecisionWithSignatures(
    issuer, "approve", [compactSigner, compactSigner],
  ), {
    id: "compact-issuer-duplicate-signer",
    invariant: "Compact rejects duplicate maintainer signatures as one quorum vote",
    boundary: "compact",
    messagePattern: /quorum|threshold|assert|signature|maintainer|duplicate/iu,
    category: "duplicate-signer-rejected",
  });
  adversarialMatrix.expectThrown(() => harness.executeIssuerDecisionWithSignatures(
    issuer, "approve", [compactSigner, signCompact(
      createMaintainerScenarioFixture("governed-demo-outsider"), compactApproval,
    )],
  ), {
    id: "compact-issuer-unknown-signer",
    invariant: "An unregistered JubJub key cannot substitute for an active maintainer",
    boundary: "compact",
    messagePattern: /assert|signature|maintainer|authorized|registered/iu,
    category: "unknown-signer-rejected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, governanceActionsBeforeRejections);
  const otherProposals = [];
  for (const [role, target] of proposalTargets) {
    const evidence = target.evidence();
    assert.ok(evidence);
    const endpoint = `${base}/v1/governed/${role}/${target.id}/proposal`;
    const prepared = await expectHttp(await fetch(`${endpoint}/prepare`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ evidence }),
    }), 200);
    const signature = target.signEvidence(target.prepare(evidence));
    const body = {
      evidence,
      prepared,
      signers: [sign(second, prepared), sign(third, prepared)],
      evidenceVerifierSignature: asHex(encodeJubjubSignature(signature)),
    };
    const submit = (payload) => fetch(`${endpoint}/submit`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
    });
    await expectHttp(await submit({ ...body, signers: body.signers.slice(0, 1) }), 403);
    assert.equal((await submit(body)).status, 202);
    const accepted = await expectHttp(await fetch(`${endpoint}/resolve`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ evidence }),
    }), 200);
    assert.equal(accepted.state, "observed");
    await expectHttp(await submit(body), 409);
    otherProposals.push({
      role,
      eventHash: accepted.eventHash,
      evidenceCommitment: evidence.commitment,
      source: "authenticated VP HTTP intake and governed HTTP proposal",
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
      await adversarialMatrix.expectHttp(await submit(prepared, signers.slice(0, 1)), {
        id: `${role}-${action}-insufficient-quorum`,
        invariant: "Governed membership transition requires the active maintainer quorum",
        boundary: "api",
        status: 403,
        problemType: "governed-action-rejected",
      });
      if (role === "maintainer") {
        await adversarialMatrix.expectHttp(await submit(prepared, [signers[0], sign(candidate, prepared)]), {
          id: `maintainer-${action}-candidate-self-vote`,
          invariant: "A candidate maintainer cannot approve its own membership",
          boundary: "api",
          status: 403,
          problemType: "governed-action-rejected",
        });
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
  adversarialMatrix.expectThrown(() => client.verifyIssuerAuthorizationBundle({
    ...issuerBundle,
    inclusionProof: {
      ...issuerBundle.inclusionProof,
      path: [changeLastHexNibble(issuerBundle.inclusionProof.path[0])],
    },
  }, { expectedRegistryId: harness.registryId }), {
    id: "issuer-tampered-merkle-path",
    invariant: "A changed Merkle sibling cannot verify against the anchored epoch",
    boundary: "client",
    messagePattern: /event sibling/iu,
    category: "tampered-merkle-path",
  });
  adversarialMatrix.expectThrown(() => client.verifyIssuerAuthorizationBundle(issuerBundle, {
    expectedResourceId: "credential-family:unknown",
  }), {
    id: "issuer-wrong-credential-family",
    invariant: "Issuer authorization is bound to the exact credential family",
    boundary: "client",
    messagePattern: /issuer authorization resource mismatch/iu,
    category: "issuer-scope-mismatch",
  });
  const verifierBundle = await expectHttp(await fetch(
    `${base}/v1/authorizations/verifier/${verifier.authorizationId}/evidence`,
  ), 200);
  adversarialMatrix.expectThrown(() => client.verifyVerifierAuthorizationBundle(verifierBundle, {
    expectedResourceId: "request-profile:unknown",
  }), {
    id: "verifier-wrong-request-profile",
    invariant: "Verifier authorization is bound to the exact request profile",
    boundary: "client",
    messagePattern: /verifier authorization resource mismatch/iu,
    category: "verifier-scope-mismatch",
  });
  const recognitionBundle = await expectHttp(await fetch(
    `${base}/v1/recognitions/${recognition.recognitionId}/evidence`,
  ), 200);
  adversarialMatrix.expectThrown(() => client.verifyIssuerAuthorizationBundle(recognitionBundle, {}), {
    id: "recognition-not-issuer-authorization",
    invariant: "External registry recognition cannot authorize local VC issuance",
    boundary: "client",
    messagePattern: /does not contain issuer authorization/iu,
    category: "recognition-not-authorization",
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
  const trqpRequest = {
    entity_id: issuer.subjectDid,
    authority_id: harness.registryRecord.registryDid,
    action: "issue",
    resource: issuer.resourceId,
  };
  const trqpAdapter = new TrustRegistryTrqpAdapter({
    getRegistryRecord: async (authorityId) => authorityId === harness.registryRecord.registryDid
      ? harness.registryRecord : null,
    getAuthorizationDecision: async (request) => request.resource === issuer.resourceId
      ? { statusAtTime: "active", trustedAtTime: true } : null,
    getRecognitionDecision: async () => null,
  }, { clock: () => activeAt });
  adversarialMatrix.expectAdapterProblem(await trqpAdapter.queryAuthorization({
    ...trqpRequest,
    resource: "credential-family:unknown",
  }), {
    id: "trqp-unknown-issuer-scope",
    invariant: "TRQP cannot project an authorization for an unregistered credential family",
    status: 404,
    problemType: "not-found",
  });
  adversarialMatrix.expectAdapterProblem(await trqpAdapter.getAuthorizationEvidence(trqpRequest), {
    id: "trqp-missing-epoch-evidence",
    invariant: "TRQP cannot claim evidence when the source has no epoch-bound bundle",
    status: 424,
    problemType: "epoch-evidence-unavailable",
  });
  const inconsistentTrqpAdapter = new TrustRegistryTrqpAdapter({
    getRegistryRecord: async () => harness.registryRecord,
    getAuthorizationDecision: async () => ({ statusAtTime: "suspended", trustedAtTime: true }),
    getRecognitionDecision: async () => null,
  }, { clock: () => activeAt });
  adversarialMatrix.expectAdapterProblem(await inconsistentTrqpAdapter.queryAuthorization(trqpRequest), {
    id: "trqp-contradictory-source",
    invariant: "TRQP must reject a source claiming suspended authorization is trusted",
    status: 500,
    problemType: "invalid-source-data",
  });
  adversarialMatrix.expectThrown(() => client.verifyIssuerAuthorizationBundle(issuerBundle, {
    expectedRegistryId: "registry:wrong",
  }), {
    id: "issuer-wrong-registry",
    invariant: "Issuer evidence must bind the selected registry",
    boundary: "client",
    messagePattern: /registry mismatch/iu,
    category: "registry-mismatch",
  });
  const afterEpochExpiry = new Date(Date.parse(issuerBundle.epoch.validUntil) + 1).toISOString();
  adversarialMatrix.expectThrown(() => client.verifyIssuerAuthorizationBundle(issuerBundle, {
    expectedRegistryId: harness.registryId,
    evaluationTime: afterEpochExpiry,
  }), {
    id: "issuer-expired-epoch",
    invariant: "An expired epoch cannot establish current issuer trust",
    boundary: "client",
    messagePattern: /epoch|expired|valid/iu,
    category: "expired-epoch",
  });

  const candidateCoSignedProposal = harness.proposeIssuer(
    createIssuerScenarioFixture("governed-demo-candidate-proposal"), [candidate],
  );
  harness.suspendIssuer(issuer);
  snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
  const suspendedBundle = await expectHttp(await fetch(
    `${base}/v1/authorizations/issuer/${issuer.authorizationId}/evidence`,
  ), 200);
  assert.equal(suspendedBundle.authorization.status, "suspended");
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
  const historicalAfterSuspension = await expectHttp(await evaluateIssuerAt(activeAt), 200);
  assert.equal(historicalAfterSuspension.trustedAtTime, true);
  adversarialMatrix.expectVerified(() => client.verifyIssuerAuthorizationBundle(issuerBundle, {
    expectedRegistryId: harness.registryId,
    evaluationTime: activeAt,
  }), {
    id: "issuer-historical-after-suspension",
    invariant: "A later suspension does not erase the issuer's earlier active authorization",
    boundary: "client",
  });
  harness.revokeIssuer(issuer);
  snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
  const revokedBundle = await expectHttp(await fetch(
    `${base}/v1/authorizations/issuer/${issuer.authorizationId}/evidence`,
  ), 200);
  assert.equal(revokedBundle.authorization.status, "revoked");
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
  const historicalAfterRevocation = await expectHttp(await evaluateIssuerAt(activeAt), 200);
  assert.equal(historicalAfterRevocation.trustedAtTime, true);
  adversarialMatrix.expectVerified(() => client.verifyIssuerAuthorizationBundle(issuerBundle, {
    expectedRegistryId: harness.registryId,
    evaluationTime: activeAt,
  }), {
    id: "issuer-historical-after-revocation",
    invariant: "A later revocation does not erase the issuer's earlier active authorization",
    boundary: "client",
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
    adversarialMatrix.expectVerified(() => target.verify(activeBundle, {
      expectedRegistryId: harness.registryId,
      evaluationTime: roleActiveAt,
    }), {
      id: `${target.role}-historical-after-suspension`,
      invariant: `A later suspension does not erase ${target.role} trust at its active instant`,
      boundary: "client",
    });

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

  process.stdout.write(`${JSON.stringify({
    mode: "Compact simulator fixture; not network finality",
    registryId: harness.registryId,
    governance: "2-of-3 external JubJub signatures for all decisions",
    acceptedVpRecovery: "issuer, verifier, auditor, and maintainer recovered by authenticated receipt lookup",
    issuerProposal: {
      eventHash: issuerProposal.eventHash,
      evidenceCommitment: issuerEvidence.commitment,
      source: "authenticated VP HTTP intake and governed HTTP proposal",
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
    adversarialMatrix: adversarialMatrix.report(),
  }, null, 2)}\n`);
} finally {
  await new Promise((resolve) => server.close(resolve));
}
