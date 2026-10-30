import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { CompactError, sampleContractAddress } from "@midnight-ntwrk/compact-runtime";

import {
  computeAuditorEvidenceBoundProposalPayloadHash,
  computeCreateAuditorAuthorizationPayloadHash,
  computeCreateIssuerAuthorizationPayloadHash,
  computeCreateMaintainerMembershipPayloadHash,
  computeCreateVerifierAuthorizationPayloadHash,
  computeIssuerEvidenceBoundProposalPayloadHash,
  computeMaintainerEvidenceBoundProposalPayloadHash,
  computeVerifierEvidenceBoundProposalPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signIssuerProposalEvidenceFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
  verifyAuditorProposalEvidenceSignature,
  verifyIssuerProposalEvidenceSignature,
  verifyMaintainerProposalEvidenceSignature,
  verifyVerifierProposalEvidenceSignature,
} from "../contracts/trust-registry/dist/index.js";
import { AuthorizationStatus, IssuerResourceType } from "../contracts/trust-registry/dist/managed/trust-registry/contract/index.js";
import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import {
  bytes32Commitment,
  createVerifiedDecisionEvidenceSource,
} from "../packages/trust-registry-client/dist/index.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  ApplicationChallengeBindingSchema,
  computeApplicationEvidenceCommitment,
  computeAuthorizationScopeCommitment,
  createScopedIdentifier,
  sha256Hex,
} from "../packages/trust-registry-domain/dist/index.js";
import {
  createApplicationVpIntakePorts,
  createApplicationVpScenarioFixture,
  verifyApplicationStatusDecisionWitness,
  createMidnightDid,
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
  AtomicMaintainerRecoveryPrecheckError,
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
  GovernedPolicyActionRejectedError,
  GovernedVerifierProposalRejectedError,
} from "../packages/trust-registry-api/dist/index.js";
import { AdversarialMatrix } from "./adversarial-matrix.mjs";
import { buildActorEvidenceReport } from "./actor-evidence-report.mjs";
import { runApplicationEvidenceSafetyScenarios } from "./governed-demo-application-evidence-safety.mjs";
import { runDenialSafetyScenario } from "./governed-demo-denial-safety.mjs";
import { runGovernedConsumerEvidence } from "./governed-demo-consumer-evidence.mjs";
import { runIssuerTemporalLifecycle } from "./governed-demo-issuer-temporal.mjs";
import { runOtherGovernedProposals } from "./governed-demo-other-proposals.mjs";
import { runOtherTemporalLifecycles } from "./governed-demo-other-temporal.mjs";
import { runHistoricalPolicyHttpChecks } from "./governed-demo-historical-http.mjs";
import { runMaintainerSafetyScenarios } from "./governed-demo-maintainer-safety.mjs";
import { runGovernedRecognitionFlow } from "./governed-demo-recognition-flow.mjs";
import { runGovernedPolicyRecovery } from "./governed-demo-policy-recovery.mjs";
import { runPublicLookupSafety } from "./governed-demo-public-lookup-safety.mjs";
import {
  runHistoricalPolicyClientChecks, runOldPolicyIssuerReplay, runOldPolicyRecognitionReplay,
  runRevisedPolicyRoleReplays,
} from "./governed-demo-policy-replay.mjs";
import { TrustRegistryTrqpAdapter } from "../adapters/trqp/dist/index.js";

const asHex = (value) => `0x${Buffer.from(value).toString("hex")}`;
const fromHex = (value) => Buffer.from(value.slice(2), "hex");
const changeLastHexNibble = (value) => `${value.slice(0, -1)}${value.endsWith("0") ? "1" : "0"}`;
const sign = (maintainer, prepared, sourceHarness = harness) => {
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const ledger = sourceHarness.simulator.getLedger();
  const signature = signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed,
    ledger.registryId,
    ledger.deploymentNetworkIdCommitment,
    Buffer.from(sourceHarness.simulator.contractAddress, "hex"),
    ledger.governancePolicyCommitment,
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
const signCompact = (maintainer, prepared, sourceHarness = harness, policyCommitment) => {
  const ledger = sourceHarness.simulator.getLedger();
  return {
    keyId: maintainer.keyId,
    publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
    signature: signDeploymentBoundMaintainerActionFromSeed(
      maintainer.seed,
      ledger.registryId,
      ledger.deploymentNetworkIdCommitment,
      Buffer.from(sourceHarness.simulator.contractAddress, "hex"),
      policyCommitment ?? ledger.governancePolicyCommitment,
      prepared.actionKind,
      prepared.actionPayloadHash,
      prepared.actionSequence,
    ),
  };
};

const expectHttp = async (response, status) => {
  const payload = await response.json();
  assert.equal(response.status, status, JSON.stringify(payload));
  return payload;
};
const adversarialMatrix = new AdversarialMatrix({ collectFailures: true });
const expectedAdversarialCaseCount = 198;

runMaintainerSafetyScenarios(adversarialMatrix, signCompact);

const { denialEventHash, deniedIssuer, deniedBundle, replacementIssuer, replacementProposalEventHash } =
  runDenialSafetyScenario(adversarialMatrix, signCompact);

runApplicationEvidenceSafetyScenarios(adversarialMatrix);

const policyHarness = new LocalTrustRegistryIntegrationHarness("governed-demo-policy-replay");
const policySecond = createMaintainerScenarioFixture("governed-demo-policy-second");
const policyThird = createMaintainerScenarioFixture("governed-demo-policy-third");
const historicalIssuer = createIssuerScenarioFixture("governed-demo-historical-issuer");
const historicalVerifier = createVerifierScenarioFixture("governed-demo-historical-verifier");
const historicalAuditor = createAuditorScenarioFixture("governed-demo-historical-auditor");
const historicalRecognition = createRecognitionScenarioFixture("governed-demo-historical-recognition");
const pendingPolicyIssuer = createIssuerScenarioFixture("governed-demo-pending-policy-issuer");
const currentPolicyIssuer = createIssuerScenarioFixture("governed-demo-current-policy-issuer");
const policyClient = new TrustRegistrySimulatorClient(policyHarness.simulator);
policyHarness.authorizeIssuer(historicalIssuer);
policyHarness.authorizeVerifier(historicalVerifier);
policyHarness.authorizeAuditor(historicalAuditor);
policyHarness.authorizeRecognition(historicalRecognition);
const originalPolicyBundle = policyHarness.evaluateCurrentIssuerDecision(historicalIssuer);
const originalVerifierBundle = policyHarness.evaluateCurrentVerifierDecision(historicalVerifier);
const originalAuditorBundle = policyHarness.evaluateCurrentAuditorDecision(historicalAuditor);
const originalRecognitionBundle = policyHarness.evaluateCurrentRecognitionDecision(historicalRecognition);
const originalPolicySnapshot = publishSimulatorSnapshot(policyHarness, {
  label: "governed-demo-policy-replay",
  issuers: [{ fixture: historicalIssuer, label: "historical-issuer" }],
  verifiers: [{ fixture: historicalVerifier, label: "historical-verifier" }],
  auditors: [{ fixture: historicalAuditor, label: "historical-auditor" }],
  recognitions: [{ fixture: historicalRecognition, label: "historical-recognition" }],
});
policyHarness.authorizeMaintainer(policySecond);
policyHarness.authorizeMaintainer(policyThird);
policyHarness.proposeIssuer(pendingPolicyIssuer);
const formerPolicyCommitment = Buffer.from(policyHarness.simulator.getLedger().governancePolicyCommitment);
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
assert.equal(policyHarness.simulator.getLedger().governanceActionCount, policyActionCountBeforeReplay);
policyHarness.proposeIssuer(currentPolicyIssuer, [policySecond]);
const currentPolicyBundle = runOldPolicyIssuerReplay(adversarialMatrix, policyHarness,
  currentPolicyIssuer, policySecond, policyThird, formerPolicyCommitment, signCompact);
runOldPolicyRecognitionReplay(adversarialMatrix, policyHarness,
  policySecond, policyThird, formerPolicyCommitment, signCompact);
const historicalPolicyBundle = policyHarness.buildIssuerHistoricalEvidence(historicalIssuer);
assert.equal(originalPolicyBundle.policy.version, historicalPolicyBundle.policy.version);
assert.notEqual(historicalPolicyBundle.policy.version, currentPolicyBundle.policy.version);
assert.notEqual(originalVerifierBundle.policy.version, currentPolicyBundle.policy.version);
policyHarness.revokeIssuer(historicalIssuer, [policySecond]);
policyHarness.revokeVerifier(historicalVerifier, [policySecond]);
policyHarness.revokeAuditor(historicalAuditor, [policySecond]);
policyHarness.revokeRecognition(historicalRecognition, [policySecond]);
const revisedPolicySnapshot = publishSimulatorSnapshot(policyHarness, {
  label: "governed-demo-policy-replay",
  issuers: [
    { fixture: historicalIssuer, label: "historical-issuer" },
    { fixture: currentPolicyIssuer, label: "current-issuer" },
  ],
  verifiers: [{ fixture: historicalVerifier, label: "historical-verifier" }],
  auditors: [{ fixture: historicalAuditor, label: "historical-auditor" }],
  recognitions: [{ fixture: historicalRecognition, label: "historical-recognition" }],
}, originalPolicySnapshot);
// Keep this listener isolated from the later mutable demo server.
await runHistoricalPolicyHttpChecks(adversarialMatrix, {
  originalPolicySnapshot, revisedPolicySnapshot, historicalIssuer, historicalVerifier,
  historicalAuditor, historicalRecognition, originalAuditorBundle,
  originalRecognitionBundle, registryDid: policyHarness.registryDid,
});
runHistoricalPolicyClientChecks(adversarialMatrix, policyClient, {
  historicalPolicyBundle, originalVerifierBundle, originalAuditorBundle,
  originalRecognitionBundle, currentPolicyBundle,
}, changeLastHexNibble);
runRevisedPolicyRoleReplays(adversarialMatrix, policyHarness, policyClient,
  policySecond, policyThird, formerPolicyCommitment, signCompact);

const harness = new LocalTrustRegistryIntegrationHarness("governed-registry-demo");
const second = createMaintainerScenarioFixture("governed-demo-second");
const third = createMaintainerScenarioFixture("governed-demo-third");
const candidate = createMaintainerScenarioFixture("governed-demo-candidate");
const issuer = createIssuerScenarioFixture("governed-demo-issuer", IssuerResourceType.schema);
const verifier = createVerifierScenarioFixture("governed-demo-verifier");
const auditor = createAuditorScenarioFixture("governed-demo-auditor");
const recognitionAuthoritySeed = new Uint8Array(32).fill(116);
const recognitionAuthorityDid = createMidnightDid("governed-demo-recognition-authority");
const recognition = {
  ...createRecognitionScenarioFixture("governed-demo-recognition"),
  recognizedAuthorityDid: recognitionAuthorityDid,
  recognizedAuthorityDidCommitment: bytes32Commitment(recognitionAuthorityDid),
};
harness.authorizeMaintainer(second);
harness.authorizeMaintainer(third);
harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
const vcAuthoritySeed = new Uint8Array(32).fill(77);
const vcAuthorityDid = createMidnightDid("governed-demo-vc-authority");
const vcAuthorityAnchor = {
  domain: {
    networkId: issuer.subjectDid.split(":")[2],
    consumerContractAddress: `0x${sampleContractAddress()}`,
    registryId: harness.registryId,
    registryContractAddress: `0x${harness.simulator.contractAddress}`,
    authorityDid: vcAuthorityDid,
    authorityMethodId: `${vcAuthorityDid}#authority-1`,
  },
  publicKey: deriveJubjubPublicKeyFromSeed(vcAuthoritySeed),
};
const vcAuthorityKeyIdCommitment = bytes32Commitment("vc-authority:governed-demo");

const { verifiedRecognition, recognitionProposalEventHash } = await runGovernedRecognitionFlow(
  adversarialMatrix, {
    harness, recognition, recognitionAuthorityDid, recognitionAuthoritySeed,
    vcAuthorityAnchor, vcAuthorityKeyIdCommitment, second, third, signCompact,
  },
);
const applicantSpecs = [
  {
    role: "issuer",
    id: issuer.authorizationId,
    subjectDid: issuer.subjectDid,
    scope: createIssuerAuthorizationScopeFixture(issuer),
    governedResource: { type: "schema", id: issuer.resourceId },
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
const withAlteredProposalEvidence = (role, fixture, prepared, evidenceHash) => {
  const trustLevel = bytes32Commitment(fixture.trustLevel);
  const base = role === "issuer"
    ? computeCreateIssuerAuthorizationPayloadHash(
      fixture.authorizationIdCommitment, fixture.subjectDidCommitment,
      fixture.resourceType, fixture.resourceIdCommitment, prepared.policyCommitment,
      prepared.statusPolicyBindingCommitment, trustLevel, evidenceHash,
    )
    : role === "maintainer"
      ? computeCreateMaintainerMembershipPayloadHash(
        fixture.maintainerIdCommitment, fixture.subjectDidCommitment, fixture.keyId,
        deriveJubjubPublicKeyFromSeed(fixture.seed), prepared.policyCommitment,
        trustLevel, evidenceHash,
      )
      : (role === "verifier" ? computeCreateVerifierAuthorizationPayloadHash
        : computeCreateAuditorAuthorizationPayloadHash)(
        fixture.authorizationIdCommitment, fixture.subjectDidCommitment,
        fixture.requestResourceIdCommitment, fixture.allowedAttributeSetCommitment,
        fixture.allowedPredicateSetCommitment, fixture.disclosureLevelCommitment,
        prepared.policyCommitment, trustLevel, evidenceHash,
      );
  const bind = role === "issuer" ? computeIssuerEvidenceBoundProposalPayloadHash
    : role === "verifier" ? computeVerifierEvidenceBoundProposalPayloadHash
      : role === "auditor" ? computeAuditorEvidenceBoundProposalPayloadHash
        : computeMaintainerEvidenceBoundProposalPayloadHash;
  return {
    ...prepared,
    evidenceHash,
    actionPayloadHash: bind(base, prepared.evidenceVerifierAuthorizationId,
      prepared.evidenceVerifierKeyIdCommitment, prepared.policyCommitment, prepared.policyVersion),
  };
};
const submitRawProposal = (role, fixture, prepared, verifierSignature, signers) => {
  const [primary, ...coSigners] = signers;
  assert.ok(primary);
  const authorization = [primary.keyId, primary.publicKey, primary.signature];
  const verifier = [
    prepared.evidenceVerifierAuthorizationId,
    prepared.evidenceVerifierKeyIdCommitment,
    verifierSignature,
    coSigners,
  ];
  if (role === "issuer") {
    return harness.simulator.proposeIssuerAuthorization(
      ...authorization,
      fixture.authorizationIdCommitment,
      fixture.subjectDidCommitment,
      fixture.resourceType,
      fixture.resourceIdCommitment,
      prepared.policyCommitment,
      prepared.statusPolicyBindingCommitment,
      bytes32Commitment(fixture.trustLevel),
      prepared.evidenceHash,
      ...verifier,
    );
  }
  if (role === "maintainer") {
    return harness.simulator.proposeMaintainerMembership(
      ...authorization,
      fixture.maintainerIdCommitment,
      fixture.subjectDidCommitment,
      fixture.keyId,
      deriveJubjubPublicKeyFromSeed(fixture.seed),
      prepared.policyCommitment,
      bytes32Commitment(fixture.trustLevel),
      prepared.evidenceHash,
      ...verifier,
    );
  }
  assert.ok(role === "verifier" || role === "auditor");
  return harness.simulator[
    role === "verifier" ? "proposeVerifierAuthorization" : "proposeAuditorAuthorization"
  ](
    ...authorization,
    fixture.authorizationIdCommitment,
    fixture.subjectDidCommitment,
    fixture.requestResourceIdCommitment,
    fixture.allowedAttributeSetCommitment,
    fixture.allowedPredicateSetCommitment,
    fixture.disclosureLevelCommitment,
    prepared.policyCommitment,
    bytes32Commitment(fixture.trustLevel),
    prepared.evidenceHash,
    ...verifier,
  );
};
const assertFreshProposalCanExecute = (role, fixture, prepared, verifierSignature) => {
  const originalContext = harness.simulator.circuitContext;
  const originalCount = harness.simulator.getLedger().governanceActionCount;
  try {
    submitRawProposal(role, fixture, prepared, verifierSignature, [
      signCompact(second, prepared), signCompact(third, prepared),
    ]);
    assert.equal(harness.simulator.getLedger().governanceActionCount, originalCount + 1n);
  } finally {
    harness.simulator.circuitContext = originalContext;
  }
  assert.equal(harness.simulator.getLedger().governanceActionCount, originalCount);
};
const assertValidProposalVerifierSignature = (role, prepared, signature) => {
  const verifierKey = harness.simulator.getEvidenceVerifierKey(prepared.evidenceVerifierAuthorizationId);
  const verify = {
    issuer: verifyIssuerProposalEvidenceSignature,
    verifier: verifyVerifierProposalEvidenceSignature,
    auditor: verifyAuditorProposalEvidenceSignature,
    maintainer: verifyMaintainerProposalEvidenceSignature,
  }[role];
  assert.ok(verify, `Unknown proposal role: ${role}`);
  assert.equal(verify(
    verifierKey.publicKey, prepared.registryId, prepared.networkIdCommitment, prepared.contractAddress,
    prepared.evidenceVerifierKeyIdCommitment,
    prepared.actionPayloadHash, signature,
  ), true, `${role} substituted evidence-verifier signature must be valid`);
};
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
const decisionEvidenceByGrant = new Map();
const decisionContextByGrant = new Map();
const publishDecisionEvidence = (role, authorizationId, candidate, readers) => {
  decisionEvidenceByGrant.set(`${role}:${authorizationId}`, { buildInput: candidate.buildInput });
  decisionContextByGrant.set(`${role}:${authorizationId}`, { selection: candidate.selection, readers });
};
const readVerifiedDecisionEvidence = createVerifiedDecisionEvidenceSource({
  loadCandidate: async (role, authorizationId) =>
    decisionEvidenceByGrant.get(`${role}:${authorizationId}`) ?? null,
  trustedContextFor: async (role, authorizationId) =>
    decisionContextByGrant.get(`${role}:${authorizationId}`) ?? null,
});
const server = createTrustRegistryApiServer({
  source: { mode: "memory", loadSnapshot: async () => snapshot },
  readDecisionEvidence: readVerifiedDecisionEvidence,
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
      return bindings.get(applicationId)?.subjectDid;
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
  governedPolicyActions: {
    async prepareMaintainerRecovery(maintainerId, evidenceHash, value) {
      if (maintainerId !== asHex(candidate.maintainerIdCommitment)) {
        throw new GovernedPolicyActionRejectedError();
      }
      try {
        return harness.prepareAtomicMaintainerRecoveryAction(
          candidate, fromHex(evidenceHash), BigInt(value.default), BigInt(value.emergency), BigInt(value.archival),
        );
      } catch (error) {
        if (!(error instanceof CompactError || error instanceof AtomicMaintainerRecoveryPrecheckError)) {
          throw error;
        }
        throw new GovernedPolicyActionRejectedError();
      }
    },
    async executeMaintainerRecovery(maintainerId, evidenceHash, value, signers) {
      if (maintainerId !== asHex(candidate.maintainerIdCommitment)) {
        throw new GovernedPolicyActionRejectedError();
      }
      try {
        const eventHash = harness.executeAtomicMaintainerRecoveryWithSignatures(
          candidate, fromHex(evidenceHash), BigInt(value.default), BigInt(value.emergency), BigInt(value.archival), signers,
        );
        return { eventHash: asHex(eventHash) };
      } catch {
        throw new GovernedPolicyActionRejectedError();
      }
    },
    async prepareThresholds(value) {
      try {
        return harness.prepareThresholdPolicyRevisionAction(
          BigInt(value.default), BigInt(value.emergency), BigInt(value.archival),
        );
      } catch (error) {
        if (!(error instanceof CompactError)) throw error;
        throw new GovernedPolicyActionRejectedError();
      }
    },
    async executeThresholds(value, signers) {
      try {
        const eventHash = harness.executeThresholdPolicyRevisionWithSignatures(
          BigInt(value.default), BigInt(value.emergency), BigInt(value.archival), signers,
        );
        return { eventHash: asHex(eventHash) };
      } catch {
        throw new GovernedPolicyActionRejectedError();
      }
    },
    async prepareEvidenceVerifier() {
      return harness.prepareEvidenceVerifierRegistrationAction();
    },
    async executeEvidenceVerifier(signers) {
      try {
        const eventHash = harness.executeEvidenceVerifierRegistrationWithSignatures(signers);
        publishCurrentSnapshot();
        return { eventHash: asHex(eventHash) };
      } catch {
        throw new GovernedPolicyActionRejectedError();
      }
    },
  },
});

try {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address unavailable");
  const base = `http://127.0.0.1:${address.port}`;
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  let issuerVpFixture;
  let verifierVpFixture;
  const statusWitnessAuditedRoles = [];
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
    if (spec.role === "issuer") issuerVpFixture = proof;
    if (spec.role === "verifier") verifierVpFixture = proof;
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
    if (spec.role === "issuer") {
      const method = submission.presentation.presentationProof.signerVerificationMethodRef;
      await adversarialMatrix.expectHttp(await post("submissions", {
        ...submission,
        presentation: {
          ...submission.presentation,
          presentationProof: {
            ...submission.presentation.presentationProof,
            signerVerificationMethodRef: {
              ...method, methodId: changeLastHexNibble(method.methodId),
            },
          },
        },
      }), {
        id: "issuer-vp-holder-method-substitution",
        invariant: "A VP signer method reference cannot be changed after the holder signs",
        boundary: "api", status: 403, problemType: "application-vp-rejected",
      });
      assert.equal(persistedEvidence.has(applicationId), false);
    }
    // Recovery reads the accepted record; it must not repeat VP verification.
    assert.equal((await post("submissions", submission)).status, 202);
    const submitted = await expectHttp(await getReceipt(), 200);
    assert.equal(submitted.receipt.evidenceCommitment, submitted.evidence.commitment);
    assert.deepEqual(persistedEvidence.get(applicationId), submitted.evidence);
    assert.equal(JSON.stringify(submitted).includes(proof.input.submission.rawCredentialBody), false);
    assert.equal(JSON.stringify(submitted).includes(proof.input.submission.rawPresentationBody), false);
    const statusWitness = proof.readStatusWitness(challenge.challengeHash);
    assert.ok(statusWitness);
    const audit = {
      signed: statusWitness,
      expectedCommitment: submitted.evidence.envelope.statusDecisionCommitment,
      material: proof.material,
      binding: proof.fixtureStatusPolicyBinding,
      nonce: challenge.nonce,
      evaluatedAtMs: VP_FIXTURE_TIME_MS,
      resolver: proof.input.resolver,
    };
    assert.equal(await verifyApplicationStatusDecisionWitness(audit), true);
    statusWitnessAuditedRoles.push(spec.role);
    if (spec.role === "issuer") {
      await assert.rejects(verifyApplicationStatusDecisionWitness({
        ...audit,
        binding: {
          ...audit.binding,
          statusPolicyContentCommitment: sha256Hex("substituted-governed-status-policy"),
        },
      }), /does not match/u);
    }
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
  const issuerApplicationId = createScopedIdentifier("application", "issuer", issuer.authorizationId);
  const acceptedIssuerEvidence = persistedEvidence.get(issuerApplicationId);
  const acceptedIssuerReceipt = evidenceReceipts.get(issuerApplicationId);
  assert.ok(acceptedIssuerEvidence);
  assert.ok(acceptedIssuerReceipt);
  const expiredEnvelope = {
    ...issuerEvidence.envelope,
    expiresAt: new Date(Date.parse(issuerEvidence.envelope.verifiedAt) + 1).toISOString(),
  };
  const expiredCommitment = computeApplicationEvidenceCommitment(expiredEnvelope);
  const expiredIssuerEvidence = {
    envelope: expiredEnvelope,
    commitment: expiredCommitment,
    signature: harness.signApplicationEvidenceCommitment(expiredCommitment),
  };
  assert.equal(harness.verifyApplicationEvidenceSignature(
    expiredCommitment, expiredIssuerEvidence.signature, harness.evidenceVerifier,
  ), true);
  assert.ok(Date.parse(issuerEvidence.envelope.expiresAt) > Date.parse(expiredEnvelope.expiresAt) + 1000);
  harness.advanceEvidenceTimeBy(1000);
  adversarialMatrix.expectThrown(() => harness.prepareIssuerProposalAction(
    issuer, expiredIssuerEvidence, expectedIssuerEvidence,
  ), {
    id: "issuer-expired-evidence-api-preflight",
    invariant: "Accepted signed evidence cannot authorize a proposal after its expiry",
    boundary: "integration",
    messagePattern: /expired/iu,
    category: "expired-application-evidence",
  });
  persistedEvidence.set(issuerApplicationId, expiredIssuerEvidence);
  evidenceReceipts.set(issuerApplicationId, {
    ...acceptedIssuerReceipt,
    receiptId: sha256Hex(`receipt:${issuerApplicationId}:${expiredCommitment}`),
    evidenceCommitment: expiredCommitment,
  });
  try {
    await adversarialMatrix.expectHttp(await proposePrepare(proposalEndpoint, expiredIssuerEvidence), {
      id: "issuer-expired-accepted-evidence-api",
      invariant: "The governed API rejects an admitted issuer receipt when its signed evidence has expired",
      boundary: "api",
      status: 403,
      problemType: "governed-proposal-rejected",
    });
  } finally {
    persistedEvidence.set(issuerApplicationId, acceptedIssuerEvidence);
    evidenceReceipts.set(issuerApplicationId, acceptedIssuerReceipt);
  }
  for (const spec of applicantSpecs) {
    const endpoint = `${base}/v1/governed/${spec.role}/${spec.id}/proposal`;
    const applicationId = createScopedIdentifier("application", spec.role, spec.id);
    const evidence = evidenceByRole.get(spec.role);
    if (spec.role !== "issuer") {
      const originalEvidence = persistedEvidence.get(applicationId);
      const originalReceipt = evidenceReceipts.get(applicationId);
      const target = proposalTargets.get(spec.role);
      assert.ok(originalEvidence);
      assert.ok(originalReceipt);
      assert.ok(target);
      const shortLivedEnvelope = {
        ...originalEvidence.envelope,
        expiresAt: new Date(Date.parse(originalEvidence.envelope.verifiedAt) + 1).toISOString(),
      };
      const commitment = computeApplicationEvidenceCommitment(shortLivedEnvelope);
      const shortLivedEvidence = {
        envelope: shortLivedEnvelope,
        commitment,
        signature: harness.signApplicationEvidenceCommitment(commitment),
      };
      assert.equal(harness.verifyApplicationEvidenceSignature(
        commitment, shortLivedEvidence.signature, harness.evidenceVerifier,
      ), true);
      adversarialMatrix.expectThrown(() => target.prepare(shortLivedEvidence), {
        id: `${spec.role}-expired-evidence-api-preflight`,
        invariant: `Accepted signed evidence cannot authorize a ${spec.role} proposal after expiry`,
        boundary: "integration",
        messagePattern: /expired/iu,
        category: "expired-application-evidence",
      });
      persistedEvidence.set(applicationId, shortLivedEvidence);
      evidenceReceipts.set(applicationId, {
        ...originalReceipt,
        receiptId: sha256Hex(`receipt:${applicationId}:${commitment}`),
        evidenceCommitment: commitment,
      });
      try {
        await adversarialMatrix.expectHttp(await proposePrepare(endpoint, shortLivedEvidence), {
          id: `${spec.role}-expired-accepted-evidence-api`,
          invariant: `The governed API rejects admitted ${spec.role} evidence after expiry`,
          boundary: "api",
          status: 403,
          problemType: "governed-proposal-rejected",
        });
      } finally {
        persistedEvidence.set(applicationId, originalEvidence);
        evidenceReceipts.set(applicationId, originalReceipt);
      }
    }
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
    fromHex(proposalPrepared.networkIdCommitment),
    fromHex(proposalPrepared.contractAddress),
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
  const alteredProposalEvidenceHash = Uint8Array.from(compactIssuerProposal.evidenceHash);
  alteredProposalEvidenceHash[0] ^= 1;
  const alteredIssuerProposal = withAlteredProposalEvidence(
    "issuer", issuer, compactIssuerProposal, alteredProposalEvidenceHash,
  );
  const alteredIssuerVerifierSignature = harness.signIssuerProposalEvidence(alteredIssuerProposal);
  assertValidProposalVerifierSignature("issuer", alteredIssuerProposal, alteredIssuerVerifierSignature);
  const proposalPrimary = signCompact(second, compactIssuerProposal);
  const proposalCoSigner = signCompact(third, compactIssuerProposal);
  assertFreshProposalCanExecute("issuer", issuer, alteredIssuerProposal, alteredIssuerVerifierSignature);
  adversarialMatrix.expectThrown(() => submitRawProposal(
    "issuer", issuer, alteredIssuerProposal, alteredIssuerVerifierSignature,
    [proposalPrimary, proposalCoSigner],
  ), {
    id: "compact-issuer-proposal-altered-evidence-hash",
    invariant: "A valid quorum cannot reuse its signed issuer proposal with a substituted evidence commitment",
    boundary: "compact",
    messagePattern: /Invalid Jubjub Schnorr signature/u,
    category: "proposal-evidence-substitution-rejected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, actionCountBeforeWrongVerifier);
  const changedIssuerScope = {
    ...issuer, resourceIdCommitment: bytes32Commitment("credential-family:substituted:v1"),
  };
  const changedIssuerPrepared = withAlteredProposalEvidence(
    "issuer", changedIssuerScope, compactIssuerProposal, compactIssuerProposal.evidenceHash,
  );
  const changedIssuerVerifierSignature = harness.signIssuerProposalEvidence(changedIssuerPrepared);
  assertValidProposalVerifierSignature("issuer", changedIssuerPrepared, changedIssuerVerifierSignature);
  assertFreshProposalCanExecute("issuer", changedIssuerScope, changedIssuerPrepared,
    changedIssuerVerifierSignature);
  adversarialMatrix.expectThrown(() => submitRawProposal(
    "issuer", changedIssuerScope, changedIssuerPrepared, changedIssuerVerifierSignature,
    [proposalPrimary, proposalCoSigner],
  ), {
    id: "compact-issuer-proposal-scope-substitution",
    invariant: "Issuer proposal signatures cannot be reused for another credential family scope",
    boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
    category: "proposal-scope-substitution-rejected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, actionCountBeforeWrongVerifier);
  adversarialMatrix.expectThrown(() => harness.executeIssuerProposalWithSignatures(
    issuer, issuerEvidence, [proposalPrimary], verifierSignature, expectedIssuerEvidence,
  ), {
    id: "compact-issuer-proposal-insufficient-quorum",
    invariant: "Compact requires the active maintainer quorum for an issuer proposal",
    boundary: "compact",
    messagePattern: /Maintainer signer count must satisfy the action threshold/u,
    category: "proposal-quorum-rejected",
  });
  adversarialMatrix.expectThrown(() => harness.executeIssuerProposalWithSignatures(
    issuer, issuerEvidence, [proposalPrimary, proposalPrimary], verifierSignature, expectedIssuerEvidence,
  ), {
    id: "client-issuer-proposal-duplicate-signer",
    invariant: "The canonical bundle builder rejects a repeated maintainer before Compact execution",
    boundary: "client",
    messagePattern: /Maintainer authorization bundle contains a duplicate key ID/u,
    category: "proposal-duplicate-signer-rejected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, actionCountBeforeWrongVerifier);
  adversarialMatrix.expectThrown(() => harness.executeIssuerProposalWithSignatures(
    issuer,
    issuerEvidence,
    [proposalPrimary, proposalCoSigner],
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
  await adversarialMatrix.expectHttp(
    await submitProposal({ ...proposalBody, signers: [proposalBody.signers[0], proposalBody.signers[0]] }),
    {
      id: "issuer-proposal-duplicate-signer",
      invariant: "One maintainer cannot provide both signatures for an issuer proposal quorum",
      boundary: "api",
      status: 403,
      problemType: "invalid-governed-signature",
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
  const compactCoSigner = signCompact(third, compactApproval);
  const governanceActionsBeforeRejections = harness.simulator.getLedger().governanceActionCount;
  const alteredEvidenceHash = Uint8Array.from(compactApproval.evidenceHash);
  alteredEvidenceHash[0] ^= 1;
  adversarialMatrix.expectThrown(() => harness.simulator.authorizeIssuerAuthorization(
    compactSigner.keyId,
    compactSigner.publicKey,
    compactSigner.signature,
    issuer.authorizationIdCommitment,
    alteredEvidenceHash,
    [compactCoSigner],
  ), {
    id: "compact-issuer-altered-evidence-hash",
    invariant: "A signed approval cannot swap the proposed issuer evidence hash",
    boundary: "compact",
    messagePattern: /evidence|match/iu,
    category: "evidence-hash-mismatch",
  });
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
    id: "client-issuer-duplicate-signer",
    invariant: "The canonical bundle builder rejects a repeated issuer approval signer before Compact execution",
    boundary: "client",
    messagePattern: /Maintainer authorization bundle contains a duplicate key ID/u,
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
  const otherProposals = await runOtherGovernedProposals(adversarialMatrix, {
    proposalTargets, base, harness, second, third, verifier, auditor, candidate,
    sign, signCompact, withAlteredProposalEvidence, assertValidProposalVerifierSignature,
    assertFreshProposalCanExecute, submitRawProposal, expectHttp, asHex,
  });
  const decisions = [];
  const decisionSignerSets = new Map();
  let maintainerObservationEpochId;
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
      await adversarialMatrix.expectHttp(await submit(prepared, [signers[0], signers[0]]), {
        id: `${role}-${action}-duplicate-signer`,
        invariant: "The API rejects a duplicate maintainer key before governed execution",
        boundary: "api",
        status: 403,
        problemType: "invalid-governed-signature",
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
      if (action === "activate") {
        decisionSignerSets.set(role, signers.map((signer) => signer.keyId));
        if (role === "maintainer") {
          const epoch = snapshot.epochs.at(-1);
          assert.ok(epoch);
          maintainerObservationEpochId = epoch.epochId;
        }
      }
      await expectHttp(await submit(prepared, signers), 409);
      events[action] = accepted.eventHash;
    }
    decisions.push({ role, id: target.id, events });
  }

  let auditorMandate;
  const actorReportByRole = new Map();
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
      assert.throws(() => client.verifyIssuerAuthorizationBundle(bundle, {}),
        /does not contain issuer authorization/u);
      assert.throws(() => client.getCurrentMaintainerMembership(recognition.recognizedAuthorityDid),
        /not registered/u);
    } else {
      assert.equal(bundle.authorization.status, "active");
      if (role === "issuer") client.verifyIssuerAuthorizationBundle(bundle, {});
      if (role === "verifier") client.verifyVerifierAuthorizationBundle(bundle, {});
      if (role === "auditor") {
        client.verifyAuditorAuthorizationBundle(bundle, {});
        const scope = createAuditorAuthorizationScopeFixture(auditor);
        const options = {
          expectedRegistryId: harness.registryId,
          expectedSubjectDid: auditor.subjectDid,
          evaluationTime: bundle.generatedAt,
        };
        auditorMandate = client.verifyAuditorRequestMandate(bundle, scope, options);
        assert.throws(() => client.verifyAuditorRequestMandate(
          bundle, { ...scope, purpose: "unapproved-audit-purpose" }, options,
        ), /resource mismatch/u);
      }
    }
    assert.equal(bundle.policy.version, harness.policyRecord.version);
    actorReportByRole.set(role, {
      role,
      policyVersion: bundle.policy.version,
      epochId: bundle.epoch.epochId,
      epochSource: "active-evidence",
      activationSignerKeyIds: decisionSignerSets.get(role),
      expectedResult: "active",
      observedResult: role === "recognition" ? bundle.recognition.status : bundle.authorization.status,
    });
  }
  const maintainerRecord = harness.simulator.getCurrentMaintainerMembership(candidate.subjectDidCommitment);
  assert.equal(maintainerRecord.status, AuthorizationStatus.active);
  assert.ok(maintainerObservationEpochId);
  assert.ok(snapshot.epochs.some((epoch) => epoch.epochId === maintainerObservationEpochId));
  actorReportByRole.set("maintainer", {
    role: "maintainer",
    policyVersion: harness.policyRecord.version,
    epochId: maintainerObservationEpochId,
    epochSource: "membership-snapshot",
    activationSignerKeyIds: decisionSignerSets.get("maintainer"),
    expectedResult: "active",
    observedResult: AuthorizationStatus[maintainerRecord.status],
  });
  const actorOutcomes = [...targets.keys()].map((role) => {
    const result = actorReportByRole.get(role);
    assert.ok(result);
    assert.equal(result.activationSignerKeyIds.length, 2);
    assert.equal(result.observedResult, result.expectedResult);
    return result;
  });
  await runPublicLookupSafety(adversarialMatrix, { base, issuer, verifier, recognition, expectHttp });
  const { issuerBundle, verifierBundle, recognitionBundle, vcConsumer, verifierConsumer,
    trustedRecognitionEpoch } = await runGovernedConsumerEvidence(adversarialMatrix, {
    base, client, harness, issuer, verifier, recognition, issuerVpFixture, verifierVpFixture,
    vcAuthorityAnchor, vcAuthoritySeed, vcAuthorityKeyIdCommitment,
    verifiedRecognition, publishDecisionEvidence, expectHttp, changeLastHexNibble,
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
  adversarialMatrix.expectDecision(activeEvaluation, {
    id: "issuer-active-api",
    invariant: "Issuer trust is active at its committed activation instant",
    boundary: "api", trusted: true, statusAtTime: "active",
  });
  const trqpRequest = {
    entity_id: issuer.subjectDid,
    authority_id: harness.registryRecord.registryDid,
    action: "issue",
    resource: issuer.resourceId,
  };
  const queryTrqpIssuerAt = (at) => fetch(`${base}/v1/trqp/authorizations/query`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...trqpRequest, context: { time: at } }),
  });
  adversarialMatrix.expectDecision(await expectHttp(await queryTrqpIssuerAt(activeAt), 200), {
    id: "issuer-active-trqp",
    invariant: "TRQP and public API agree on issuer trust at activation",
    boundary: "adapter", trusted: activeEvaluation.trustedAtTime,
  });
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
  const trqpRecognitionRequest = {
    entity_id: recognition.recognizedAuthorityDid,
    authority_id: harness.registryDid,
    action: recognition.scopeResourceType,
    resource: recognition.scopeResourceId,
    context: {
      time: recognitionBundle.recognition.effectiveFrom,
      recognized_registry_id: recognition.recognizedRegistryId,
    },
  };
  const recognitionAdapter = new TrustRegistryTrqpAdapter({
    getRegistryRecord: async (authorityId) => authorityId === harness.registryDid
      ? harness.registryRecord : null,
    getAuthorizationDecision: async () => null,
    getRecognitionDecision: async (request) => request.entity_id === recognition.recognizedAuthorityDid
      && request.action === recognition.scopeResourceType
      && request.resource === recognition.scopeResourceId
      && request.context?.recognized_registry_id === recognition.recognizedRegistryId
      ? { bundle: recognitionBundle, statusAtTime: "active", trustedAtTime: true }
      : null,
  }, { clock: () => recognitionBundle.recognition.effectiveFrom });
  const recognized = await recognitionAdapter.queryRecognition(trqpRecognitionRequest);
  assert.equal(recognized.ok, true);
  const recognitionTrqpEvidence = await recognitionAdapter.getRecognitionEvidence(trqpRecognitionRequest);
  assert.equal(recognitionTrqpEvidence.ok, true);
  assert.equal(recognitionTrqpEvidence.value.bundle.recognition.evidenceHash,
    verifiedRecognition.evidenceCommitment);
  adversarialMatrix.expectAdapterProblem(await recognitionAdapter.queryRecognition({
    ...trqpRecognitionRequest,
    context: { ...trqpRecognitionRequest.context, recognized_registry_id: "registry:external:wrong:v1" },
  }), {
    id: "trqp-wrong-recognized-registry",
    invariant: "A recognition for one external registry cannot authorize a different registry",
    status: 404,
    problemType: "not-found",
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

  const issuerTemporal = await runIssuerTemporalLifecycle(adversarialMatrix, {
    base, harness, issuer, candidate, client, issuerVpFixture,
    publishSnapshot: () => { snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot); },
    vcAuthorityAnchor, vcAuthoritySeed, vcAuthorityKeyIdCommitment, vcConsumer,
    issuerBundle, activeAt, evaluateIssuerAt, queryTrqpIssuerAt, expectHttp,
  });
  const { candidateCoSignedProposal, suspendedConsumer, revokedConsumer,
    suspendedEvaluation, revokedEvaluation, historicalAfterSuspension,
    historicalAfterRevocation, revokedBundle } = issuerTemporal;

  const { temporalChecks, verifierLifecycle } = await runOtherTemporalLifecycles(adversarialMatrix, {
    base, harness, verifier, auditor, recognition, client, expectHttp,
    trustedRecognitionEpoch, verifierVpFixture, vcAuthorityAnchor,
    vcAuthoritySeed, vcAuthorityKeyIdCommitment, verifierConsumer,
    publishSnapshot: () => { snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot); },
  });

  const { policyVersionBeforeRevision, revisionReceipt, registrationReceipt, recoveryReceipt,
    recoveryRegistrationReceipt, suspendedMaintainerEventHash, remainingQuorumEventHash } =
    await runGovernedPolicyRecovery(adversarialMatrix, {
      base, harness, second, third, candidate, sign, expectHttp, publishCurrentSnapshot, asHex,
    });

  const matrixReport = adversarialMatrix.report();
  process.stdout.write(`${JSON.stringify({
    mode: "Compact simulator fixture; not network finality",
    registryId: harness.registryId,
    governance: "2-of-3 external JubJub signatures; HTTP-revised to 3-of-4, then atomically reduced to 2-of-3 with target suspension",
    acceptedVpRecovery: "issuer, verifier, auditor, and maintainer recovered by authenticated receipt lookup",
    statusWitnessAudit: {
      roles: statusWitnessAuditedRoles,
      substitutedIssuerPolicyRejected: true,
      mode: "private fixture witness and DID resolver; not network finality",
    },
    issuerProposal: {
      eventHash: issuerProposal.eventHash,
      evidenceCommitment: issuerEvidence.commitment,
      source: "authenticated VP HTTP intake and governed HTTP proposal",
    },
    proposalDenial: {
      deniedAuthorizationId: deniedIssuer.authorizationId,
      denialEventHash: asHex(denialEventHash),
      historicalStatus: deniedBundle.authorization.status,
      currentTrust: false,
      replacementAuthorizationId: replacementIssuer.authorizationId,
      replacementProposalEventHash: asHex(replacementProposalEventHash),
      replacementStatus: "proposed",
      source: "quorum-signed Compact archival; local simulator, not network finality",
    },
    otherProposals,
    recognitionProposal: {
      eventHash: asHex(recognitionProposalEventHash),
      evidenceCommitment: verifiedRecognition.evidenceCommitment,
      authorityDidStateVersionId: verifiedRecognition.authority.didStateVersionId,
      accreditorDidStateVersionId: verifiedRecognition.accreditation.accreditorDidStateVersionId,
      anchorCommitment: verifiedRecognition.accreditation.anchorCommitment,
      governedPolicyCommitment: asHex(harness.simulator.getLedger().governancePolicyCommitment),
      governedPolicyVersion: harness.policyRecord.version,
      statusDecisionCommitment: verifiedRecognition.accreditation.statusDecisionCommitment,
      oneUseChallengeConsumed: true,
      source: "Midnight DID authority assertion and independent accreditor VC/VP verified; local evidence verifier is fixture-held",
      accreditation: "signed VC/VP and challenge-bound status attestation with quorum-governed anchor; attestation is fixture-fetched, not live status-ledger evidence",
      expectedRejections: ["wrong-external-registry", "tampered-authority-signature", "stale-governed-anchor-policy", "inactive-accreditation-status", "substituted-vp", "challenge-replay", "one-maintainer"],
    },
    decisions,
    actorReport: buildActorEvidenceReport(actorOutcomes, matrixReport),
    activeEvidence: "issuer, verifier, auditor, and recognition independently verified",
    auditorMandate,
    vcConsumer: vcConsumer.report,
    vcConsumerLifecycle: [suspendedConsumer.report, revokedConsumer.report],
    verifierConsumer: verifierConsumer.report,
    verifierConsumerLifecycle: verifierLifecycle,
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
    maintainerLifecycle: {
      policyVersionBeforeRevision: policyVersionBeforeRevision.toString(),
      policyVersionAfterRevision: harness.simulator.getLedger().governancePolicyVersion.toString(),
      thresholdRevisionEventHash: revisionReceipt.eventHash,
      atomicRecoveryEventHash: recoveryReceipt.eventHash,
      recoveryEvidenceVerifierRegistrationEventHash: recoveryRegistrationReceipt.eventHash,
      evidenceVerifierRegistrationEventHash: registrationReceipt.eventHash,
      suspendedMaintainerEventHash,
      remainingActiveMaintainers: harness.simulator.getLedger().activeMaintainerCount.toString(),
      remainingQuorumEventHash: asHex(remainingQuorumEventHash),
    },
    expectedRejections: [
      "vp-unauthorized:403", "vp-wrong-signed-scope:403", "vp-unbound-credential:403",
      "vp-revoked-fixture-status:403", "vp-challenge-replay:404",
      "proposal-cross-role-evidence:403", "proposal-wrong-target:403",
      "proposal-missing-receipt:403", "proposal-substituted-pending-target:403",
      "denied-proposal-blocks-live-scope-reuse:compact", "denied-proposal-requires-quorum:compact",
      "denied-proposal-is-not-trust:client",
      "proposal-one-signer:403", "proposal-replay:409", "decision-one-signer:403",
      "candidate-self-vote:403", "replayed-context:409", "cross-role:404",
      "recognition-is-not-local-issuer-or-maintainer:client",
      "revised-threshold-rejects-two-signers:simulator",
      "policy-revision-one-signer:403", "policy-revision-stale-replay:409",
      "new-policy-registration-two-signers:403",
      "suspended-maintainer-cannot-vote:simulator",
      "wrong-scope:404", "wrong-registry:client", "expired-epoch:client",
      "suspended:client", "revoked:client",
    ],
    adversarialMatrix: matrixReport,
  }, null, 2)}\n`);
  assert.equal(matrixReport.summary.total, expectedAdversarialCaseCount,
    "Governed demo adversarial case count changed without a parity review");
  adversarialMatrix.assertAllPassed();
} finally {
  await new Promise((resolve) => server.close(resolve));
}
