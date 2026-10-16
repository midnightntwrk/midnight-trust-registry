import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { sampleContractAddress } from "@midnight-ntwrk/compact-runtime";
import { signJubjubDigestFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";

import {
  verifyGovernedIssuerCredential,
  verifyGovernedIssuerStatusUpdate,
  verifyGovernedVerifierRequest,
  verifyGovernedVerifierStatusUpdate,
} from "./demo-vc-issuer-consumer.mjs";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signIssuerProposalEvidenceFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { AuthorizationStatus } from "../contracts/trust-registry/dist/managed/trust-registry/contract/index.js";
import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import {
  bytes32Commitment,
  createVerifiedDecisionEvidenceSource,
  defaultSequenceToTimestamp,
  verifyHistoricalRecognitionEvidenceFromApi,
  verifyHistoricalRecognitionEvidenceResponse,
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
  createRecognitionAccreditationVpScenarioFixture,
  RECOGNITION_VP_FIXTURE_ANCHOR,
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
  resolveCompactHistoricalEpochAnchor,
  recognitionAuthorityAssertionDigest,
  recognitionAccreditationSubmissionCommitment,
  VP_FIXTURE_NONCE,
  VP_FIXTURE_TIME_MS,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  InMemoryApplicationChallengeStore,
  RecognitionAuthorityChallengeService,
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
import { TrustRegistryTrqpAdapter, verifyTrqpRecognitionEvidenceFromApi } from "../adapters/trqp/dist/index.js";

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
const signCompact = (maintainer, prepared, sourceHarness = harness) => {
  const ledger = sourceHarness.simulator.getLedger();
  return {
    keyId: maintainer.keyId,
    publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
    signature: signDeploymentBoundMaintainerActionFromSeed(
      maintainer.seed,
      ledger.registryId,
      ledger.deploymentNetworkIdCommitment,
      Buffer.from(sourceHarness.simulator.contractAddress, "hex"),
      ledger.governancePolicyCommitment,
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
  id: "compact-self-voted-maintainer-suspension",
  invariant: "A maintainer cannot vote to suspend its own DID",
  boundary: "compact",
  messagePattern: /own DID/iu,
  category: "conflicted-maintainer-vote-rejected",
});
adversarialMatrix.expectThrown(() => lastActiveHarness.revokeMaintainer(bootstrapMembership), {
  id: "compact-self-voted-maintainer-revocation",
  invariant: "A maintainer cannot vote to revoke its own DID",
  boundary: "compact",
  messagePattern: /own DID/iu,
  category: "conflicted-maintainer-vote-rejected",
});
assert.equal(lastActiveHarness.simulator.getLedger().activeMaintainerCount, 1n);
assert.equal(lastActiveHarness.simulator.getLedger().governanceActionCount, lastActiveActionCount);
const thresholdSecond = createMaintainerScenarioFixture("governed-demo-threshold-second");
const thresholdThird = createMaintainerScenarioFixture("governed-demo-threshold-third");
lastActiveHarness.authorizeMaintainer(thresholdSecond);
lastActiveHarness.authorizeMaintainer(thresholdThird);
lastActiveHarness.updateMaintainerThresholdPolicy(2n, 1n, 1n, [thresholdSecond]);
const thresholdRemoval = lastActiveHarness.prepareMaintainerDecisionAction(bootstrapMembership, "suspend");
const thresholdActionCount = lastActiveHarness.simulator.getLedger().governanceActionCount;
adversarialMatrix.expectThrown(() => lastActiveHarness.executeMaintainerDecisionWithSignatures(
  bootstrapMembership, "suspend", [signCompact(thresholdSecond, thresholdRemoval, lastActiveHarness)],
), {
  id: "compact-removal-below-maintainer-threshold",
  invariant: "A non-conflicted signer cannot remove a maintainer into an all-member quorum",
  boundary: "compact",
  messagePattern: /non-conflicted removal quorum/iu,
  category: "maintainer-threshold-protected",
});
assert.equal(lastActiveHarness.simulator.getLedger().activeMaintainerCount, 3n);
assert.equal(lastActiveHarness.simulator.getLedger().governanceActionCount, thresholdActionCount);

const removedSignerHarness = new LocalTrustRegistryIntegrationHarness("governed-demo-removed-signer");
const removedSigner = createMaintainerScenarioFixture("governed-demo-removed-signer");
const removedSignerIssuer = createIssuerScenarioFixture("governed-demo-removed-signer-issuer");
removedSignerHarness.authorizeMaintainer(removedSigner);
removedSignerHarness.suspendMaintainer(removedSigner);
removedSignerHarness.proposeIssuer(removedSignerIssuer);
const removedSignerApproval = removedSignerHarness.prepareIssuerDecisionAction(removedSignerIssuer, "approve");
const removedSignerActionCount = removedSignerHarness.simulator.getLedger().governanceActionCount;
adversarialMatrix.expectThrown(() => removedSignerHarness.executeIssuerDecisionWithSignatures(
  removedSignerIssuer, "approve", [signCompact(removedSigner, removedSignerApproval, removedSignerHarness)],
), {
  id: "compact-removed-maintainer-signer",
  invariant: "A suspended maintainer key cannot approve a new issuer",
  boundary: "compact",
  messagePattern: /active|authorized|maintainer|signature|assert/iu,
  category: "removed-signer-rejected",
});
assert.equal(removedSignerHarness.simulator.getLedger().governanceActionCount, removedSignerActionCount);

const denialHarness = new LocalTrustRegistryIntegrationHarness("governed-demo-denial");
const denialSecond = createMaintainerScenarioFixture("governed-demo-denial-second");
const denialThird = createMaintainerScenarioFixture("governed-demo-denial-third");
const deniedIssuer = createIssuerScenarioFixture("governed-demo-denied-issuer");
const replacementIssuer = {
  ...deniedIssuer,
  authorizationId: `${deniedIssuer.authorizationId}:replacement`,
  authorizationIdCommitment: bytes32Commitment(`${deniedIssuer.authorizationId}:replacement`),
};
denialHarness.authorizeMaintainer(denialSecond);
denialHarness.authorizeMaintainer(denialThird);
denialHarness.proposeIssuer(deniedIssuer);
adversarialMatrix.expectThrown(() => denialHarness.proposeIssuer(replacementIssuer), {
  id: "denied-proposal-blocks-live-scope-reuse",
  invariant: "A second application cannot claim the same scope while a proposal remains live",
  boundary: "compact",
  messagePattern: /live authorization/iu,
  category: "duplicate-live-scope-rejected",
});
denialHarness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
const denialPrepared = denialHarness.prepareIssuerDecisionAction(deniedIssuer, "archive");
const denialActionCount = denialHarness.simulator.getLedger().governanceActionCount;
adversarialMatrix.expectThrown(() => denialHarness.executeIssuerDecisionWithSignatures(
  deniedIssuer, "archive", [signCompact(denialSecond, denialPrepared, denialHarness)],
), {
  id: "denied-proposal-requires-quorum",
  invariant: "Archiving a pending issuer proposal requires the current maintainer quorum",
  boundary: "compact",
  messagePattern: /threshold|quorum|signer|authorization/iu,
  category: "insufficient-archive-quorum",
});
assert.equal(denialHarness.simulator.getLedger().governanceActionCount, denialActionCount);
const denialEventHash = denialHarness.executeIssuerDecisionWithSignatures(
  deniedIssuer, "archive", [signCompact(denialSecond, denialPrepared, denialHarness), signCompact(denialThird, denialPrepared, denialHarness)],
);
assert.equal(denialHarness.simulator.getIssuerAuthorization(deniedIssuer.authorizationIdCommitment).status,
  AuthorizationStatus.archived);
const deniedBundle = denialHarness.buildIssuerHistoricalEvidence(deniedIssuer);
assert.equal(deniedBundle.authorization?.status, "archived");
assert.equal(deniedBundle.authorization?.authorizedAt, undefined);
assert.equal(deniedBundle.authorization?.activeFrom, undefined);
adversarialMatrix.expectThrown(() => new TrustRegistrySimulatorClient(denialHarness.simulator)
  .verifyIssuerAuthorizationBundle(deniedBundle, {}), {
  id: "denied-proposal-is-not-trust",
  invariant: "Historical evidence for an archived proposal cannot authorize a current issuer",
  boundary: "client",
  messagePattern: /not active/iu,
  category: "archived-issuer-not-active",
});
const replacementProposalEventHash = denialHarness.proposeIssuer(replacementIssuer, [denialSecond]);
assert.equal(denialHarness.simulator.getIssuerAuthorization(replacementIssuer.authorizationIdCommitment).status,
  AuthorizationStatus.proposed);
assert.equal(denialHarness.simulator.getIssuerAuthorization(deniedIssuer.authorizationIdCommitment).status,
  AuthorizationStatus.archived);

const evidenceHarness = new LocalTrustRegistryIntegrationHarness("governed-demo-evidence-boundaries");
const policyIdIssuer = createIssuerScenarioFixture("governed-demo-wrong-policy-id");
const expiringIssuer = createIssuerScenarioFixture("governed-demo-expired-evidence");
const policyIdEvidence = evidenceHarness.createApplicationEvidence({
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
  signature: evidenceHarness.signApplicationEvidenceCommitment(wrongPolicyCommitment),
};
assert.equal(evidenceHarness.verifyApplicationEvidenceSignature(
  wrongPolicyEvidence.commitment,
  wrongPolicyEvidence.signature,
  evidenceHarness.evidenceVerifier,
), true);
const evidenceActionsBeforeRejections = evidenceHarness.simulator.getLedger().governanceActionCount;
adversarialMatrix.expectThrown(() => evidenceHarness.proposeIssuerWithApplicationEvidence(
  policyIdIssuer, wrongPolicyEvidence,
), {
  id: "issuer-signed-wrong-policy-id",
  invariant: "Even validly signed applicant evidence cannot substitute another governance policy ID",
  boundary: "integration",
  messagePattern: /policyId does not match/iu,
  category: "policy-id-mismatch",
});
const expiringEvidence = evidenceHarness.createApplicationEvidence({
  applicationId: expiringIssuer.authorizationId,
  subjectDid: expiringIssuer.subjectDid,
  role: "issuer",
  scope: createIssuerAuthorizationScopeFixture(expiringIssuer),
  governedResource: { type: "credentialFamily", id: expiringIssuer.resourceId },
});
evidenceHarness.advanceEvidenceTimeBy(24 * 60 * 60 * 1000 + 1);
adversarialMatrix.expectThrown(() => evidenceHarness.proposeIssuerWithApplicationEvidence(
  expiringIssuer, expiringEvidence,
), {
  id: "issuer-expired-signed-application-evidence",
  invariant: "A validly signed evidence receipt expires before a later governed transition",
  boundary: "integration",
  messagePattern: /evidence is expired/iu,
  category: "expired-application-evidence",
});
assert.equal(evidenceHarness.simulator.getLedger().governanceActionCount, evidenceActionsBeforeRejections);

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
const oldPolicySignature = signCompact(policySecond, oldPolicyAction, policyHarness);
const oldPolicyCoSignature = signCompact(policyThird, oldPolicyAction, policyHarness);
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
adversarialMatrix.expectThrown(() => policyClient.verifyIssuerAuthorizationBundle({
  ...historicalPolicyBundle,
  inclusionProof: {
    ...historicalPolicyBundle.inclusionProof,
    path: [changeLastHexNibble(historicalPolicyBundle.inclusionProof.path[0])],
  },
}, {}), {
  id: "issuer-historical-proof-tampered-after-policy-revision",
  invariant: "A threshold revision cannot make a tampered old-policy Merkle proof valid",
  boundary: "client",
  messagePattern: /event sibling/iu,
  category: "historical-merkle-path-rejected",
});
const historicalEpochSignature = historicalPolicyBundle.epoch.maintainerSignatures[0];
assert.ok(historicalEpochSignature);
const alteredEpochSignature = `0x${historicalEpochSignature.signature[2] === "0" ? "1" : "0"}${historicalEpochSignature.signature.slice(3)}`;
adversarialMatrix.expectThrown(() => policyClient.verifyIssuerAuthorizationBundle({
  ...historicalPolicyBundle,
  epoch: {
    ...historicalPolicyBundle.epoch,
    maintainerSignatures: [{ ...historicalEpochSignature, signature: alteredEpochSignature }],
  },
}, {}), {
  id: "issuer-historical-epoch-signature-tampered",
  invariant: "A policy revision cannot make a forged historical epoch signature valid",
  boundary: "client",
  messagePattern: /invalid/iu,
  category: "historical-epoch-signature-rejected",
});

const harness = new LocalTrustRegistryIntegrationHarness("governed-registry-demo");
const second = createMaintainerScenarioFixture("governed-demo-second");
const third = createMaintainerScenarioFixture("governed-demo-third");
const candidate = createMaintainerScenarioFixture("governed-demo-candidate");
const issuer = createIssuerScenarioFixture("governed-demo-issuer");
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

const recognitionMethodId = `${recognitionAuthorityDid}#assertion-1`;
const recognitionChallengeBinding = {
  targetRegistryId: harness.registryId,
  recognitionId: recognition.recognitionId,
  authorityDid: recognitionAuthorityDid,
  recognizedRegistryId: recognition.recognizedRegistryId,
  scopeResourceType: recognition.scopeResourceType,
  scopeResourceId: recognition.scopeResourceId,
};
const recognitionAnchor = {
  ...RECOGNITION_VP_FIXTURE_ANCHOR,
  targetRegistryId: harness.registryId,
  policyId: harness.policyId,
  policyVersion: `v${(harness.simulator.getLedger().governancePolicyVersion + 1n).toString()}`,
  recognizedRegistryId: recognition.recognizedRegistryId,
  scopeResourceType: recognition.scopeResourceType,
  scopeResourceId: recognition.scopeResourceId,
};
harness.governRecognitionAccreditorAnchor(recognitionAnchor, [second]);
harness.registerVcAuthorityKey({
  domain: vcAuthorityAnchor.domain,
  keyIdCommitment: vcAuthorityKeyIdCommitment,
  publicKey: vcAuthorityAnchor.publicKey,
});
harness.advanceEvidenceTimeBy(60_000);
const recognitionEvaluationMs = Math.max(
  VP_FIXTURE_TIME_MS, Date.parse(harness.policyRecord.effectiveFrom) + 60_000,
);
const governedRecognitionAnchor = harness.resolveCurrentRecognitionAccreditorAnchor({
  recognizedRegistryId: recognition.recognizedRegistryId,
  scopeResourceType: recognition.scopeResourceType,
  scopeResourceId: recognition.scopeResourceId,
  evaluatedAtMs: recognitionEvaluationMs,
});
const recognitionChallengeService = new RecognitionAuthorityChallengeService(
  new InMemoryApplicationChallengeStore(), () => recognitionEvaluationMs,
);
const recognitionChallenge = await recognitionChallengeService.issue(recognitionChallengeBinding);
const recognitionChallengeHash = recognitionChallenge.challengeHash;
const recognitionAccreditationFixture = await createRecognitionAccreditationVpScenarioFixture({
  nonce: recognitionChallenge.nonce,
  evaluatedAtMs: recognitionEvaluationMs,
  authorityDid: recognitionAuthorityDid,
  authorityAssertionSeed: recognitionAuthoritySeed,
  anchor: governedRecognitionAnchor.anchor,
});
const recognitionStatement = {
  version: "tr-recognition-authority-assertion-v1",
  ...recognitionChallengeBinding,
  accreditationSubmissionCommitment: recognitionAccreditationSubmissionCommitment(
    recognitionAccreditationFixture.input.submission,
  ),
  challengeHash: recognitionChallengeHash,
  issuedAt: new Date(recognitionEvaluationMs).toISOString(),
  expiresAt: new Date(recognitionEvaluationMs + 50 * 60_000).toISOString(),
};
const recognitionAssertion = {
  statement: recognitionStatement,
  proof: {
    verificationMethodId: recognitionMethodId,
    algorithm: "jubjub-schnorr",
    signature: asHex(encodeJubjubSignature(signJubjubDigestFromSeed(
      recognitionAuthoritySeed,
      recognitionAuthorityAssertionDigest(recognitionStatement, recognitionMethodId),
    ))),
  },
};
const verifyRecognitionChallenge = (signed, overrides = {}) => recognitionChallengeService.verifyAndConsumeAccreditedAssertion({
  binding: recognitionChallengeBinding,
  nonce: recognitionChallenge.nonce,
  signed,
  accreditation: recognitionAccreditationFixture.input.submission,
  readCurrentGovernance: async () => ({
    governancePolicy: harness.policyRecord,
    activePolicyCommitment: asHex(harness.simulator.getLedger().governancePolicyCommitment),
  }),
  resolver: recognitionAccreditationFixture.input.resolver,
  statusSource: recognitionAccreditationFixture.input.statusSource,
  ...overrides,
});
const recognitionSequenceBefore = harness.simulator.getLedger().governanceActionCount;
await assert.rejects(verifyRecognitionChallenge({
  ...recognitionAssertion,
  statement: { ...recognitionStatement, recognizedRegistryId: "registry:external:wrong:v1" },
}), /does not match/u);
await assert.rejects(verifyRecognitionChallenge({
  ...recognitionAssertion,
  proof: {
    ...recognitionAssertion.proof,
    signature: asHex(encodeJubjubSignature(signJubjubDigestFromSeed(
      recognitionAuthoritySeed,
      recognitionAuthorityAssertionDigest({
        ...recognitionStatement,
        scopeResourceId: "credential-family:wrong:v1",
      }, recognitionMethodId),
    ))),
  },
}), /signature is invalid/u);
await assert.rejects(verifyRecognitionChallenge(recognitionAssertion, {
  readCurrentGovernance: async () => ({
    governancePolicy: harness.policyRecord,
    activePolicyCommitment: sha256Hex("stale-recognition-policy"),
  }),
}), /active governed policy/u);
await assert.rejects(verifyRecognitionChallenge(recognitionAssertion, {
  statusSource: {
    verifyPinnedStatus: async (request) => ({
      ...await recognitionAccreditationFixture.input.statusSource.verifyPinnedStatus(request),
      active: false,
    }),
  },
}), /status is not active/u);
await assert.rejects(verifyRecognitionChallenge(recognitionAssertion, {
  accreditation: {
    ...recognitionAccreditationFixture.input.submission,
    rawCredentialBody: `${recognitionAccreditationFixture.input.submission.rawCredentialBody} `,
  },
}), /submitted accreditation VP/u);
assert.equal(harness.simulator.getLedger().governanceActionCount, recognitionSequenceBefore);
const verifiedRecognition = await verifyRecognitionChallenge(recognitionAssertion);
await assert.rejects(verifyRecognitionChallenge(recognitionAssertion), /already consumed/u);
const recognitionPrepared = harness.prepareRecognitionProposalAction(
  recognition, fromHex(verifiedRecognition.evidenceCommitment),
);
assert.equal(asHex(recognitionPrepared.evidenceHash), verifiedRecognition.evidenceCommitment);
const recognitionEvidenceSignature = harness.signRecognitionProposalEvidence(recognitionPrepared);
const recognitionSigners = [
  signCompact(second, recognitionPrepared), signCompact(third, recognitionPrepared),
];
const proposeRecognitionWithChangedScope = (registryIdCommitment, resourceIdCommitment) =>
  harness.simulator.proposeRecognition(
    recognitionSigners[0].keyId,
    recognitionSigners[0].publicKey,
    recognitionSigners[0].signature,
    recognition.recognitionIdCommitment,
    recognition.recognizedAuthorityDidCommitment,
    registryIdCommitment,
    recognition.scopeResourceTypeCommitment,
    resourceIdCommitment,
    recognitionPrepared.policyCommitment,
    bytes32Commitment(recognition.trustLevel),
    recognitionPrepared.evidenceHash,
    recognitionPrepared.evidenceVerifierAuthorizationId,
    recognitionPrepared.evidenceVerifierKeyIdCommitment,
    recognitionEvidenceSignature,
    recognitionSigners.slice(1),
  );
adversarialMatrix.expectThrown(() => proposeRecognitionWithChangedScope(
  bytes32Commitment("registry:external:substituted:v1"), recognition.scopeResourceIdCommitment,
), {
  id: "compact-recognition-external-registry-substitution",
  invariant: "A recognition quorum signature cannot be reused for another external registry",
  boundary: "compact", messagePattern: /signature|payload/iu,
  category: "recognition-scope-signature-rejected",
});
adversarialMatrix.expectThrown(() => proposeRecognitionWithChangedScope(
  recognition.recognizedRegistryIdCommitment, bytes32Commitment("credential-family:substituted:v1"),
), {
  id: "compact-recognition-resource-substitution",
  invariant: "A recognition quorum signature cannot be reused for another resource scope",
  boundary: "compact", messagePattern: /signature|payload/iu,
  category: "recognition-scope-signature-rejected",
});
assert.equal(harness.simulator.getLedger().governanceActionCount, recognitionSequenceBefore);
assert.throws(() => harness.executeRecognitionProposalWithSignatures(
  recognition,
  recognitionSigners.slice(0, 1),
  recognitionEvidenceSignature,
  recognitionPrepared,
), /action threshold/u);
const recognitionProposalEventHash = harness.executeRecognitionProposalWithSignatures(
  recognition,
  recognitionSigners,
  recognitionEvidenceSignature,
  recognitionPrepared,
);
assert.equal(asHex(harness.simulator.getRecognitionProposalEvidence(
  recognition.recognitionIdCommitment,
).evidenceCommitment), verifiedRecognition.evidenceCommitment);
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
    async prepareThresholds(value) {
      return harness.prepareThresholdPolicyRevisionAction(
        BigInt(value.default), BigInt(value.emergency), BigInt(value.archival),
      );
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
    await adversarialMatrix.expectHttp(await submit({ ...body, signers: body.signers.slice(0, 1) }), {
      id: `${role}-proposal-insufficient-quorum`,
      invariant: `A ${role} proposal requires the active maintainer quorum`,
      boundary: "api", status: 403, problemType: "governed-proposal-rejected",
    });
    await adversarialMatrix.expectHttp(await submit({ ...body, signers: [body.signers[0], body.signers[0]] }), {
      id: `${role}-proposal-duplicate-signer`,
      invariant: `One maintainer cannot provide both signatures for a ${role} proposal quorum`,
      boundary: "api", status: 403, problemType: "invalid-governed-signature",
    });
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
  await expectHttp(await fetch(
    `${base}/v1/governed/issuer/${recognition.recognitionId}/actions/approve`,
  ), 404);
  await adversarialMatrix.expectHttp(await fetch(`${base}/v1/authorizations/resolve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      role: "issuer", subjectDid: issuer.subjectDid,
      resourceId: createIssuerScenarioFixture("wrong-scope").resourceId,
    }),
  }), {
    id: "issuer-wrong-resource-api",
    invariant: "The public lookup cannot substitute another issuer credential-family scope",
    boundary: "api",
    status: 404,
    problemType: "authorization-not-found",
  });
  await adversarialMatrix.expectHttp(await fetch(`${base}/v1/authorizations/resolve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      role: "verifier", subjectDid: verifier.subjectDid,
      resourceId: createVerifierScenarioFixture("wrong-scope").scopeResourceId,
    }),
  }), {
    id: "verifier-wrong-resource-api",
    invariant: "The public lookup cannot substitute another verifier request-profile scope",
    boundary: "api",
    status: 404,
    problemType: "authorization-not-found",
  });
  await adversarialMatrix.expectHttp(await fetch(`${base}/v1/recognitions/resolve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      recognizedAuthorityDid: recognition.recognizedAuthorityDid,
      recognizedRegistryId: "registry:external:wrong:v1",
      scopeResourceType: recognition.scopeResourceType,
      scopeResourceId: recognition.scopeResourceId,
    }),
  }), {
    id: "recognition-wrong-external-registry-api",
    invariant: "The public lookup cannot substitute a different recognized external registry",
    boundary: "api",
    status: 404,
    problemType: "recognition-not-found",
  });
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
    harness,
    issuer,
    apiBundle: issuerBundle,
    applicantVp: issuerVpFixture,
    authorityAnchor: vcAuthorityAnchor,
    authoritySeed: vcAuthoritySeed,
    authorityKeyIdCommitment: vcAuthorityKeyIdCommitment,
    apiBase: base,
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
  assert.ok(verifierVpFixture);
  const verifierConsumer = await verifyGovernedVerifierRequest({
    harness,
    verifier,
    scope: createVerifierAuthorizationScopeFixture(verifier),
    apiBundle: verifierBundle,
    applicantVp: verifierVpFixture,
    authorityAnchor: vcAuthorityAnchor,
    authoritySeed: vcAuthoritySeed,
    authorityKeyIdCommitment: vcAuthorityKeyIdCommitment,
    apiBase: base,
    publishDecisionEvidence,
  });
  const verifierDecision = await expectHttp(await fetch(
    `${base}/v1/decision-evidence/verifier/${encodeURIComponent(verifier.authorizationId)}`,
  ), 200);
  assert.equal(verifierDecision.verification, "client-required");
  assert.equal(verifierDecision.evidence.grant.authorizationId, verifier.authorizationId);
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
  const locallyVerifiedRecognition = harness.evaluateCurrentRecognitionDecision(recognition);
  const trustedRecognitionEpoch = {
    epochId: locallyVerifiedRecognition.epoch.epochId,
    policyVersion: locallyVerifiedRecognition.policy.version,
  };
  assert.equal(recognitionBundle.epoch.epochId, trustedRecognitionEpoch.epochId);
  assert.equal(recognitionBundle.recognition.evidenceHash, verifiedRecognition.evidenceCommitment);
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

  const candidateCoSignedProposal = harness.proposeIssuer(
    createIssuerScenarioFixture("governed-demo-candidate-proposal"), [candidate],
  );
  harness.suspendIssuer(issuer);
  snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
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
  snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
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
    snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
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
    snapshot = publishSimulatorSnapshot(harness, fixtures, snapshot);
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

  const policyVersionBeforeRevision = harness.simulator.getLedger().governancePolicyVersion;
  const policyEndpoint = `${base}/v1/governed/policy`;
  const postPolicy = (path, body) => fetch(`${policyEndpoint}/${path}`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  const thresholds = { default: "3", emergency: "1", archival: "2" };
  const revisionContext = await expectHttp(await postPolicy("thresholds/prepare", { thresholds }), 200);
  await adversarialMatrix.expectHttp(await postPolicy("thresholds/submit", {
    thresholds, prepared: revisionContext, signers: [sign(second, revisionContext)],
  }), {
    id: "policy-revision-one-signer",
    invariant: "Old-policy quorum is required for threshold revision",
    boundary: "api", status: 403, problemType: "governed-policy-rejected",
  });
  const revisionReceipt = await expectHttp(await postPolicy("thresholds/submit", {
    thresholds, prepared: revisionContext,
    signers: [sign(second, revisionContext), sign(third, revisionContext)],
  }), 202);
  await adversarialMatrix.expectHttp(await postPolicy("thresholds/submit", {
    thresholds, prepared: revisionContext,
    signers: [sign(second, revisionContext), sign(third, revisionContext)],
  }), {
    id: "policy-revision-stale-replay",
    invariant: "A consumed old-policy context cannot revise governance twice",
    boundary: "api", status: 409, problemType: "stale-governed-policy",
  });
  assert.equal(harness.simulator.getLedger().governancePolicyVersion, policyVersionBeforeRevision + 1n);
  const threeSignerIssuer = createIssuerScenarioFixture("governed-demo-three-signer-issuer");
  assert.throws(() => harness.proposeIssuer(threeSignerIssuer, [second, third]),
    /policy|evidence|verifier|active|registered|signature|assert/iu);
  const registrationContext = await expectHttp(await postPolicy("evidence-verifier/prepare", {}), 200);
  await adversarialMatrix.expectHttp(await postPolicy("evidence-verifier/submit", {
    prepared: registrationContext,
    signers: [sign(second, registrationContext), sign(third, registrationContext)],
  }), {
    id: "new-policy-registration-two-signers",
    invariant: "New-policy quorum is required to register the evidence verifier",
    boundary: "api", status: 403, problemType: "governed-policy-rejected",
  });
  const registrationReceipt = await expectHttp(await postPolicy("evidence-verifier/submit", {
    prepared: registrationContext,
    signers: [sign(second, registrationContext), sign(third, registrationContext), sign(candidate, registrationContext)],
  }), 202);
  assert.throws(() => harness.proposeIssuer(threeSignerIssuer, [second]), /action threshold/u);
  harness.proposeIssuer(threeSignerIssuer, [second, third]);
  const removalSequence = harness.simulator.getLedger().governanceActionCount;
  adversarialMatrix.expectThrown(() => harness.suspendMaintainer(candidate), {
    id: "compact-recovery-policy-reduction-required",
    invariant: "A maintainer removal cannot leave an all-member quorum",
    boundary: "compact",
    messagePattern: /non-conflicted removal quorum/iu,
    category: "maintainer-recovery-protected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, removalSequence);
  const recoveryThresholds = { default: "2", emergency: "1", archival: "2" };
  const recoveryContext = await expectHttp(await postPolicy("thresholds/prepare", {
    thresholds: recoveryThresholds,
  }), 200);
  const recoveryRevisionReceipt = await expectHttp(await postPolicy("thresholds/submit", {
    thresholds: recoveryThresholds,
    prepared: recoveryContext,
    signers: [sign(second, recoveryContext), sign(third, recoveryContext), sign(candidate, recoveryContext)],
  }), 202);
  const recoveryRegistrationContext = await expectHttp(await postPolicy("evidence-verifier/prepare", {}), 200);
  const recoveryRegistrationReceipt = await expectHttp(await postPolicy("evidence-verifier/submit", {
    prepared: recoveryRegistrationContext,
    signers: [sign(second, recoveryRegistrationContext), sign(third, recoveryRegistrationContext)],
  }), 202);
  const suspendedMaintainerEventHash = harness.suspendMaintainer(candidate);
  assert.equal(harness.simulator.getLedger().activeMaintainerCount, 3n);
  const postSuspensionIssuer = createIssuerScenarioFixture("governed-demo-post-suspension-issuer");
  assert.throws(() => harness.proposeIssuer(postSuspensionIssuer, [candidate, second]),
    /Maintainer must be active/u);
  const remainingQuorumEventHash = harness.proposeIssuer(postSuspensionIssuer, [second, third]);

  process.stdout.write(`${JSON.stringify({
    mode: "Compact simulator fixture; not network finality",
    registryId: harness.registryId,
    governance: "2-of-3 external JubJub signatures; HTTP-revised to 3-of-4, then reduced to 2-of-4 before removal",
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
    actorReport: buildActorEvidenceReport(actorOutcomes, adversarialMatrix.report()),
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
      recoveryPolicyRevisionEventHash: recoveryRevisionReceipt.eventHash,
      recoveryEvidenceVerifierRegistrationEventHash: recoveryRegistrationReceipt.eventHash,
      evidenceVerifierRegistrationEventHash: registrationReceipt.eventHash,
      suspendedMaintainerEventHash: asHex(suspendedMaintainerEventHash),
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
    adversarialMatrix: adversarialMatrix.report(),
  }, null, 2)}\n`);
} finally {
  await new Promise((resolve) => server.close(resolve));
}
