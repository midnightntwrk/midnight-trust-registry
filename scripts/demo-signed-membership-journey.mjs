import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  encodeJubjubSignature,
  payloadToJubjubDigest,
  signJubjubDigest,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature as encodeGovernanceSignature,
  AuthorizationStatus,
  signPolicyBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";

import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import {
  defaultSequenceToTimestamp,
  verifyHistoricalAuthorizationEvidenceFromApi,
  verifyHistoricalAuthorizationEvidenceResponse,
} from "../packages/trust-registry-client/dist/index.js";
import { publishSimulatorSnapshot, TrustRegistryOperatorWorkspaceSchema } from "../packages/trust-registry-cli/dist/index.js";
import {
  computeAuthorizationScopeCommitment,
  computePendingApplicationPayloadCommitment,
  createScopedIdentifier,
  mutationIntentDigestBytes,
  requestGovernedResourceId,
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
  createVerifierAuthorizationScopeFixture,
  createVerifierScenarioFixture,
  bytes32Commitment,
  LocalTrustRegistryIntegrationHarness,
  resolveCompactHistoricalEpochAnchor,
  VP_FIXTURE_NONCE,
  VP_FIXTURE_TIME_MS,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  computeOperatorWorkspaceCommitment,
  createTrustRegistryApiServer,
  GovernedAuditorProposalRejectedError,
  GovernedIssuerProposalRejectedError,
  GovernedMaintainerProposalRejectedError,
  GovernedMembershipActionRejectedError,
  GovernedEpochPublicationRejectedError,
  GovernedVerifierProposalRejectedError,
  FileApplicationAdmissionStore,
  FileApplicationChallengeStore,
} from "../packages/trust-registry-api/dist/index.js";
import { TrustRegistryAdminConsoleClient } from "../packages/trust-registry-admin-console/dist/api.js";
import { TrustRegistryApplicantPortalClient } from "../packages/trust-registry-applicant-portal/dist/api.js";
import { verifyTrqpAuthorizationEvidenceFromApi } from "../adapters/trqp/dist/index.js";

const role = process.argv[2];
if (role !== "issuer" && role !== "verifier" && role !== "auditor" && role !== "maintainer") {
  throw new Error("Expected issuer, verifier, auditor, or maintainer journey");
}
const label = `signed-${role}-journey`;
const now = new Date(VP_FIXTURE_TIME_MS);
const asHex = (value) => `0x${Buffer.from(value).toString("hex")}`;
const fromHex = (value) => Buffer.from(value.slice(2), "hex");
const harness = new LocalTrustRegistryIntegrationHarness(label);
const maintainers = [
  createMaintainerScenarioFixture(`${label}-first`),
  createMaintainerScenarioFixture(`${label}-second`),
];
for (const maintainer of maintainers) harness.authorizeMaintainer(maintainer);
harness.updateMaintainerThresholdPolicy(2n, 2n, 2n);
const activeMaintainersBeforeApplication = harness.simulator.getLedger().activeMaintainerCount;
const profiles = {
  issuer: () => {
    const fixture = createIssuerScenarioFixture(label);
    return {
      fixture, id: fixture.authorizationId, idCommitment: fixture.authorizationIdCommitment,
      scope: createIssuerAuthorizationScopeFixture(fixture), resourceId: fixture.resourceId,
      resourceType: "credentialFamily", snapshotKey: "issuers", proposalPort: "governedIssuerProposals",
      rejected: GovernedIssuerProposalRejectedError,
      prepareProposal: (evidence, expected) => harness.prepareIssuerProposalAction(fixture, evidence, expected),
      executeProposal: (evidence, signers, signature, expected) =>
        harness.executeIssuerProposalWithSignatures(fixture, evidence, signers, signature, expected),
      getProposalEvidence: () => harness.simulator.getIssuerProposalEvidence(fixture.authorizationIdCommitment),
      getStatusRecord: () => harness.simulator.getIssuerAuthorization(fixture.authorizationIdCommitment),
      signProposalEvidence: (prepared) => harness.signIssuerProposalEvidence(prepared),
      prepareDecision: (action) => harness.prepareIssuerDecisionAction(fixture, action),
      executeDecision: (action, signers) => harness.executeIssuerDecisionWithSignatures(fixture, action, signers),
      verifyBundle: (client, bundle, options) => client.verifyIssuerAuthorizationBundle(bundle, options),
    };
  },
  verifier: () => {
    const fixture = createVerifierScenarioFixture(label);
    return {
      fixture, id: fixture.authorizationId, idCommitment: fixture.authorizationIdCommitment,
      scope: createVerifierAuthorizationScopeFixture(fixture), resourceId: fixture.scopeResourceId,
      resourceType: "requestProfile", snapshotKey: "verifiers", proposalPort: "governedVerifierProposals",
      rejected: GovernedVerifierProposalRejectedError,
      prepareProposal: (evidence, expected) => harness.prepareVerifierProposalAction(fixture, evidence, expected),
      executeProposal: (evidence, signers, signature, expected) =>
        harness.executeVerifierProposalWithSignatures(fixture, evidence, signers, signature, expected),
      getProposalEvidence: () => harness.simulator.getVerifierProposalEvidence(fixture.authorizationIdCommitment),
      getStatusRecord: () => harness.simulator.getVerifierAuthorization(fixture.authorizationIdCommitment),
      signProposalEvidence: (prepared) => harness.signVerifierProposalEvidence(prepared),
      prepareDecision: (action) => harness.prepareVerifierDecisionAction(fixture, action),
      executeDecision: (action, signers) => harness.executeVerifierDecisionWithSignatures(fixture, action, signers),
      verifyBundle: (client, bundle, options) => client.verifyVerifierAuthorizationBundle(bundle, options),
    };
  },
  auditor: () => {
    const fixture = createAuditorScenarioFixture(label);
    return {
      fixture, id: fixture.authorizationId, idCommitment: fixture.authorizationIdCommitment,
      scope: createAuditorAuthorizationScopeFixture(fixture), resourceId: fixture.scopeResourceId,
      resourceType: "requestProfile", snapshotKey: "auditors", proposalPort: "governedAuditorProposals",
      rejected: GovernedAuditorProposalRejectedError,
      prepareProposal: (evidence, expected) => harness.prepareAuditorProposalAction(fixture, evidence, expected),
      executeProposal: (evidence, signers, signature, expected) =>
        harness.executeAuditorProposalWithSignatures(fixture, evidence, signers, signature, expected),
      getProposalEvidence: () => harness.simulator.getAuditorProposalEvidence(fixture.authorizationIdCommitment),
      getStatusRecord: () => harness.simulator.getAuditorAuthorization(fixture.authorizationIdCommitment),
      signProposalEvidence: (prepared) => harness.signAuditorProposalEvidence(prepared),
      prepareDecision: (action) => harness.prepareAuditorDecisionAction(fixture, action),
      executeDecision: (action, signers) => harness.executeAuditorDecisionWithSignatures(fixture, action, signers),
      verifyBundle: (client, bundle, options) => client.verifyAuditorAuthorizationBundle(bundle, options),
    };
  },
  maintainer: () => {
    const fixture = createMaintainerScenarioFixture(label);
    return {
      fixture, id: fixture.maintainerId, idCommitment: fixture.maintainerIdCommitment,
      scope: createMaintainerAuthorizationScopeFixture(harness.registryId), resourceId: harness.registryId,
      resourceType: "registry", snapshotKey: null, proposalPort: "governedMaintainerProposals",
      rejected: GovernedMaintainerProposalRejectedError,
      prepareProposal: (evidence, expected) => harness.prepareMaintainerProposalAction(fixture, evidence, expected),
      executeProposal: (evidence, signers, signature, expected) =>
        harness.executeMaintainerProposalWithSignatures(fixture, evidence, signers, signature, expected),
      getProposalEvidence: () => harness.simulator.getMaintainerProposalEvidence(fixture.maintainerIdCommitment),
      signProposalEvidence: (prepared) => harness.signMaintainerProposalEvidence(prepared),
      prepareDecision: (action) => harness.prepareMaintainerDecisionAction(fixture, action),
      executeDecision: (action, signers) => harness.executeMaintainerDecisionWithSignatures(fixture, action, signers),
      verifyBundle: null,
    };
  },
};
const profile = profiles[role]();
const participant = profile.fixture;
const scope = profile.scope;
const resourceId = profile.resourceId;
const governedResource = { type: profile.resourceType, id: resourceId };
const applicationId = createScopedIdentifier("application", role, profile.id);
let snapshot = publishSimulatorSnapshot(harness, { label });
const workspaceForSnapshot = () => TrustRegistryOperatorWorkspaceSchema.parse({
  workspaceVersion: "1",
  updatedAt: snapshot.generatedAt,
  registryLabel: label,
  operations: [],
  consumedMutationNonces: [],
  snapshot,
});

const fixtureOptions = {
  subjectDid: participant.subjectDid,
  evidenceVerifierDid: harness.evidenceVerifier.did,
  evidenceVerifierMethodId: harness.evidenceVerifier.keyIds[0].split("#")[1],
  scope,
};
const resolverFixture = await createApplicationVpScenarioFixture(VP_FIXTURE_NONCE, fixtureOptions);
const signingPorts = await createApplicationVpIntakePorts({
  resolver: resolverFixture.input.resolver,
  family: resolverFixture.input.family,
  signer: resolverFixture.signer,
});
const stateDirectory = await mkdtemp(join(tmpdir(), `tr-signed-${role}-`));
const admissionPath = join(stateDirectory, "admission.json");
const registration = new FileApplicationAdmissionStore(
  admissionPath, harness.evidenceVerifier.did, resolverFixture.input.resolver,
  async () => workspaceForSnapshot(),
);
let withholdAcceptedReceipt = false;
const token = randomBytes(32).toString("hex");
const authorized = (request) => {
  const supplied = request.headers.authorization?.replace(/^Bearer /u, "");
  return typeof supplied === "string" && supplied.length === token.length
    && timingSafeEqual(Buffer.from(supplied), Buffer.from(token));
};
const admission = {
  resolvePendingApplication: (id) => registration.resolvePendingApplication(id),
  resolveAcceptedEvidence: (id) => withholdAcceptedReceipt
    ? Promise.resolve(null) : registration.resolveAcceptedEvidence(id),
};
const signAction = (maintainer, prepared) => {
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
    signature: asHex(encodeGovernanceSignature(signature)),
  };
};
const quorumSignatures = (prepared) => maintainers.map((maintainer) => signAction(maintainer, prepared));
let currentProof;
let acceptedChallengeHash;
const expectedEvidence = () => {
  if (acceptedChallengeHash === undefined) throw new Error("No accepted application challenge");
  return { scope, challengeHash: acceptedChallengeHash, governedResource };
};
const server = createTrustRegistryApiServer({
  source: { mode: "memory", loadSnapshot: async () => snapshot },
  clock: () => now.toISOString(),
  pendingApplicationRegistration: registration,
  proposalAdmission: admission,
  [profile.proposalPort]: {
    async prepare(id, evidence) {
      if (id !== profile.id) throw new profile.rejected("unknown-authorization");
      try {
        return profile.prepareProposal(evidence, expectedEvidence());
      } catch {
        throw new profile.rejected("invalid-evidence");
      }
    },
    async execute(id, evidence, signers, verifierSignature) {
      if (id !== profile.id) throw new profile.rejected("unknown-authorization");
      try {
        const eventHash = profile.executeProposal(evidence, signers, verifierSignature, expectedEvidence());
        return { eventHash: asHex(eventHash) };
      } catch {
        throw new profile.rejected("invalid-signers");
      }
    },
    async resolve(id) {
      if (id !== profile.id) throw new profile.rejected("unknown-authorization");
      const record = profile.getProposalEvidence();
      return {
        eventHash: asHex(record.proposalGovernanceEventHash),
        evidenceCommitment: asHex(record.evidenceCommitment),
      };
    },
  },
  governedMembershipActions: {
    async prepare(actionRole, id, action) {
      if (actionRole !== role || id !== profile.id) {
        throw new GovernedMembershipActionRejectedError("unknown-authorization");
      }
      return profile.prepareDecision(action);
    },
    async execute(actionRole, id, action, signers) {
      if (actionRole !== role || id !== profile.id) {
        throw new GovernedMembershipActionRejectedError("unknown-authorization");
      }
      try {
        const eventHash = profile.executeDecision(action, signers);
        return { eventHash: asHex(eventHash) };
      } catch {
        throw new GovernedMembershipActionRejectedError("invalid-signers");
      }
    },
  },
  governedEpochPublication: {
    async prepare(epochLabel) {
      return harness.prepareRegistryEpochPublicationAction(epochLabel);
    },
    async execute(epochLabel, signers) {
      let epoch;
      try {
        epoch = harness.executeRegistryEpochPublicationWithSignatures(epochLabel, signers);
      } catch {
        throw new GovernedEpochPublicationRejectedError();
      }
      snapshot = publishSimulatorSnapshot(harness, {
        label,
        ...(profile.snapshotKey !== null ? {
          [profile.snapshotKey]: [{ label: `joined-${role}`, fixture: participant }],
        } : {}),
      }, snapshot, epoch);
      assert.equal(asHex(harness.simulator.getCurrentEpochCommitment().epochId),
        asHex(bytes32Commitment(snapshot.currentEpoch.epochId)));
      return { epoch, eventHash: harness.getEpochPublicationWitness(epoch.epochId).eventHash };
    },
  },
  authorizePendingApplicationRegistration: async (request) => {
    if (!authorized(request)) throw new Error("Applicant bearer token required");
  },
  applicationVp: {
    challengeStore: new FileApplicationChallengeStore(join(stateDirectory, "challenges.json")),
    authorizeRequest: async (id, request) => {
      if (!authorized(request) || (await registration.readPending(id))?.binding.subjectDid !== participant.subjectDid) {
        throw new Error("Applicant bearer token denied");
      }
    },
    resolvePendingApplication: async (id) => {
      const pending = await registration.readPending(id);
      return pending === null || await registration.resolveAcceptedEvidence(id) !== null ? null : {
        binding: pending.binding,
        authorizedVerifiers: [harness.evidenceVerifier],
      };
    },
    verifyPresentation: async (presentation, context) => {
      if (currentProof === undefined) throw new Error("VP proof not supplied");
      const ports = await createApplicationVpIntakePorts({
        resolver: currentProof.input.resolver,
        family: currentProof.input.family,
        signer: currentProof.signer,
      });
      return ports.verifyPresentation(presentation, context);
    },
    signEvidence: signingPorts.signEvidence,
    verifyEvidenceSignature: signingPorts.verifyEvidenceSignature,
    persistRedactedEvidence: (id, evidence) => registration.acceptEvidence(id, evidence, now),
    resolveAcceptedEvidence: (id) => registration.resolveAcceptedEvidence(id),
  },
});

const signedApplication = () => {
  const intent = {
    version: "tr-mutation-intent-v1",
    registryId: harness.registryId,
    actorDid: participant.subjectDid,
    actorKeyId: `${participant.subjectDid}#auth-1`,
    actorRole: "applicant",
    action: "apply",
    target: role,
    targetId: applicationId,
    scopeCommitment: computeAuthorizationScopeCommitment(scope),
    payloadCommitment: computePendingApplicationPayloadCommitment({
      applicationId, authorizationId: profile.id, scope, governedResource,
    }),
    nonce: `0x${"22".repeat(32)}`,
    expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(workspaceForSnapshot()),
    expectedEpochId: snapshot.currentEpoch.epochId,
    issuedAt: new Date(VP_FIXTURE_TIME_MS - 60_000).toISOString(),
    expiresAt: new Date(VP_FIXTURE_TIME_MS + 60_000).toISOString(),
  };
  return {
    applicationId,
    authorizationId: profile.id,
    scope,
    governedResource,
    intent,
    signature: {
      keyId: intent.actorKeyId,
      algorithm: "jubjub-schnorr",
      value: `0x${Buffer.from(encodeJubjubSignature(signJubjubDigest(
        23n, payloadToJubjubDigest(mutationIntentDigestBytes(intent)),
      ))).toString("hex")}`,
    },
  };
};

const expectHttp = async (response, status) => {
  const payload = await response.json();
  assert.equal(response.status, status, JSON.stringify(payload));
  return payload;
};

try {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address unavailable");
  const base = `http://127.0.0.1:${address.port}`;
  const authenticatedFetch = (input, init = {}) => fetch(input, {
    ...init,
    headers: { ...init.headers, authorization: `Bearer ${token}` },
  });
  const applicantClient = new TrustRegistryApplicantPortalClient(base, authenticatedFetch);
  const adminClient = new TrustRegistryAdminConsoleClient(base, authenticatedFetch);
  const publishedEpochIds = [];
  const trustedEpochsByPhase = new Map();
  const publishGovernedEpoch = async (phase) => {
    const epochLabel = `${role}-${phase}`;
    const locallyPrepared = harness.prepareRegistryEpochPublicationAction(epochLabel);
    const policyVersion = `v${harness.simulator.getLedger().governancePolicyVersion.toString()}`;
    const prepared = await adminClient.prepareGovernedEpoch(epochLabel);
    assert.equal(prepared.epochId, locallyPrepared.epochId);
    const before = harness.simulator.getLedger().governanceActionCount;
    const publishPath = "/v1/governed/epochs/publish";
    assert.equal((await post(publishPath, {
      label: epochLabel, prepared, signers: [signAction(maintainers[0], prepared)],
    })).status, 403);
    assert.equal((await post(publishPath, {
      label: epochLabel,
      prepared,
      signers: [signAction(maintainers[0], prepared), signAction(maintainers[0], prepared)],
    })).status, 403);
    assert.equal((await post(publishPath, {
      label: `${epochLabel}-other`, prepared, signers: quorumSignatures(prepared),
    })).status, 409);
    assert.equal((await post(publishPath, {
      label: epochLabel,
      prepared: { ...prepared, actionSequence: (BigInt(prepared.actionSequence) + 1n).toString() },
      signers: quorumSignatures(prepared),
    })).status, 409);
    assert.equal(harness.simulator.getLedger().governanceActionCount, before);
    const receipt = await adminClient.submitGovernedEpoch({
      label: epochLabel, prepared, signers: quorumSignatures(prepared),
    });
    assert.equal(receipt.epoch.epochId, prepared.epochId);
    const published = await expectHttp(await fetch(
      `${base}/v1/epochs/${encodeURIComponent(receipt.epoch.epochId)}`,
    ), 200);
    assert.equal(published.epochId, receipt.epoch.epochId);
    publishedEpochIds.push(receipt.epoch.epochId);
    if (profile.getStatusRecord !== undefined) {
      const { lastStatusSequence } = profile.getStatusRecord();
      trustedEpochsByPhase.set(phase, {
        epochId: createScopedIdentifier("epoch", harness.registryId, `seq-${lastStatusSequence.toString()}`),
        policyVersion,
      });
    }
  };
  const post = (path, body, withToken = true) => fetch(`${base}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(withToken ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const getPrivate = (path, withToken = true) => fetch(`${base}${path}`, {
    headers: withToken ? { authorization: `Bearer ${token}` } : {},
  });

  const application = signedApplication();
  assert.equal((await post("/v1/pending-applications", application, false)).status, 403);
  assert.equal((await post("/v1/pending-applications", {
    ...application, authorizationId: `auth:${role}:substituted:v1`,
  })).status, 400);
  const pending = await applicantClient.registerPendingApplication(application);
  assert.equal(pending.authorizationId, profile.id);
  assert.equal(pending.binding.applicationId, applicationId);
  assert.equal(pending.binding.scopeCommitment, computeAuthorizationScopeCommitment(scope));
  assert.equal((await post("/v1/pending-applications", application)).status, 409);

  const evidencePath = `/v1/application-evidence/${applicationId}`;
  const binding = await applicantClient.loadPendingApplicationBinding(applicationId);
  assert.equal(binding.applicationId, applicationId);
  assert.equal(binding.subjectDid, participant.subjectDid);
  assert.deepEqual(binding.scope, scope);
  assert.equal(binding.scopeCommitment, computeAuthorizationScopeCommitment(scope));
  assert.deepEqual(binding.governedResource, governedResource);
  assert.equal((await post(`${evidencePath}/challenges`, {}, false)).status, 403);
  const challenge = await applicantClient.issueApplicationChallenge(applicationId);
  assert.equal((await getPrivate(`${evidencePath}/receipt`, false)).status, 403);
  assert.equal((await getPrivate(`${evidencePath}/receipt`)).status, 404);
  acceptedChallengeHash = challenge.challengeHash;
  currentProof = await createApplicationVpScenarioFixture(challenge.nonce, fixtureOptions);
  const submission = {
    nonce: challenge.nonce,
    challengeHash: challenge.challengeHash,
    presentation: currentProof.input.submission,
  };
  // The accepted VP response is intentionally lost; recover without reusing the challenge.
  await applicantClient.submitApplicationPresentation(applicationId, challenge, submission.presentation);
  const submitted = await applicantClient.loadAcceptedApplicationEvidence(applicationId);
  assert.equal(submitted.receipt.evidenceCommitment, submitted.evidence.commitment);
  assert.equal(JSON.stringify(submitted).includes(currentProof.input.submission.rawCredentialBody), false);
  const reopened = new FileApplicationAdmissionStore(
    admissionPath, harness.evidenceVerifier.did, resolverFixture.input.resolver,
    async () => workspaceForSnapshot(),
  );
  assert.deepEqual(await reopened.resolveAcceptedEvidence(applicationId), submitted);
  assert.equal((await readFile(admissionPath, "utf8")).includes(currentProof.input.submission.rawCredentialBody), false);
  assert.equal((await post(`${evidencePath}/submissions`, submission)).status, 404);
  assert.equal((await post(`${evidencePath}/challenges`, {})).status, 404);

  harness.advanceEvidenceTimeBy(60_000);
  const proposalPath = `/v1/governed/${role}/${profile.id}/proposal`;
  assert.equal((await post(
    `/v1/governed/${role}/auth:${role}:substituted:v1/proposal/prepare`,
    { evidence: submitted.evidence },
  )).status, 403);
  withholdAcceptedReceipt = true;
  assert.equal((await post(`${proposalPath}/prepare`, { evidence: submitted.evidence })).status, 403);
  withholdAcceptedReceipt = false;
  const preparedProposal = await adminClient.prepareProposal(role, profile.id, submitted.evidence);
  const verifierSignature = profile.signProposalEvidence(
    profile.prepareProposal(submitted.evidence, expectedEvidence()),
  );
  const proposalBody = {
    evidence: submitted.evidence,
    prepared: preparedProposal,
    signers: quorumSignatures(preparedProposal),
    evidenceVerifierSignature: asHex(encodeGovernanceSignature(verifierSignature)),
  };
  withholdAcceptedReceipt = true;
  assert.equal((await post(`${proposalPath}/submit`, proposalBody)).status, 403);
  withholdAcceptedReceipt = false;
  const beforeProposal = harness.simulator.getLedger().governanceActionCount;
  assert.equal((await post(`${proposalPath}/submit`, {
    ...proposalBody, signers: [signAction(maintainers[0], preparedProposal)],
  })).status, 403);
  assert.equal(harness.simulator.getLedger().governanceActionCount, beforeProposal);
  assert.equal((await post(`${proposalPath}/submit`, {
    ...proposalBody,
    signers: [signAction(maintainers[0], preparedProposal), signAction(maintainers[0], preparedProposal)],
  })).status, 403);
  if (role === "maintainer") {
    assert.equal((await post(`${proposalPath}/submit`, {
      ...proposalBody,
      signers: [signAction(maintainers[0], preparedProposal), signAction(participant, preparedProposal)],
    })).status, 403);
  }
  assert.equal(harness.simulator.getLedger().governanceActionCount, beforeProposal);
  // Discard the response body to exercise recovery after a client loses its submit receipt.
  await adminClient.submitProposal(role, profile.id, proposalBody);
  withholdAcceptedReceipt = true;
  assert.equal((await post(`${proposalPath}/resolve`, { evidence: submitted.evidence })).status, 403);
  withholdAcceptedReceipt = false;
  const proposal = await adminClient.resolveProposal(role, profile.id, submitted.evidence);
  assert.equal(proposal.state, "observed");
  assert.equal(proposal.eventHash, asHex(profile.getProposalEvidence().proposalGovernanceEventHash));
  assert.equal((await post(`${proposalPath}/submit`, proposalBody)).status, 409);

  const beforePremature = harness.simulator.getLedger().governanceActionCount;
  const premature = await adminClient.prepareGovernedAction(role, profile.id, "activate");
  const earlyActivation = await post(`/v1/governed/${role}/${profile.id}/actions/activate`, {
    prepared: premature,
    signers: quorumSignatures(premature),
  });
  assert.equal(earlyActivation.status, 403);
  assert.match((await earlyActivation.json()).type, /governed-action-rejected$/u);
  assert.equal(harness.simulator.getLedger().governanceActionCount, beforePremature);

  for (const action of ["approve", "activate"]) {
    const actionPath = `/v1/governed/${role}/${profile.id}/actions/${action}`;
    const prepared = await adminClient.prepareGovernedAction(role, profile.id, action);
    const beforeAction = harness.simulator.getLedger().governanceActionCount;
    const stale = await post(actionPath, {
      prepared: { ...prepared, actionSequence: (BigInt(prepared.actionSequence) + 1n).toString() },
      signers: quorumSignatures(prepared),
    });
    assert.equal(stale.status, 409);
    assert.match((await stale.json()).type, /stale-governed-action$/u);
    assert.equal(harness.simulator.getLedger().governanceActionCount, beforeAction);
    assert.equal((await post(actionPath, {
      prepared, signers: [signAction(maintainers[0], prepared)],
    })).status, 403);
    if (role === "maintainer") {
      assert.equal((await post(actionPath, {
        prepared, signers: [signAction(maintainers[0], prepared), signAction(participant, prepared)],
      })).status, 403);
    }
    assert.equal(harness.simulator.getLedger().governanceActionCount, beforeAction);
    await adminClient.submitGovernedAction(role, profile.id, action, {
      prepared, signers: quorumSignatures(prepared),
    });
    if (action === "activate") await publishGovernedEpoch(action);
  }

  let trustResult;
  let lifecycleResult = null;
  if (role === "maintainer") {
    const membership = harness.simulator.getMaintainerMembership(profile.idCommitment);
    assert.equal(membership.status, AuthorizationStatus.active);
    assert.equal(harness.simulator.getLedger().activeMaintainerCount, activeMaintainersBeforeApplication + 1n);
    trustResult = {
      activatedBeforeRevocation: true,
      currentMembershipActive: false,
      verificationSurface: "Compact membership record",
    };
    const lifecycle = [];
    for (const action of ["suspend", "revoke"]) {
      const prepared = await adminClient.prepareGovernedAction(role, profile.id, action);
      const actionPath = `/v1/governed/${role}/${profile.id}/actions/${action}`;
      const beforeAction = harness.simulator.getLedger().governanceActionCount;
      assert.equal((await post(actionPath, {
        prepared, signers: [signAction(maintainers[0], prepared)],
      })).status, 403);
      assert.equal((await post(actionPath, {
        prepared,
        signers: [signAction(maintainers[0], prepared), signAction(maintainers[0], prepared)],
      })).status, 403);
      assert.equal(harness.simulator.getLedger().governanceActionCount, beforeAction);
      await adminClient.submitGovernedAction(role, profile.id, action, {
        prepared, signers: quorumSignatures(prepared),
      });
      await publishGovernedEpoch(action);
      assert.equal(harness.simulator.getMaintainerMembership(profile.idCommitment).status,
        action === "suspend" ? AuthorizationStatus.suspended : AuthorizationStatus.revoked);
      assert.equal(harness.simulator.getLedger().activeMaintainerCount, activeMaintainersBeforeApplication);
      lifecycle.push({ action, remainingActiveMaintainers: Number(activeMaintainersBeforeApplication) });
    }
    lifecycleResult = lifecycle;
  } else {
    const otherResourceId = `${resourceId.slice(0, -1)}${resourceId.endsWith("0") ? "1" : "0"}`;
    const board = await adminClient.loadReviewBoard();
    assert.equal(board[profile.snapshotKey].some((entry) =>
      entry.authorization?.authorizationId === profile.id && entry.authorization.status === "active"), true);
    const bundle = await expectHttp(await fetch(
      `${base}/v1/authorizations/${role}/${profile.id}/evidence`,
    ), 200);
    assert.equal(bundle.authorization.evidenceHash, submitted.receipt.evidenceCommitment);
    const client = new TrustRegistrySimulatorClient(harness.simulator);
    profile.verifyBundle(client, bundle, {
      expectedRegistryId: harness.registryId,
      expectedSubjectDid: participant.subjectDid,
      expectedResourceId: resourceId,
    });
    assert.throws(() => profile.verifyBundle(client, bundle, {
      expectedRegistryId: `${harness.registryId}:other`,
      expectedSubjectDid: participant.subjectDid,
      expectedResourceId: resourceId,
    }), /registry mismatch/iu);
    assert.throws(() => profile.verifyBundle(client, bundle, {
      expectedRegistryId: harness.registryId,
      expectedSubjectDid: participant.subjectDid,
      expectedResourceId: otherResourceId,
    }), /resource mismatch/iu);
    assert.throws(() => profile.verifyBundle(client, bundle, {
      expectedRegistryId: harness.registryId,
      expectedSubjectDid: participant.subjectDid,
      expectedResourceId: resourceId,
      evaluationTime: new Date(Date.parse(bundle.epoch.validUntil) + 1000).toISOString(),
    }), /Epoch is stale/iu);
    const evaluated = await expectHttp(await post("/v1/authorizations/evaluate", {
      role, subjectDid: participant.subjectDid, resourceId,
      at: bundle.authorization.activeFrom,
    }), 200);
    assert.equal(evaluated.trustedAtTime, true);
    const wrongScope = await post("/v1/authorizations/evaluate", {
      role, subjectDid: participant.subjectDid, resourceId: otherResourceId,
      at: bundle.authorization.activeFrom,
    });
    assert.equal(wrongScope.status, 404);
    if (role === "verifier" || role === "auditor") {
      const expandedScopes = [
        { ...scope, allowedAttributes: [...scope.allowedAttributes, "extra-attribute"] },
        { ...scope, allowedPredicates: [...scope.allowedPredicates, "extra-predicate"] },
        { ...scope, purpose: `${scope.purpose}-other` },
        { ...scope, disclosureLevel: `${scope.disclosureLevel}-other` },
      ];
      for (const expandedScope of expandedScopes) {
        const expandedResourceId = requestGovernedResourceId(expandedScope);
        assert.notEqual(expandedResourceId, resourceId);
        const expandedDecision = await post("/v1/authorizations/evaluate", {
          role, subjectDid: participant.subjectDid, resourceId: expandedResourceId,
          at: bundle.authorization.activeFrom,
        });
        assert.equal(expandedDecision.status, 404);
      }
    }
    let trqpAgreement = null;
    if (role === "issuer" || role === "verifier") {
      const request = {
        entity_id: participant.subjectDid,
        authority_id: harness.registryDid,
        action: role === "issuer" ? "issue" : "verify",
        resource: resourceId,
        context: { time: bundle.authorization.activeFrom },
      };
      const decision = await expectHttp(await post("/v1/trqp/authorizations/query", request), 200);
      const evidence = await expectHttp(await post("/v1/trqp/authorizations/evidence", request), 200);
      assert.equal(decision.authorized, evaluated.trustedAtTime);
      assert.equal(evidence.authorized, evaluated.trustedAtTime);
      assert.equal(evidence.bundle.inclusionProof.leafHash, bundle.inclusionProof.leafHash);
      trqpAgreement = true;
    }
    trustResult = {
      trustedAtActivation: true,
      currentTrustedAfterRevocation: false,
      trqpAgreement,
      verificationSurface: "UI clients, API/TRQP, and independently verified historical evidence",
    };
    const activeAt = bundle.authorization.activeFrom;
    const queryDecision = (at) => post("/v1/authorizations/evaluate", {
      role, subjectDid: participant.subjectDid, resourceId, at,
    });
    const historicalSelection = (at) => ({
      role, subjectDid: participant.subjectDid, resourceId, at,
    });
    const queryVerifiedEvidence = async (at, trustedEpoch) => {
      const selection = historicalSelection(at);
      const response = await expectHttp(await post("/v1/authorizations/evaluate/evidence", selection), 200);
      const anchor = resolveCompactHistoricalEpochAnchor({
        ledger: harness.simulator.getLedger(), registryId: harness.registryId,
        ...trustedEpoch,
        sequenceToTimestamp: defaultSequenceToTimestamp,
      });
      const { epochRecord } = anchor;
      const decision = verifyHistoricalAuthorizationEvidenceResponse(response, selection, anchor);
      const fromApi = await verifyHistoricalAuthorizationEvidenceFromApi(base, selection, anchor);
      assert.equal(fromApi.trustedAtTime, decision.trustedAtTime);
      if (role === "issuer" || role === "verifier") {
        const request = trqpRequest(at);
        const verifiedTrqp = await verifyTrqpAuthorizationEvidenceFromApi(
          base, request, harness.registryDid, anchor,
        );
        assert.equal(verifiedTrqp.authorized, decision.trustedAtTime);
        assert.equal(verifiedTrqp.bundle.epoch.epochId, trustedEpoch.epochId);
      }
      assert.throws(() => verifyHistoricalAuthorizationEvidenceResponse(response, {
        ...selection, resourceId: otherResourceId,
      }, anchor), /scope mismatch/iu);
      assert.throws(() => verifyHistoricalAuthorizationEvidenceResponse(response, selection, {
        ...anchor,
        epochRecord: { ...epochRecord, stateRoot: new Uint8Array(32) },
      }), /state root mismatch/iu);
      return decision;
    };
    const trqpRequest = (at) => ({
      entity_id: participant.subjectDid,
      authority_id: harness.registryDid,
      action: role === "issuer" ? "issue" : "verify",
      resource: resourceId,
      context: { time: at },
    });
    const lifecycle = [];
    for (const action of ["suspend", "revoke"]) {
      const prepared = await adminClient.prepareGovernedAction(role, profile.id, action);
      const actionPath = `/v1/governed/${role}/${profile.id}/actions/${action}`;
      const beforeAction = harness.simulator.getLedger().governanceActionCount;
      assert.equal((await post(actionPath, {
        prepared, signers: [signAction(maintainers[0], prepared)],
      })).status, 403);
      assert.equal((await post(actionPath, {
        prepared,
        signers: [signAction(maintainers[0], prepared), signAction(maintainers[0], prepared)],
      })).status, 403);
      assert.equal(harness.simulator.getLedger().governanceActionCount, beforeAction);
      await adminClient.submitGovernedAction(role, profile.id, action, {
        prepared, signers: quorumSignatures(prepared),
      });
      await publishGovernedEpoch(action);
      const entry = await expectHttp(await fetch(
        `${base}/v1/authorizations/${role}/${profile.id}`,
      ), 200);
      assert.equal(entry.authorization.status, action === "suspend" ? "suspended" : "revoked");
      const board = await adminClient.loadReviewBoard();
      assert.equal(board[profile.snapshotKey].some((candidate) =>
        candidate.authorization?.authorizationId === profile.id
        && candidate.authorization.status === entry.authorization.status), true);
      const changedAt = action === "suspend"
        ? entry.authorization.suspendedAt : entry.authorization.revokedAt;
      assert.ok(changedAt);
      const currentDecision = await expectHttp(await queryDecision(changedAt), 200);
      const historicalDecision = await expectHttp(await queryDecision(activeAt), 200);
      assert.equal(currentDecision.trustedAtTime, false);
      assert.equal(historicalDecision.trustedAtTime, true);
      assert.equal((await queryVerifiedEvidence(changedAt, trustedEpochsByPhase.get(action))).trustedAtTime, false);
      assert.equal((await queryVerifiedEvidence(activeAt, trustedEpochsByPhase.get("activate"))).trustedAtTime, true);
      if (role === "issuer" || role === "verifier") {
        const trqp = await expectHttp(await post(
          "/v1/trqp/authorizations/query", trqpRequest(changedAt),
        ), 200);
        assert.equal(trqp.authorized, currentDecision.trustedAtTime);
      }
      if (role === "auditor") {
        const portalRecord = await applicantClient.loadAuditorAuthorization(profile.id);
        assert.equal(portalRecord?.authorization.status, entry.authorization.status);
      }
      lifecycle.push({ action, changedAt, currentTrusted: false, historicalActiveRetained: true });
    }
    lifecycleResult = lifecycle;
  }
  process.stdout.write(`${JSON.stringify({
    demo: `signed-${role}-journey`,
    mode: "deterministic local Compact simulator and private file-backed admission state",
    governance: "2-of-3 active maintainers",
    applicationId,
    targetId: profile.id,
    proposalEventHash: proposal.eventHash,
    evidenceCommitment: submitted.evidence.commitment,
    currentEpochId: snapshot.currentEpoch.epochId,
    externallyPublishedEpochIds: publishedEpochIds,
    clientSurfaces: ["applicant portal", "admin console"],
    lifecycle: lifecycleResult,
    ...trustResult,
    expectedRejections: ["unauthorized-apply:403", "wrong-signed-target:400", "apply-replay:409",
      "unauthorized-vp:403", "vp-replay:404", "lost-vp-response-recovered:200",
      "wrong-proposal-target:403",
      "missing-proposal-receipt:403", "single-maintainer:403",
      "duplicate-maintainer:403", ...(role === "maintainer" ? ["candidate-self-vote:403"] : []),
      "proposal-replay:409", "lost-response-recovered:200",
      "premature-activation:403", "stale-governed-context:409",
      "single-epoch-signer:403", "duplicate-epoch-signer:403",
      "wrong-epoch-label:409", "stale-epoch-context:409",
      ...(role === "maintainer" ? [] : ["wrong-registry:client", "wrong-resource:client",
        "expired-evidence:client", "out-of-scope-query:404"]),
      ...(role === "verifier" || role === "auditor" ? ["expanded-request-permissions:404"] : []),
      "single-suspend:403", "duplicate-suspend:403", "single-revoke:403", "duplicate-revoke:403"],
  }, null, 2)}\n`);
} finally {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  await rm(stateDirectory, { recursive: true, force: true });
}
