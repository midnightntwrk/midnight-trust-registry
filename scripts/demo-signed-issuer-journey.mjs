import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { randomBytes, timingSafeEqual } from "node:crypto";

import {
  encodeJubjubSignature,
  payloadToJubjubDigest,
  signJubjubDigest,
} from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature as encodeGovernanceSignature,
  signPolicyBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";

import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import { createOperatorWorkspace, publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  computeAuthorizationScopeCommitment,
  computePendingApplicationPayloadCommitment,
  createScopedIdentifier,
  mutationIntentDigestBytes,
  sha256Hex,
} from "../packages/trust-registry-domain/dist/index.js";
import {
  bytes32Commitment,
  createApplicationVpIntakePorts,
  createApplicationVpScenarioFixture,
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  VP_FIXTURE_NONCE,
  VP_FIXTURE_TIME_MS,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  computeOperatorWorkspaceCommitment,
  createTrustRegistryApiServer,
  GovernedIssuerProposalRejectedError,
  GovernedMembershipActionRejectedError,
  InMemoryApplicationChallengeStore,
  InMemoryPendingApplicationRegistrationPort,
} from "../packages/trust-registry-api/dist/index.js";

const label = "signed-issuer-journey";
const now = new Date(VP_FIXTURE_TIME_MS);
const asHex = (value) => `0x${Buffer.from(value).toString("hex")}`;
const fromHex = (value) => Buffer.from(value.slice(2), "hex");
const harness = new LocalTrustRegistryIntegrationHarness(label);
const workspace = createOperatorWorkspace({ label });
const issuer = createIssuerScenarioFixture(label);
const scope = createIssuerAuthorizationScopeFixture(issuer);
const governedResource = { type: "credentialFamily", id: issuer.resourceId };
const applicationId = createScopedIdentifier("application", "issuer", issuer.authorizationId);
const initialSnapshot = publishSimulatorSnapshot(harness, { label });

assert.deepEqual(initialSnapshot.registry, workspace.snapshot.registry);
assert.deepEqual(initialSnapshot.policy, workspace.snapshot.policy);
assert.deepEqual(initialSnapshot.currentEpoch, workspace.snapshot.currentEpoch);

const fixtureOptions = {
  subjectDid: issuer.subjectDid,
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
const registration = new InMemoryPendingApplicationRegistrationPort({
  workspace, applications: [], consumedNonces: [],
}, harness.evidenceVerifier.did, resolverFixture.input.resolver);
const acceptedEvidence = new Map();
const token = randomBytes(32).toString("hex");
const authorized = (request) => {
  const supplied = request.headers.authorization?.replace(/^Bearer /u, "");
  return typeof supplied === "string" && supplied.length === token.length
    && timingSafeEqual(Buffer.from(supplied), Buffer.from(token));
};
const admission = {
  resolvePendingApplication: async (id) => registration.readPending(id),
  resolveAcceptedEvidence: async (id) => acceptedEvidence.get(id) ?? null,
};
const bootstrapSeed = new Uint8Array(32).fill(17);
const bootstrapKeyId = bytes32Commitment(`${harness.maintainerDid}#key-1`);
const signAction = (prepared) => {
  const publicKey = deriveJubjubPublicKeyFromSeed(bootstrapSeed);
  const signature = signPolicyBoundMaintainerActionFromSeed(
    bootstrapSeed,
    fromHex(prepared.registryId),
    fromHex(prepared.policyCommitment),
    fromHex(prepared.actionKind),
    fromHex(prepared.actionPayloadHash),
    BigInt(prepared.actionSequence),
  );
  return {
    keyId: asHex(bootstrapKeyId),
    publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
    signature: asHex(encodeGovernanceSignature(signature)),
  };
};
let currentProof;
let acceptedChallengeHash;
let snapshot = initialSnapshot;
const expectedEvidence = () => {
  if (acceptedChallengeHash === undefined) throw new Error("No accepted application challenge");
  return { scope, challengeHash: acceptedChallengeHash, governedResource };
};
const server = createTrustRegistryApiServer({
  source: { mode: "memory", loadSnapshot: async () => snapshot },
  clock: () => now.toISOString(),
  pendingApplicationRegistration: registration,
  proposalAdmission: admission,
  governedIssuerProposals: {
    async prepare(id, evidence) {
      if (id !== issuer.authorizationId) throw new GovernedIssuerProposalRejectedError("unknown-authorization");
      try {
        return harness.prepareIssuerProposalAction(issuer, evidence, expectedEvidence());
      } catch {
        throw new GovernedIssuerProposalRejectedError("invalid-evidence");
      }
    },
    async execute(id, evidence, signers, verifierSignature) {
      if (id !== issuer.authorizationId) throw new GovernedIssuerProposalRejectedError("unknown-authorization");
      try {
        const eventHash = harness.executeIssuerProposalWithSignatures(
          issuer, evidence, signers, verifierSignature, expectedEvidence(),
        );
        return { eventHash: asHex(eventHash) };
      } catch {
        throw new GovernedIssuerProposalRejectedError("invalid-signers");
      }
    },
  },
  governedMembershipActions: {
    async prepare(role, id, action) {
      if (role !== "issuer" || id !== issuer.authorizationId) {
        throw new GovernedMembershipActionRejectedError("unknown-authorization");
      }
      return harness.prepareIssuerDecisionAction(issuer, action);
    },
    async execute(role, id, action, signers) {
      if (role !== "issuer" || id !== issuer.authorizationId) {
        throw new GovernedMembershipActionRejectedError("unknown-authorization");
      }
      try {
        const eventHash = harness.executeIssuerDecisionWithSignatures(issuer, action, signers);
        if (action === "activate") {
          snapshot = publishSimulatorSnapshot(harness, {
            label, issuers: [{ label: "joined-issuer", fixture: issuer }],
          }, snapshot);
        }
        return { eventHash: asHex(eventHash) };
      } catch {
        throw new GovernedMembershipActionRejectedError("invalid-signers");
      }
    },
  },
  authorizePendingApplicationRegistration: async (request) => {
    if (!authorized(request)) throw new Error("Applicant bearer token required");
  },
  applicationVp: {
    challengeStore: new InMemoryApplicationChallengeStore(),
    authorizeRequest: async (id, request) => {
      if (!authorized(request) || registration.readPending(id)?.binding.subjectDid !== issuer.subjectDid) {
        throw new Error("Applicant bearer token denied");
      }
    },
    resolvePendingApplication: async (id) => {
      const pending = registration.readPending(id);
      return pending === null || acceptedEvidence.has(id) ? null : {
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
    persistRedactedEvidence: async (id, evidence) => {
      if (id !== applicationId || acceptedEvidence.has(id) || registration.readPending(id) === null) {
        throw new Error("Application already accepted or unavailable");
      }
      const receipt = {
        receiptId: sha256Hex(JSON.stringify([id, evidence.commitment])),
        evidenceCommitment: evidence.commitment,
        acceptedAt: now.toISOString(),
      };
      acceptedEvidence.set(id, { evidence, receipt });
      return receipt;
    },
  },
});

const signedApplication = () => {
  const intent = {
    version: "tr-mutation-intent-v1",
    registryId: harness.registryId,
    actorDid: issuer.subjectDid,
    actorKeyId: `${issuer.subjectDid}#auth-1`,
    actorRole: "applicant",
    action: "apply",
    target: "issuer",
    targetId: applicationId,
    scopeCommitment: computeAuthorizationScopeCommitment(scope),
    payloadCommitment: computePendingApplicationPayloadCommitment({
      applicationId, authorizationId: issuer.authorizationId, scope, governedResource,
    }),
    nonce: `0x${"22".repeat(32)}`,
    expectedWorkspaceCommitment: computeOperatorWorkspaceCommitment(workspace),
    expectedEpochId: workspace.snapshot.currentEpoch.epochId,
    issuedAt: new Date(VP_FIXTURE_TIME_MS - 60_000).toISOString(),
    expiresAt: new Date(VP_FIXTURE_TIME_MS + 60_000).toISOString(),
  };
  return {
    applicationId,
    authorizationId: issuer.authorizationId,
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
  const post = (path, body, withToken = true) => fetch(`${base}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(withToken ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });

  const application = signedApplication();
  assert.equal((await post("/v1/pending-applications", application, false)).status, 403);
  assert.equal((await post("/v1/pending-applications", {
    ...application, authorizationId: "auth:issuer:substituted:v1",
  })).status, 400);
  const pending = await expectHttp(await post("/v1/pending-applications", application), 201);
  assert.equal(pending.authorizationId, issuer.authorizationId);
  assert.equal(pending.binding.applicationId, applicationId);
  assert.equal(pending.binding.scopeCommitment, computeAuthorizationScopeCommitment(scope));
  assert.equal((await post("/v1/pending-applications", application)).status, 409);

  const evidencePath = `/v1/application-evidence/${applicationId}`;
  assert.equal((await post(`${evidencePath}/challenges`, {}, false)).status, 403);
  const challenge = await expectHttp(await post(`${evidencePath}/challenges`, {}), 201);
  acceptedChallengeHash = challenge.challengeHash;
  currentProof = await createApplicationVpScenarioFixture(challenge.nonce, fixtureOptions);
  const submission = {
    nonce: challenge.nonce,
    challengeHash: challenge.challengeHash,
    presentation: currentProof.input.submission,
  };
  const submitted = await expectHttp(await post(`${evidencePath}/submissions`, submission), 202);
  assert.equal(submitted.receipt.evidenceCommitment, submitted.evidence.commitment);
  assert.equal(JSON.stringify(submitted).includes(currentProof.input.submission.rawCredentialBody), false);
  assert.equal((await post(`${evidencePath}/submissions`, submission)).status, 404);
  assert.equal((await post(`${evidencePath}/challenges`, {})).status, 404);

  harness.advanceEvidenceTimeBy(60_000);
  const proposalPath = `/v1/governed/issuer/${issuer.authorizationId}/proposal`;
  assert.equal((await post(
    `/v1/governed/issuer/auth:issuer:substituted:v1/proposal/prepare`,
    { evidence: submitted.evidence },
  )).status, 403);
  const acceptedRecord = acceptedEvidence.get(applicationId);
  acceptedEvidence.delete(applicationId);
  assert.equal((await post(`${proposalPath}/prepare`, { evidence: submitted.evidence })).status, 403);
  acceptedEvidence.set(applicationId, acceptedRecord);
  const preparedProposal = await expectHttp(await post(
    `${proposalPath}/prepare`, { evidence: submitted.evidence },
  ), 200);
  const verifierSignature = harness.signIssuerProposalEvidence(
    harness.prepareIssuerProposalAction(issuer, submitted.evidence, expectedEvidence()),
  );
  const proposalBody = {
    evidence: submitted.evidence,
    prepared: preparedProposal,
    signers: [signAction(preparedProposal)],
    evidenceVerifierSignature: asHex(encodeGovernanceSignature(verifierSignature)),
  };
  acceptedEvidence.delete(applicationId);
  assert.equal((await post(`${proposalPath}/submit`, proposalBody)).status, 403);
  acceptedEvidence.set(applicationId, acceptedRecord);
  const proposal = await expectHttp(await post(`${proposalPath}/submit`, proposalBody), 202);
  assert.equal((await post(`${proposalPath}/submit`, proposalBody)).status, 409);

  for (const action of ["approve", "activate"]) {
    const actionPath = `/v1/governed/issuer/${issuer.authorizationId}/actions/${action}`;
    const prepared = await expectHttp(await fetch(`${base}${actionPath}`), 200);
    await expectHttp(await post(actionPath, { prepared, signers: [signAction(prepared)] }), 202);
  }

  const bundle = await expectHttp(await fetch(
    `${base}/v1/authorizations/issuer/${issuer.authorizationId}/evidence`,
  ), 200);
  assert.equal(bundle.authorization.evidenceHash, submitted.receipt.evidenceCommitment);
  new TrustRegistrySimulatorClient(harness.simulator).verifyIssuerAuthorizationBundle(bundle, {
    expectedRegistryId: harness.registryId,
    expectedSubjectDid: issuer.subjectDid,
    expectedResourceId: issuer.resourceId,
  });
  const evaluated = await expectHttp(await post("/v1/authorizations/evaluate", {
    role: "issuer", subjectDid: issuer.subjectDid, resourceId: issuer.resourceId,
    at: bundle.authorization.activeFrom,
  }), 200);
  assert.equal(evaluated.trustedAtTime, true);
  process.stdout.write(`${JSON.stringify({
    demo: "signed-issuer-journey",
    mode: "deterministic local Compact simulator and in-memory applicant state",
    applicationId,
    authorizationId: issuer.authorizationId,
    proposalEventHash: proposal.eventHash,
    evidenceCommitment: submitted.evidence.commitment,
    activeEpochId: bundle.epoch.epochId,
    trustedAtTime: evaluated.trustedAtTime,
    expectedRejections: ["unauthorized-apply:403", "wrong-signed-target:400", "apply-replay:409",
      "unauthorized-vp:403", "vp-replay:404", "wrong-proposal-target:403",
      "missing-proposal-receipt:403", "proposal-replay:409"],
  }, null, 2)}\n`);
} finally {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
