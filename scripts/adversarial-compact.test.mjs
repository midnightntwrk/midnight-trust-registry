import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import {
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { AuthorizationStatus } from "../contracts/trust-registry/dist/managed/trust-registry/contract/index.js";
import { bytes32Commitment } from "../packages/trust-registry-client/dist/index.js";
import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import { computeApplicationEvidenceCommitment } from "../packages/trust-registry-domain/dist/index.js";
import {
  createAuditorScenarioFixture,
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";

const bootstrapMembership = async (harness) => ({
  maintainerIdCommitment: harness.maintainerIdCommitment,
  maintainerId: harness.maintainerId,
  subjectDidCommitment: harness.maintainerDidCommitment,
  keyId: (await harness.simulator.getLedger()).lastAuthorizedMaintainerKeyId,
  seed: new Uint8Array(32),
  subjectDid: harness.maintainerDid,
  trustLevel: "bootstrap-maintainer",
});

const signAction = async (harness, maintainer, prepared, policyCommitment) => {
  const ledger = await harness.simulator.getLedger();
  return {
    keyId: maintainer.keyId,
    publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
    signature: signDeploymentBoundMaintainerActionFromSeed(
      maintainer.seed,
      ledger.registryId,
      ledger.deploymentNetworkIdCommitment,
      Buffer.from(harness.simulator.contractAddress, "hex"),
      policyCommitment ?? ledger.governancePolicyCommitment,
      prepared.actionKind,
      prepared.actionPayloadHash,
      prepared.actionSequence,
    ),
  };
};

const revisedPolicyEvidence = async (label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const second = createMaintainerScenarioFixture(`${label}-second`);
  const third = createMaintainerScenarioFixture(`${label}-third`);
  const historicalIssuer = createIssuerScenarioFixture(`${label}-historical`);
  const currentIssuer = createIssuerScenarioFixture(`${label}-current`);
  await harness.authorizeIssuer(historicalIssuer);
  await harness.authorizeMaintainer(second);
  await harness.authorizeMaintainer(third);
  await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  await harness.proposeIssuer(currentIssuer, [second]);
  await harness.approveIssuer(currentIssuer, [second]);
  await harness.activateIssuer(currentIssuer, [second]);
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  const historical = await harness.buildIssuerHistoricalEvidence(historicalIssuer);
  const current = await harness.evaluateCurrentIssuerDecision(currentIssuer);
  assert.equal(historical.policy.version, "v1");
  assert.equal(current.policy.version, "v2");
  assert.ok(await client.verifyIssuerAuthorizationBundle(historical, {}));
  assert.ok(await client.verifyIssuerAuthorizationBundle(current, {}));
  return { client, historical, current };
};

const activeIssuerEvidence = async (label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const issuer = createIssuerScenarioFixture(`${label}-issuer`);
  await harness.authorizeIssuer(issuer);
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  const bundle = await harness.evaluateCurrentIssuerDecision(issuer);
  assert.ok(await client.verifyIssuerAuthorizationBundle(bundle, { expectedRegistryId: harness.registryId }));
  return { harness, issuer, client, bundle };
};

test("compact-self-voted-maintainer-suspension", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-self-suspension");
  await harness.ready;
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  assert.equal((await harness.simulator.getLedger()).activeMaintainerCount, 1n);
  await assert.rejects(harness.suspendMaintainer(await bootstrapMembership(harness)), /own DID/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  assert.equal((await harness.simulator.getLedger()).activeMaintainerCount, 1n);
});

test("compact-self-voted-maintainer-revocation", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-self-revocation");
  await harness.ready;
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  assert.equal((await harness.simulator.getLedger()).activeMaintainerCount, 1n);
  await assert.rejects(harness.revokeMaintainer(await bootstrapMembership(harness)), /own DID/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  assert.equal((await harness.simulator.getLedger()).activeMaintainerCount, 1n);
});

test("compact-removal-below-maintainer-threshold", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-removal-threshold");
  const second = createMaintainerScenarioFixture("isolated-removal-second");
  const third = createMaintainerScenarioFixture("isolated-removal-third");
  await harness.authorizeMaintainer(second);
  await harness.authorizeMaintainer(third);
  await harness.updateMaintainerThresholdPolicy(2n, 1n, 1n, [second]);
  const target = await bootstrapMembership(harness);
  const prepared = await harness.prepareMaintainerDecisionAction(target, "suspend");
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  assert.equal((await harness.simulator.getLedger()).activeMaintainerCount, 3n);
  await assert.rejects(harness.executeMaintainerDecisionWithSignatures(
    target, "suspend", [await signAction(harness, second, prepared)],
  ), /non-conflicted removal quorum/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  assert.equal((await harness.simulator.getLedger()).activeMaintainerCount, 3n);
});

test("compact-removed-maintainer-signer", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-removed-signer");
  const removed = createMaintainerScenarioFixture("isolated-removed-key");
  const issuer = createIssuerScenarioFixture("isolated-removed-issuer");
  await harness.authorizeMaintainer(removed);
  await harness.suspendMaintainer(removed);
  await harness.proposeIssuer(issuer);
  const prepared = await harness.prepareIssuerDecisionAction(issuer, "approve");
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.executeIssuerDecisionWithSignatures(
    issuer, "approve", [await signAction(harness, removed, prepared)],
  ), /active|authorized|maintainer|signature|assert/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
});

test("denied-proposal-blocks-live-scope-reuse", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-live-scope");
  const issuer = createIssuerScenarioFixture("isolated-live-scope-issuer");
  const replacementId = `${issuer.authorizationId}:replacement`;
  const replacement = {
    ...issuer,
    authorizationId: replacementId,
    authorizationIdCommitment: bytes32Commitment(replacementId),
  };
  await harness.proposeIssuer(issuer);
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.proposeIssuer(replacement), /live authorization/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
});

test("denied-proposal-requires-quorum", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-denial-quorum");
  const second = createMaintainerScenarioFixture("isolated-denial-second");
  const third = createMaintainerScenarioFixture("isolated-denial-third");
  const issuer = createIssuerScenarioFixture("isolated-denial-issuer");
  await harness.authorizeMaintainer(second);
  await harness.authorizeMaintainer(third);
  await harness.proposeIssuer(issuer);
  await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const prepared = await harness.prepareIssuerDecisionAction(issuer, "archive");
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.executeIssuerDecisionWithSignatures(
    issuer, "archive", [await signAction(harness, second, prepared)],
  ), /threshold|quorum|signer|authorization/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  const archived = await harness.executeIssuerDecisionWithSignatures(
    issuer, "archive", [await signAction(harness, second, prepared), await signAction(harness, third, prepared)],
  );
  assert.equal(archived.length, 32);
});

test("denied-proposal-is-not-trust", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-archived-proposal");
  const issuer = createIssuerScenarioFixture("isolated-archived-issuer");
  await harness.proposeIssuer(issuer);
  await harness.archiveIssuer(issuer);
  const bundle = await harness.buildIssuerHistoricalEvidence(issuer);
  assert.equal(bundle.authorization.status, "archived");
  assert.equal(bundle.authorization.authorizedAt, undefined);
  await assert.rejects(new TrustRegistrySimulatorClient(harness.simulator)
    .verifyIssuerAuthorizationBundle(bundle, {}), /not active/iu);
});

test("issuer-signed-wrong-policy-id", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-wrong-evidence-policy");
  const issuer = createIssuerScenarioFixture("isolated-wrong-evidence-policy-issuer");
  const evidence = await harness.createApplicationEvidence({
    applicationId: issuer.authorizationId,
    subjectDid: issuer.subjectDid,
    role: "issuer",
    scope: createIssuerAuthorizationScopeFixture(issuer),
    governedResource: { type: "credentialFamily", id: issuer.resourceId },
  });
  const envelope = { ...evidence.envelope, policyId: "policy:wrong:v1" };
  const commitment = computeApplicationEvidenceCommitment(envelope);
  const signed = {
    envelope,
    commitment,
    signature: harness.signApplicationEvidenceCommitment(commitment),
  };
  assert.equal(await harness.verifyApplicationEvidenceSignature(
    signed.commitment, signed.signature, harness.evidenceVerifier,
  ), true);
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.proposeIssuerWithApplicationEvidence(issuer, signed), /policyId does not match/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  await harness.proposeIssuerWithApplicationEvidence(issuer, evidence);
});

test("issuer-expired-signed-application-evidence", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-expired-evidence");
  const issuer = createIssuerScenarioFixture("isolated-expired-evidence-issuer");
  const evidence = await harness.createApplicationEvidence({
    applicationId: issuer.authorizationId,
    subjectDid: issuer.subjectDid,
    role: "issuer",
    scope: createIssuerAuthorizationScopeFixture(issuer),
    governedResource: { type: "credentialFamily", id: issuer.resourceId },
  });
  harness.advanceEvidenceTimeBy(24 * 60 * 60 * 1000 + 1);
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.proposeIssuerWithApplicationEvidence(issuer, evidence), /evidence is expired/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  const fresh = await harness.createApplicationEvidence({
    applicationId: issuer.authorizationId,
    subjectDid: issuer.subjectDid,
    role: "issuer",
    scope: createIssuerAuthorizationScopeFixture(issuer),
    governedResource: { type: "credentialFamily", id: issuer.resourceId },
  });
  await harness.proposeIssuerWithApplicationEvidence(issuer, fresh);
});

test("integration-old-policy-application-preflight", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-old-policy-application");
  const second = createMaintainerScenarioFixture("isolated-old-policy-second");
  const third = createMaintainerScenarioFixture("isolated-old-policy-third");
  const issuer = createIssuerScenarioFixture("isolated-old-policy-issuer");
  await harness.authorizeMaintainer(second);
  await harness.authorizeMaintainer(third);
  await harness.proposeIssuer(issuer);
  await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.prepareIssuerDecisionAction(issuer, "approve"), /policyVersion does not match/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  const current = createIssuerScenarioFixture("isolated-current-policy-issuer");
  await harness.proposeIssuer(current, [second]);
  await harness.approveIssuer(current, [second]);
});

test("compact-old-policy-signature-replay", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-old-policy-signature");
  const second = createMaintainerScenarioFixture("isolated-old-signature-second");
  const third = createMaintainerScenarioFixture("isolated-old-signature-third");
  const issuer = createIssuerScenarioFixture("isolated-current-signature-issuer");
  await harness.authorizeMaintainer(second);
  await harness.authorizeMaintainer(third);
  const oldPolicyCommitment = Buffer.from((await harness.simulator.getLedger()).governancePolicyCommitment);
  await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  await harness.proposeIssuer(issuer, [second]);
  const prepared = await harness.prepareIssuerDecisionAction(issuer, "approve");
  const oldSignature = await signAction(harness, second, prepared, oldPolicyCommitment);
  const oldCoSignature = await signAction(harness, third, prepared, oldPolicyCommitment);
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.simulator.authorizeIssuerAuthorization(
    oldSignature.keyId, oldSignature.publicKey, oldSignature.signature,
    issuer.authorizationIdCommitment, prepared.evidenceHash, [oldCoSignature],
  ), /Invalid Jubjub Schnorr signature/u);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  const currentSignature = await signAction(harness, second, prepared);
  const currentCoSignature = await signAction(harness, third, prepared);
  await harness.simulator.authorizeIssuerAuthorization(
    currentSignature.keyId, currentSignature.publicKey, currentSignature.signature,
    issuer.authorizationIdCommitment, prepared.evidenceHash, [currentCoSignature],
  );
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before + 1n);
});

for (const role of [
  { name: "verifier", fixture: createVerifierScenarioFixture },
  { name: "auditor", fixture: createAuditorScenarioFixture },
  { name: "maintainer", fixture: createMaintainerScenarioFixture },
]) {
  test(`compact-${role.name}-old-policy-signature-replay`, async () => {
    const label = `isolated-${role.name}-old-policy-replay`;
    const harness = new LocalTrustRegistryIntegrationHarness(label);
    const second = createMaintainerScenarioFixture(`${label}-second`);
    const third = createMaintainerScenarioFixture(`${label}-third`);
    const target = role.fixture(`${label}-target`);
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(third);
    const formerPolicyCommitment = Buffer.from((await harness.simulator.getLedger()).governancePolicyCommitment);
    await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const capitalized = `${role.name[0].toUpperCase()}${role.name.slice(1)}`;
    await harness[`propose${capitalized}`](target, [second]);
    const prepared = await harness[`prepare${capitalized}DecisionAction`](target, "approve");
    const before = (await harness.simulator.getLedger()).governanceActionCount;
    await assert.rejects(harness[`execute${capitalized}DecisionWithSignatures`](target, "approve", [
      await signAction(harness, second, prepared, formerPolicyCommitment),
      await signAction(harness, third, prepared, formerPolicyCommitment),
    ]), /Invalid Jubjub Schnorr signature/u);
    assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
    await harness[`execute${capitalized}DecisionWithSignatures`](target, "approve", [
      await signAction(harness, second, prepared), await signAction(harness, third, prepared),
    ]);
    assert.equal((await harness.simulator.getLedger()).governanceActionCount, before + 1n);
  });
}

test("compact-recovery-policy-headroom-required", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-recovery-headroom");
  const second = createMaintainerScenarioFixture("isolated-recovery-second");
  const third = createMaintainerScenarioFixture("isolated-recovery-third");
  const candidate = createMaintainerScenarioFixture("isolated-recovery-candidate");
  await harness.authorizeMaintainer(second);
  await harness.authorizeMaintainer(third);
  await harness.authorizeMaintainer(candidate);
  await harness.updateMaintainerThresholdPolicy(3n, 1n, 2n);
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  assert.equal((await harness.simulator.getLedger()).activeMaintainerCount, 4n);
  await assert.rejects(harness.suspendMaintainer(candidate), /non-conflicted removal quorum/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n, [second, third]);
  await harness.suspendMaintainer(candidate);
  assert.equal((await harness.simulator.getLedger()).activeMaintainerCount, 3n);
});

test("issuer-history-survives-threshold-change", async () => {
  const { client, historical, current } = await revisedPolicyEvidence("isolated-history-survives");
  assert.notEqual(historical.epoch.policyRoot, current.epoch.policyRoot);
  assert.ok(await client.verifyIssuerAuthorizationBundle(historical, {}));
});

test("verifier-history-survives-threshold-change", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-verifier-history-threshold");
  const verifier = createVerifierScenarioFixture("isolated-verifier-history-target");
  const second = createMaintainerScenarioFixture("isolated-verifier-history-second");
  const third = createMaintainerScenarioFixture("isolated-verifier-history-third");
  await harness.authorizeVerifier(verifier);
  const original = await harness.evaluateCurrentVerifierDecision(verifier);
  await harness.authorizeMaintainer(second);
  await harness.authorizeMaintainer(third);
  await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  await harness.revokeVerifier(verifier, [second]);
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  assert.notEqual(original.policy.version, harness.policyRecord.version);
  assert.ok(await client.verifyVerifierAuthorizationBundle(original, {}));
});

const recognitionAfterPolicyRevision = async (label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const second = createMaintainerScenarioFixture(`${label}-second`);
  const third = createMaintainerScenarioFixture(`${label}-third`);
  const recognition = createRecognitionScenarioFixture(`${label}-recognition`);
  await harness.authorizeMaintainer(second);
  await harness.authorizeMaintainer(third);
  const formerPolicyCommitment = Buffer.from((await harness.simulator.getLedger()).governancePolicyCommitment);
  await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  return { harness, second, third, recognition, formerPolicyCommitment };
};

test("compact-recognition-proposal-old-policy-signature-replay", async () => {
  const { harness, second, third, recognition, formerPolicyCommitment } =
    await recognitionAfterPolicyRevision("isolated-recognition-proposal-policy-replay");
  const prepared = await harness.prepareRecognitionProposalAction(recognition);
  const evidence = await harness.signRecognitionProposalEvidence(prepared);
  const count = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.executeRecognitionProposalWithSignatures(recognition,
    [await signAction(harness, second, prepared, formerPolicyCommitment),
      await signAction(harness, third, prepared, formerPolicyCommitment)], evidence, prepared),
  /Invalid Jubjub Schnorr signature/u);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, count);
  await harness.executeRecognitionProposalWithSignatures(recognition,
    [await signAction(harness, second, prepared), await signAction(harness, third, prepared)], evidence, prepared);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, count + 1n);
});

test("compact-recognition-approval-old-policy-signature-replay", async () => {
  const { harness, second, third, recognition, formerPolicyCommitment } =
    await recognitionAfterPolicyRevision("isolated-recognition-approval-policy-replay");
  await harness.proposeRecognition(recognition);
  const prepared = await harness.prepareRecognitionDecisionAction(recognition, "approve");
  const count = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.executeRecognitionDecisionWithSignatures(recognition, "approve",
    [await signAction(harness, second, prepared, formerPolicyCommitment),
      await signAction(harness, third, prepared, formerPolicyCommitment)]),
  /Invalid Jubjub Schnorr signature/u);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, count);
  await harness.executeRecognitionDecisionWithSignatures(recognition, "approve",
    [await signAction(harness, second, prepared), await signAction(harness, third, prepared)]);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, count + 1n);
});

test("issuer-current-policy-after-threshold-change", async () => {
  const { client, historical, current } = await revisedPolicyEvidence("isolated-current-policy");
  assert.notEqual(historical.policy.version, current.policy.version);
  assert.ok(await client.verifyIssuerAuthorizationBundle(current, {}));
});

test("issuer-old-policy-current-time-replay", async () => {
  const { client, historical, current } = await revisedPolicyEvidence("isolated-policy-current-replay");
  await assert.rejects(client.verifyIssuerAuthorizationBundle(
    historical, { evaluationTime: current.policy.effectiveFrom },
  ), /policy snapshot is superseded/iu);
  assert.ok(await client.verifyIssuerAuthorizationBundle(current, {}));
});

test("issuer-uncommitted-policy-version", async () => {
  const { client, historical } = await revisedPolicyEvidence("isolated-policy-version-tamper");
  await assert.rejects(client.verifyIssuerAuthorizationBundle({
    ...historical, policy: { ...historical.policy, version: "v9" },
  }, {}), /not committed to the ledger/iu);
  assert.ok(await client.verifyIssuerAuthorizationBundle(historical, {}));
});

test("verifier-uncommitted-policy-version", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-verifier-policy-version");
  const second = createMaintainerScenarioFixture("isolated-verifier-policy-second");
  const third = createMaintainerScenarioFixture("isolated-verifier-policy-third");
  const verifier = createVerifierScenarioFixture("isolated-verifier-policy-target");
  await harness.authorizeMaintainer(second);
  await harness.authorizeMaintainer(third);
  await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  await harness.proposeVerifier(verifier, [second]);
  await harness.approveVerifier(verifier, [second]);
  await harness.activateVerifier(verifier, [second]);
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  const bundle = await harness.evaluateCurrentVerifierDecision(verifier);
  assert.ok(await client.verifyVerifierAuthorizationBundle(bundle, {}));
  await assert.rejects(client.verifyVerifierAuthorizationBundle({
    ...bundle, policy: { ...bundle.policy, version: "v9" },
  }, {}), /not committed to the ledger/iu);
});

test("issuer-historical-proof-tampered-after-policy-revision", async () => {
  const { client, historical } = await revisedPolicyEvidence("isolated-historical-proof-tamper");
  const sibling = historical.inclusionProof.path[0];
  assert.ok(sibling);
  const changed = `${sibling.slice(0, -1)}${sibling.endsWith("0") ? "1" : "0"}`;
  await assert.rejects(client.verifyIssuerAuthorizationBundle({
    ...historical,
    inclusionProof: { ...historical.inclusionProof, path: [changed] },
  }, {}), /event sibling/iu);
  assert.ok(await client.verifyIssuerAuthorizationBundle(historical, {}));
});

test("issuer-historical-epoch-signature-tampered", async () => {
  const { client, historical } = await revisedPolicyEvidence("isolated-historical-signature-tamper");
  const signed = historical.epoch.maintainerSignatures[0];
  assert.ok(signed);
  const changed = `0x${signed.signature[2] === "0" ? "1" : "0"}${signed.signature.slice(3)}`;
  await assert.rejects(client.verifyIssuerAuthorizationBundle({
    ...historical,
    epoch: {
      ...historical.epoch,
      maintainerSignatures: [{ ...signed, signature: changed }],
    },
  }, {}), /invalid/iu);
  assert.ok(await client.verifyIssuerAuthorizationBundle(historical, {}));
});

for (const role of [
  {
    name: "verifier",
    fixture: createVerifierScenarioFixture,
    propose: "proposeVerifier",
    prepare: "prepareVerifierDecisionAction",
    execute: "executeVerifierDecisionWithSignatures",
    approve: "approveVerifier",
    activate: "activateVerifier",
    evaluate: "evaluateCurrentVerifierDecision",
    verify: "verifyVerifierAuthorizationBundle",
  },
  {
    name: "auditor",
    fixture: createAuditorScenarioFixture,
    propose: "proposeAuditor",
    prepare: "prepareAuditorDecisionAction",
    execute: "executeAuditorDecisionWithSignatures",
    approve: "approveAuditor",
    activate: "activateAuditor",
    evaluate: "evaluateCurrentAuditorDecision",
    verify: "verifyAuditorAuthorizationBundle",
  },
  {
    name: "maintainer",
    fixture: createMaintainerScenarioFixture,
    propose: "proposeMaintainer",
    prepare: "prepareMaintainerDecisionAction",
    execute: "executeMaintainerDecisionWithSignatures",
    approve: "approveMaintainer",
    activate: "activateMaintainer",
    evaluate: "evaluateCurrentMaintainerDecision",
    verify: null,
  },
]) {
  const newPolicyCandidate = async (label) => {
    const harness = new LocalTrustRegistryIntegrationHarness(label);
    const second = createMaintainerScenarioFixture(`${label}-second`);
    const third = createMaintainerScenarioFixture(`${label}-third`);
    const candidate = role.fixture(`${label}-${role.name}`);
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(third);
    await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    await harness[role.propose](candidate);
    return { harness, second, candidate };
  };

  test(`${role.name}-revised-policy-insufficient-quorum`, async () => {
    const { harness, second, candidate } = await newPolicyCandidate(`isolated-${role.name}-quorum`);
    const prepared = await harness[role.prepare](candidate, "approve");
    const before = (await harness.simulator.getLedger()).governanceActionCount;
    await assert.rejects(harness[role.execute](
      candidate, "approve", [await signAction(harness, second, prepared)],
    ), /Maintainer signer count must satisfy the action threshold/u);
    assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
    await harness[role.approve](candidate, [second]);
  });

  test(`${role.name}-current-policy-after-threshold-change`, async () => {
    const { harness, second, candidate } = await newPolicyCandidate(`isolated-${role.name}-current`);
    await harness[role.approve](candidate, [second]);
    await harness[role.activate](candidate, [second]);
    if (role.verify) {
      const client = new TrustRegistrySimulatorClient(harness.simulator);
      assert.ok(await client[role.verify](await harness[role.evaluate](candidate), {}));
    } else {
      const membership = await harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment);
      assert.equal(membership.status, AuthorizationStatus.active);
    }
  });
}

test("issuer-tampered-merkle-path", async () => {
  const { harness, client, bundle } = await activeIssuerEvidence("isolated-issuer-path");
  const sibling = bundle.inclusionProof.path[0];
  assert.ok(sibling);
  const changed = `${sibling.slice(0, -1)}${sibling.endsWith("0") ? "1" : "0"}`;
  await assert.rejects(client.verifyIssuerAuthorizationBundle({
    ...bundle,
    inclusionProof: { ...bundle.inclusionProof, path: [changed] },
  }, { expectedRegistryId: harness.registryId }), /event sibling/iu);
  assert.ok(await client.verifyIssuerAuthorizationBundle(bundle, { expectedRegistryId: harness.registryId }));
});

test("issuer-wrong-credential-family", async () => {
  const { client, bundle } = await activeIssuerEvidence("isolated-issuer-resource");
  await assert.rejects(client.verifyIssuerAuthorizationBundle(bundle, {
    expectedResourceId: "credential-family:unknown",
  }), /issuer authorization resource mismatch/iu);
  assert.ok(await client.verifyIssuerAuthorizationBundle(bundle, {}));
});

test("verifier-wrong-request-profile", async () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-verifier-resource");
  const verifier = createVerifierScenarioFixture("isolated-verifier-profile");
  await harness.authorizeVerifier(verifier);
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  const bundle = await harness.evaluateCurrentVerifierDecision(verifier);
  assert.ok(await client.verifyVerifierAuthorizationBundle(bundle, {}));
  await assert.rejects(client.verifyVerifierAuthorizationBundle(bundle, {
    expectedResourceId: "request-profile:unknown",
  }), /verifier authorization resource mismatch/iu);
  assert.ok(await client.verifyVerifierAuthorizationBundle(bundle, {}));
});

test("issuer-wrong-registry", async () => {
  const { harness, client, bundle } = await activeIssuerEvidence("isolated-issuer-registry");
  await assert.rejects(client.verifyIssuerAuthorizationBundle(bundle, {
    expectedRegistryId: "registry:wrong",
  }), /registry mismatch/iu);
  assert.ok(await client.verifyIssuerAuthorizationBundle(bundle, { expectedRegistryId: harness.registryId }));
});

test("issuer-expired-epoch", async () => {
  const { harness, client, bundle } = await activeIssuerEvidence("isolated-issuer-epoch");
  const afterExpiry = new Date(Date.parse(bundle.epoch.validUntil) + 1).toISOString();
  await assert.rejects(client.verifyIssuerAuthorizationBundle(bundle, {
    expectedRegistryId: harness.registryId,
    evaluationTime: afterExpiry,
  }), /epoch|expired|valid/iu);
  assert.ok(await client.verifyIssuerAuthorizationBundle(bundle, { expectedRegistryId: harness.registryId }));
});

for (const lifecycle of [
  { name: "suspended", transition: "suspendIssuer" },
  { name: "revoked", transition: "revokeIssuer" },
]) {
  const changedIssuer = async (label) => {
    const fixture = await activeIssuerEvidence(label);
    await fixture.harness[lifecycle.transition](fixture.issuer);
    const latest = await fixture.harness.buildIssuerHistoricalEvidence(fixture.issuer);
    assert.equal(latest.authorization.status, lifecycle.name);
    return { ...fixture, latest };
  };

  test(`issuer-${lifecycle.name}`, async () => {
    const { harness, client, latest, bundle } = await changedIssuer(`isolated-issuer-${lifecycle.name}`);
    await assert.rejects(client.verifyIssuerAuthorizationBundle(latest, {
      expectedRegistryId: harness.registryId,
    }), /not active/iu);
    assert.ok(await client.verifyIssuerAuthorizationBundle(bundle, {
      expectedRegistryId: harness.registryId,
      evaluationTime: bundle.authorization.activeFrom,
    }));
  });

  test(`issuer-historical-after-${lifecycle.name === "suspended" ? "suspension" : "revocation"}`, async () => {
    const { harness, client, bundle } = await changedIssuer(`isolated-issuer-history-${lifecycle.name}`);
    assert.ok(await client.verifyIssuerAuthorizationBundle(bundle, {
      expectedRegistryId: harness.registryId,
      evaluationTime: bundle.authorization.activeFrom,
    }));
  });
}
