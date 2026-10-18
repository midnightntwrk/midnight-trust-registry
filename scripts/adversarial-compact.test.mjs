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
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";

const bootstrapMembership = (harness) => ({
  maintainerIdCommitment: harness.maintainerIdCommitment,
  maintainerId: harness.maintainerId,
  subjectDidCommitment: harness.maintainerDidCommitment,
  keyId: harness.simulator.getLedger().lastAuthorizedMaintainerKeyId,
  seed: new Uint8Array(32),
  subjectDid: harness.maintainerDid,
  trustLevel: "bootstrap-maintainer",
});

const signAction = (harness, maintainer, prepared, policyCommitment) => {
  const ledger = harness.simulator.getLedger();
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

const revisedPolicyEvidence = (label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const second = createMaintainerScenarioFixture(`${label}-second`);
  const third = createMaintainerScenarioFixture(`${label}-third`);
  const historicalIssuer = createIssuerScenarioFixture(`${label}-historical`);
  const currentIssuer = createIssuerScenarioFixture(`${label}-current`);
  harness.authorizeIssuer(historicalIssuer);
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  harness.proposeIssuer(currentIssuer, [second]);
  harness.approveIssuer(currentIssuer, [second]);
  harness.activateIssuer(currentIssuer, [second]);
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  const historical = harness.buildIssuerHistoricalEvidence(historicalIssuer);
  const current = harness.evaluateCurrentIssuerDecision(currentIssuer);
  assert.equal(historical.policy.version, "v1");
  assert.equal(current.policy.version, "v2");
  assert.ok(client.verifyIssuerAuthorizationBundle(historical, {}));
  assert.ok(client.verifyIssuerAuthorizationBundle(current, {}));
  return { client, historical, current };
};

const activeIssuerEvidence = (label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const issuer = createIssuerScenarioFixture(`${label}-issuer`);
  harness.authorizeIssuer(issuer);
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  const bundle = harness.evaluateCurrentIssuerDecision(issuer);
  assert.ok(client.verifyIssuerAuthorizationBundle(bundle, { expectedRegistryId: harness.registryId }));
  return { harness, issuer, client, bundle };
};

test("compact-self-voted-maintainer-suspension", () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-self-suspension");
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.equal(harness.simulator.getLedger().activeMaintainerCount, 1n);
  assert.throws(() => harness.suspendMaintainer(bootstrapMembership(harness)), /own DID/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  assert.equal(harness.simulator.getLedger().activeMaintainerCount, 1n);
});

test("compact-self-voted-maintainer-revocation", () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-self-revocation");
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.equal(harness.simulator.getLedger().activeMaintainerCount, 1n);
  assert.throws(() => harness.revokeMaintainer(bootstrapMembership(harness)), /own DID/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  assert.equal(harness.simulator.getLedger().activeMaintainerCount, 1n);
});

test("compact-removal-below-maintainer-threshold", () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-removal-threshold");
  const second = createMaintainerScenarioFixture("isolated-removal-second");
  const third = createMaintainerScenarioFixture("isolated-removal-third");
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 1n, [second]);
  const target = bootstrapMembership(harness);
  const prepared = harness.prepareMaintainerDecisionAction(target, "suspend");
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.equal(harness.simulator.getLedger().activeMaintainerCount, 3n);
  assert.throws(() => harness.executeMaintainerDecisionWithSignatures(
    target, "suspend", [signAction(harness, second, prepared)],
  ), /non-conflicted removal quorum/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  assert.equal(harness.simulator.getLedger().activeMaintainerCount, 3n);
});

test("compact-removed-maintainer-signer", () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-removed-signer");
  const removed = createMaintainerScenarioFixture("isolated-removed-key");
  const issuer = createIssuerScenarioFixture("isolated-removed-issuer");
  harness.authorizeMaintainer(removed);
  harness.suspendMaintainer(removed);
  harness.proposeIssuer(issuer);
  const prepared = harness.prepareIssuerDecisionAction(issuer, "approve");
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.executeIssuerDecisionWithSignatures(
    issuer, "approve", [signAction(harness, removed, prepared)],
  ), /active|authorized|maintainer|signature|assert/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
});

test("denied-proposal-blocks-live-scope-reuse", () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-live-scope");
  const issuer = createIssuerScenarioFixture("isolated-live-scope-issuer");
  const replacementId = `${issuer.authorizationId}:replacement`;
  const replacement = {
    ...issuer,
    authorizationId: replacementId,
    authorizationIdCommitment: bytes32Commitment(replacementId),
  };
  harness.proposeIssuer(issuer);
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.proposeIssuer(replacement), /live authorization/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
});

test("denied-proposal-requires-quorum", () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-denial-quorum");
  const second = createMaintainerScenarioFixture("isolated-denial-second");
  const third = createMaintainerScenarioFixture("isolated-denial-third");
  const issuer = createIssuerScenarioFixture("isolated-denial-issuer");
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.proposeIssuer(issuer);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const prepared = harness.prepareIssuerDecisionAction(issuer, "archive");
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.executeIssuerDecisionWithSignatures(
    issuer, "archive", [signAction(harness, second, prepared)],
  ), /threshold|quorum|signer|authorization/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  const archived = harness.executeIssuerDecisionWithSignatures(
    issuer, "archive", [signAction(harness, second, prepared), signAction(harness, third, prepared)],
  );
  assert.equal(archived.length, 32);
});

test("denied-proposal-is-not-trust", () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-archived-proposal");
  const issuer = createIssuerScenarioFixture("isolated-archived-issuer");
  harness.proposeIssuer(issuer);
  harness.archiveIssuer(issuer);
  const bundle = harness.buildIssuerHistoricalEvidence(issuer);
  assert.equal(bundle.authorization.status, "archived");
  assert.equal(bundle.authorization.authorizedAt, undefined);
  assert.throws(() => new TrustRegistrySimulatorClient(harness.simulator)
    .verifyIssuerAuthorizationBundle(bundle, {}), /not active/iu);
});

test("issuer-signed-wrong-policy-id", () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-wrong-evidence-policy");
  const issuer = createIssuerScenarioFixture("isolated-wrong-evidence-policy-issuer");
  const evidence = harness.createApplicationEvidence({
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
  assert.equal(harness.verifyApplicationEvidenceSignature(
    signed.commitment, signed.signature, harness.evidenceVerifier,
  ), true);
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.proposeIssuerWithApplicationEvidence(issuer, signed), /policyId does not match/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  harness.proposeIssuerWithApplicationEvidence(issuer, evidence);
});

test("issuer-expired-signed-application-evidence", () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-expired-evidence");
  const issuer = createIssuerScenarioFixture("isolated-expired-evidence-issuer");
  const evidence = harness.createApplicationEvidence({
    applicationId: issuer.authorizationId,
    subjectDid: issuer.subjectDid,
    role: "issuer",
    scope: createIssuerAuthorizationScopeFixture(issuer),
    governedResource: { type: "credentialFamily", id: issuer.resourceId },
  });
  harness.advanceEvidenceTimeBy(24 * 60 * 60 * 1000 + 1);
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.proposeIssuerWithApplicationEvidence(issuer, evidence), /evidence is expired/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  const fresh = harness.createApplicationEvidence({
    applicationId: issuer.authorizationId,
    subjectDid: issuer.subjectDid,
    role: "issuer",
    scope: createIssuerAuthorizationScopeFixture(issuer),
    governedResource: { type: "credentialFamily", id: issuer.resourceId },
  });
  harness.proposeIssuerWithApplicationEvidence(issuer, fresh);
});

test("integration-old-policy-application-preflight", () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-old-policy-application");
  const second = createMaintainerScenarioFixture("isolated-old-policy-second");
  const third = createMaintainerScenarioFixture("isolated-old-policy-third");
  const issuer = createIssuerScenarioFixture("isolated-old-policy-issuer");
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.proposeIssuer(issuer);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.prepareIssuerDecisionAction(issuer, "approve"), /policyVersion does not match/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  const current = createIssuerScenarioFixture("isolated-current-policy-issuer");
  harness.proposeIssuer(current, [second]);
  harness.approveIssuer(current, [second]);
});

test("compact-old-policy-signature-replay", () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-old-policy-signature");
  const second = createMaintainerScenarioFixture("isolated-old-signature-second");
  const third = createMaintainerScenarioFixture("isolated-old-signature-third");
  const issuer = createIssuerScenarioFixture("isolated-current-signature-issuer");
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  const oldPolicyCommitment = Buffer.from(harness.simulator.getLedger().governancePolicyCommitment);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  harness.proposeIssuer(issuer, [second]);
  const prepared = harness.prepareIssuerDecisionAction(issuer, "approve");
  const oldSignature = signAction(harness, second, prepared, oldPolicyCommitment);
  const oldCoSignature = signAction(harness, third, prepared, oldPolicyCommitment);
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.simulator.authorizeIssuerAuthorization(
    oldSignature.keyId, oldSignature.publicKey, oldSignature.signature,
    issuer.authorizationIdCommitment, prepared.evidenceHash, [oldCoSignature],
  ), /Invalid Jubjub Schnorr signature/u);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  const currentSignature = signAction(harness, second, prepared);
  const currentCoSignature = signAction(harness, third, prepared);
  harness.simulator.authorizeIssuerAuthorization(
    currentSignature.keyId, currentSignature.publicKey, currentSignature.signature,
    issuer.authorizationIdCommitment, prepared.evidenceHash, [currentCoSignature],
  );
  assert.equal(harness.simulator.getLedger().governanceActionCount, before + 1n);
});

test("compact-recovery-policy-headroom-required", () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-recovery-headroom");
  const second = createMaintainerScenarioFixture("isolated-recovery-second");
  const third = createMaintainerScenarioFixture("isolated-recovery-third");
  const candidate = createMaintainerScenarioFixture("isolated-recovery-candidate");
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.authorizeMaintainer(candidate);
  harness.updateMaintainerThresholdPolicy(3n, 1n, 2n);
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.equal(harness.simulator.getLedger().activeMaintainerCount, 4n);
  assert.throws(() => harness.suspendMaintainer(candidate), /non-conflicted removal quorum/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n, [second, third]);
  harness.suspendMaintainer(candidate);
  assert.equal(harness.simulator.getLedger().activeMaintainerCount, 3n);
});

test("issuer-history-survives-threshold-change", () => {
  const { client, historical, current } = revisedPolicyEvidence("isolated-history-survives");
  assert.notEqual(historical.epoch.policyRoot, current.epoch.policyRoot);
  assert.ok(client.verifyIssuerAuthorizationBundle(historical, {}));
});

test("issuer-current-policy-after-threshold-change", () => {
  const { client, historical, current } = revisedPolicyEvidence("isolated-current-policy");
  assert.notEqual(historical.policy.version, current.policy.version);
  assert.ok(client.verifyIssuerAuthorizationBundle(current, {}));
});

test("issuer-old-policy-current-time-replay", () => {
  const { client, historical, current } = revisedPolicyEvidence("isolated-policy-current-replay");
  assert.throws(() => client.verifyIssuerAuthorizationBundle(
    historical, { evaluationTime: current.policy.effectiveFrom },
  ), /policy snapshot is superseded/iu);
  assert.ok(client.verifyIssuerAuthorizationBundle(current, {}));
});

test("issuer-uncommitted-policy-version", () => {
  const { client, historical } = revisedPolicyEvidence("isolated-policy-version-tamper");
  assert.throws(() => client.verifyIssuerAuthorizationBundle({
    ...historical, policy: { ...historical.policy, version: "v9" },
  }, {}), /not committed to the ledger/iu);
  assert.ok(client.verifyIssuerAuthorizationBundle(historical, {}));
});

test("issuer-historical-proof-tampered-after-policy-revision", () => {
  const { client, historical } = revisedPolicyEvidence("isolated-historical-proof-tamper");
  const sibling = historical.inclusionProof.path[0];
  assert.ok(sibling);
  const changed = `${sibling.slice(0, -1)}${sibling.endsWith("0") ? "1" : "0"}`;
  assert.throws(() => client.verifyIssuerAuthorizationBundle({
    ...historical,
    inclusionProof: { ...historical.inclusionProof, path: [changed] },
  }, {}), /event sibling/iu);
  assert.ok(client.verifyIssuerAuthorizationBundle(historical, {}));
});

test("issuer-historical-epoch-signature-tampered", () => {
  const { client, historical } = revisedPolicyEvidence("isolated-historical-signature-tamper");
  const signed = historical.epoch.maintainerSignatures[0];
  assert.ok(signed);
  const changed = `0x${signed.signature[2] === "0" ? "1" : "0"}${signed.signature.slice(3)}`;
  assert.throws(() => client.verifyIssuerAuthorizationBundle({
    ...historical,
    epoch: {
      ...historical.epoch,
      maintainerSignatures: [{ ...signed, signature: changed }],
    },
  }, {}), /invalid/iu);
  assert.ok(client.verifyIssuerAuthorizationBundle(historical, {}));
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
  const newPolicyCandidate = (label) => {
    const harness = new LocalTrustRegistryIntegrationHarness(label);
    const second = createMaintainerScenarioFixture(`${label}-second`);
    const third = createMaintainerScenarioFixture(`${label}-third`);
    const candidate = role.fixture(`${label}-${role.name}`);
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    harness[role.propose](candidate);
    return { harness, second, candidate };
  };

  test(`${role.name}-revised-policy-insufficient-quorum`, () => {
    const { harness, second, candidate } = newPolicyCandidate(`isolated-${role.name}-quorum`);
    const prepared = harness[role.prepare](candidate, "approve");
    const before = harness.simulator.getLedger().governanceActionCount;
    assert.throws(() => harness[role.execute](
      candidate, "approve", [signAction(harness, second, prepared)],
    ), /Maintainer signer count must satisfy the action threshold/u);
    assert.equal(harness.simulator.getLedger().governanceActionCount, before);
    harness[role.approve](candidate, [second]);
  });

  test(`${role.name}-current-policy-after-threshold-change`, () => {
    const { harness, second, candidate } = newPolicyCandidate(`isolated-${role.name}-current`);
    harness[role.approve](candidate, [second]);
    harness[role.activate](candidate, [second]);
    if (role.verify) {
      const client = new TrustRegistrySimulatorClient(harness.simulator);
      assert.ok(client[role.verify](harness[role.evaluate](candidate), {}));
    } else {
      const membership = harness.simulator.getMaintainerMembership(candidate.maintainerIdCommitment);
      assert.equal(membership.status, AuthorizationStatus.active);
    }
  });
}

test("issuer-tampered-merkle-path", () => {
  const { harness, client, bundle } = activeIssuerEvidence("isolated-issuer-path");
  const sibling = bundle.inclusionProof.path[0];
  assert.ok(sibling);
  const changed = `${sibling.slice(0, -1)}${sibling.endsWith("0") ? "1" : "0"}`;
  assert.throws(() => client.verifyIssuerAuthorizationBundle({
    ...bundle,
    inclusionProof: { ...bundle.inclusionProof, path: [changed] },
  }, { expectedRegistryId: harness.registryId }), /event sibling/iu);
  assert.ok(client.verifyIssuerAuthorizationBundle(bundle, { expectedRegistryId: harness.registryId }));
});

test("issuer-wrong-credential-family", () => {
  const { client, bundle } = activeIssuerEvidence("isolated-issuer-resource");
  assert.throws(() => client.verifyIssuerAuthorizationBundle(bundle, {
    expectedResourceId: "credential-family:unknown",
  }), /issuer authorization resource mismatch/iu);
  assert.ok(client.verifyIssuerAuthorizationBundle(bundle, {}));
});

test("verifier-wrong-request-profile", () => {
  const harness = new LocalTrustRegistryIntegrationHarness("isolated-verifier-resource");
  const verifier = createVerifierScenarioFixture("isolated-verifier-profile");
  harness.authorizeVerifier(verifier);
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  const bundle = harness.evaluateCurrentVerifierDecision(verifier);
  assert.ok(client.verifyVerifierAuthorizationBundle(bundle, {}));
  assert.throws(() => client.verifyVerifierAuthorizationBundle(bundle, {
    expectedResourceId: "request-profile:unknown",
  }), /verifier authorization resource mismatch/iu);
  assert.ok(client.verifyVerifierAuthorizationBundle(bundle, {}));
});

test("issuer-wrong-registry", () => {
  const { harness, client, bundle } = activeIssuerEvidence("isolated-issuer-registry");
  assert.throws(() => client.verifyIssuerAuthorizationBundle(bundle, {
    expectedRegistryId: "registry:wrong",
  }), /registry mismatch/iu);
  assert.ok(client.verifyIssuerAuthorizationBundle(bundle, { expectedRegistryId: harness.registryId }));
});

test("issuer-expired-epoch", () => {
  const { harness, client, bundle } = activeIssuerEvidence("isolated-issuer-epoch");
  const afterExpiry = new Date(Date.parse(bundle.epoch.validUntil) + 1).toISOString();
  assert.throws(() => client.verifyIssuerAuthorizationBundle(bundle, {
    expectedRegistryId: harness.registryId,
    evaluationTime: afterExpiry,
  }), /epoch|expired|valid/iu);
  assert.ok(client.verifyIssuerAuthorizationBundle(bundle, { expectedRegistryId: harness.registryId }));
});

for (const lifecycle of [
  { name: "suspended", transition: "suspendIssuer" },
  { name: "revoked", transition: "revokeIssuer" },
]) {
  const changedIssuer = (label) => {
    const fixture = activeIssuerEvidence(label);
    fixture.harness[lifecycle.transition](fixture.issuer);
    const latest = fixture.harness.buildIssuerHistoricalEvidence(fixture.issuer);
    assert.equal(latest.authorization.status, lifecycle.name);
    return { ...fixture, latest };
  };

  test(`issuer-${lifecycle.name}`, () => {
    const { harness, client, latest, bundle } = changedIssuer(`isolated-issuer-${lifecycle.name}`);
    assert.throws(() => client.verifyIssuerAuthorizationBundle(latest, {
      expectedRegistryId: harness.registryId,
    }), /not active/iu);
    assert.ok(client.verifyIssuerAuthorizationBundle(bundle, {
      expectedRegistryId: harness.registryId,
      evaluationTime: bundle.authorization.activeFrom,
    }));
  });

  test(`issuer-historical-after-${lifecycle.name === "suspended" ? "suspension" : "revocation"}`, () => {
    const { harness, client, bundle } = changedIssuer(`isolated-issuer-history-${lifecycle.name}`);
    assert.ok(client.verifyIssuerAuthorizationBundle(bundle, {
      expectedRegistryId: harness.registryId,
      evaluationTime: bundle.authorization.activeFrom,
    }));
  });
}
