import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import {
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { bytes32Commitment } from "../packages/trust-registry-client/dist/index.js";
import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import { computeApplicationEvidenceCommitment } from "../packages/trust-registry-domain/dist/index.js";
import {
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
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

const signAction = (harness, maintainer, prepared) => {
  const ledger = harness.simulator.getLedger();
  return {
    keyId: maintainer.keyId,
    publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
    signature: signDeploymentBoundMaintainerActionFromSeed(
      maintainer.seed,
      ledger.registryId,
      ledger.deploymentNetworkIdCommitment,
      Buffer.from(harness.simulator.contractAddress, "hex"),
      ledger.governancePolicyCommitment,
      prepared.actionKind,
      prepared.actionPayloadHash,
      prepared.actionSequence,
    ),
  };
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
  const issuer = createIssuerScenarioFixture("isolated-old-signature-issuer");
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.proposeIssuer(issuer);
  const prepared = harness.prepareIssuerDecisionAction(issuer, "approve");
  const oldSignature = signAction(harness, second, prepared);
  const oldCoSignature = signAction(harness, third, prepared);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.simulator.authorizeIssuerAuthorization(
    oldSignature.keyId, oldSignature.publicKey, oldSignature.signature,
    issuer.authorizationIdCommitment, prepared.evidenceHash, [oldCoSignature],
  ), /signature|policy|assert|maintainer/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  const current = createIssuerScenarioFixture("isolated-current-signature-issuer");
  harness.proposeIssuer(current, [second]);
  harness.approveIssuer(current, [second]);
});
