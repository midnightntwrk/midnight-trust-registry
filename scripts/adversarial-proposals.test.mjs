import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import {
  computeCreateIssuerAuthorizationPayloadHash,
  computeIssuerEvidenceBoundProposalPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  signDeploymentBoundMaintainerActionFromSeed,
  signIssuerProposalEvidenceFromSeed,
  verifyIssuerProposalEvidenceSignature,
} from "../contracts/trust-registry/dist/index.js";
import { bytes32Commitment } from "../packages/trust-registry-client/dist/index.js";
import {
  createAuditorAuthorizationScopeFixture,
  createAuditorScenarioFixture,
  createIssuerAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createMaintainerAuthorizationScopeFixture,
  createMaintainerScenarioFixture,
  createVerifierAuthorizationScopeFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";

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

const issuerProposal = (label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const second = createMaintainerScenarioFixture(`${label}-second`);
  const third = createMaintainerScenarioFixture(`${label}-third`);
  const issuer = createIssuerScenarioFixture(`${label}-issuer`);
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const evidence = harness.createApplicationEvidence({
    applicationId: issuer.authorizationId,
    subjectDid: issuer.subjectDid,
    role: "issuer",
    scope: createIssuerAuthorizationScopeFixture(issuer),
    governedResource: { type: "credentialFamily", id: issuer.resourceId },
  });
  const prepared = harness.prepareIssuerProposalAction(issuer, evidence);
  const verifierSignature = harness.signIssuerProposalEvidence(prepared);
  const signatures = [signAction(harness, second, prepared), signAction(harness, third, prepared)];
  return { harness, issuer, evidence, prepared, verifierSignature, signatures };
};

const submitRawIssuerProposal = (harness, issuer, prepared, verifierSignature, signers) => {
  const [primary, ...coSigners] = signers;
  assert.ok(primary);
  return harness.simulator.proposeIssuerAuthorization(
    primary.keyId, primary.publicKey, primary.signature,
    issuer.authorizationIdCommitment, issuer.subjectDidCommitment,
    issuer.resourceType, issuer.resourceIdCommitment,
    prepared.policyCommitment, prepared.statusPolicyBindingCommitment,
    bytes32Commitment(issuer.trustLevel), prepared.evidenceHash,
    prepared.evidenceVerifierAuthorizationId,
    prepared.evidenceVerifierKeyIdCommitment,
    verifierSignature, coSigners,
  );
};

test("compact-issuer-proposal-insufficient-quorum", () => {
  const { harness, issuer, evidence, verifierSignature, signatures } =
    issuerProposal("isolated-issuer-proposal-quorum");
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.executeIssuerProposalWithSignatures(
    issuer, evidence, signatures.slice(0, 1), verifierSignature,
  ), /Maintainer signer count must satisfy the action threshold/u);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  harness.executeIssuerProposalWithSignatures(issuer, evidence, signatures, verifierSignature);
});

test("compact-issuer-proposal-duplicate-signer", () => {
  const { harness, issuer, evidence, verifierSignature, signatures } =
    issuerProposal("isolated-issuer-proposal-duplicate");
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.executeIssuerProposalWithSignatures(
    issuer, evidence, [signatures[0], signatures[0]], verifierSignature,
  ), /Maintainer signer keys must be sorted/u);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  harness.executeIssuerProposalWithSignatures(issuer, evidence, signatures, verifierSignature);
});

test("compact-issuer-proposal-altered-evidence-hash", () => {
  const { harness, issuer, evidence, prepared, verifierSignature, signatures } =
    issuerProposal("isolated-issuer-proposal-evidence-substitution");
  const alteredHash = Uint8Array.from(prepared.evidenceHash);
  alteredHash[0] ^= 1;
  const baseHash = computeCreateIssuerAuthorizationPayloadHash(
    issuer.authorizationIdCommitment, issuer.subjectDidCommitment,
    issuer.resourceType, issuer.resourceIdCommitment,
    prepared.policyCommitment, prepared.statusPolicyBindingCommitment,
    bytes32Commitment(issuer.trustLevel), alteredHash,
  );
  const altered = {
    ...prepared,
    evidenceHash: alteredHash,
    actionPayloadHash: computeIssuerEvidenceBoundProposalPayloadHash(
      baseHash, prepared.evidenceVerifierAuthorizationId,
      prepared.evidenceVerifierKeyIdCommitment,
      prepared.policyCommitment, prepared.policyVersion,
    ),
  };
  const alteredVerifierSignature = harness.signIssuerProposalEvidence(altered);
  const verifierKey = harness.simulator.getEvidenceVerifierKey(altered.evidenceVerifierAuthorizationId);
  assert.equal(verifyIssuerProposalEvidenceSignature(
    verifierKey.publicKey, altered.registryId, altered.evidenceVerifierKeyIdCommitment,
    altered.actionPayloadHash, alteredVerifierSignature,
  ), true);
  const second = createMaintainerScenarioFixture("isolated-issuer-proposal-evidence-substitution-second");
  const third = createMaintainerScenarioFixture("isolated-issuer-proposal-evidence-substitution-third");
  const before = harness.simulator.getLedger().governanceActionCount;
  const originalContext = harness.simulator.circuitContext;
  try {
    submitRawIssuerProposal(harness, issuer, altered, alteredVerifierSignature, [
      signAction(harness, second, altered), signAction(harness, third, altered),
    ]);
    assert.equal(harness.simulator.getLedger().governanceActionCount, before + 1n);
  } finally {
    harness.simulator.circuitContext = originalContext;
  }
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  assert.throws(() => submitRawIssuerProposal(
    harness, issuer, altered, alteredVerifierSignature, signatures,
  ), /Invalid Jubjub Schnorr signature/u);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  harness.executeIssuerProposalWithSignatures(issuer, evidence, signatures, verifierSignature);
});

test("issuer-unauthorized-evidence-verifier-compact", () => {
  const { harness, issuer, evidence, prepared, verifierSignature, signatures } =
    issuerProposal("isolated-issuer-unauthorized-verifier");
  const outsider = createMaintainerScenarioFixture("isolated-unauthorized-verifier-key");
  const wrongSignature = signIssuerProposalEvidenceFromSeed(
    outsider.seed, prepared.registryId, prepared.evidenceVerifierKeyIdCommitment,
    prepared.actionPayloadHash,
  );
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.executeIssuerProposalWithSignatures(
    issuer, evidence, signatures, wrongSignature,
  ), /signature|verifier|assert|authorized/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  harness.executeIssuerProposalWithSignatures(issuer, evidence, signatures, verifierSignature);
});

const pendingIssuerApproval = (label) => {
  const setup = issuerProposal(label);
  setup.harness.executeIssuerProposalWithSignatures(
    setup.issuer, setup.evidence, setup.signatures, setup.verifierSignature,
  );
  const prepared = setup.harness.prepareIssuerDecisionAction(setup.issuer, "approve");
  const second = createMaintainerScenarioFixture(`${label}-second`);
  const third = createMaintainerScenarioFixture(`${label}-third`);
  const signatures = [
    signAction(setup.harness, second, prepared),
    signAction(setup.harness, third, prepared),
  ];
  return { ...setup, prepared, approvalSignatures: signatures };
};

test("compact-issuer-altered-evidence-hash", () => {
  const { harness, issuer, prepared, approvalSignatures } =
    pendingIssuerApproval("isolated-issuer-approval-evidence");
  const altered = Uint8Array.from(prepared.evidenceHash);
  altered[0] ^= 1;
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.simulator.authorizeIssuerAuthorization(
    approvalSignatures[0].keyId,
    approvalSignatures[0].publicKey,
    approvalSignatures[0].signature,
    issuer.authorizationIdCommitment,
    altered,
    approvalSignatures.slice(1),
  ), /evidence|match/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  harness.executeIssuerDecisionWithSignatures(issuer, "approve", approvalSignatures);
});

test("compact-issuer-insufficient-quorum", () => {
  const { harness, issuer, approvalSignatures } =
    pendingIssuerApproval("isolated-issuer-approval-quorum");
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.executeIssuerDecisionWithSignatures(
    issuer, "approve", approvalSignatures.slice(0, 1),
  ), /quorum|threshold|assert|signature|maintainer/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  harness.executeIssuerDecisionWithSignatures(issuer, "approve", approvalSignatures);
});

test("compact-issuer-duplicate-signer", () => {
  const { harness, issuer, approvalSignatures } =
    pendingIssuerApproval("isolated-issuer-approval-duplicate");
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.executeIssuerDecisionWithSignatures(
    issuer, "approve", [approvalSignatures[0], approvalSignatures[0]],
  ), /quorum|threshold|assert|signature|maintainer|duplicate/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  harness.executeIssuerDecisionWithSignatures(issuer, "approve", approvalSignatures);
});

test("compact-issuer-unknown-signer", () => {
  const { harness, issuer, prepared, approvalSignatures } =
    pendingIssuerApproval("isolated-issuer-approval-outsider");
  const outsider = createMaintainerScenarioFixture("isolated-issuer-outsider");
  const before = harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => harness.executeIssuerDecisionWithSignatures(
    issuer, "approve", [approvalSignatures[0], signAction(harness, outsider, prepared)],
  ), /assert|signature|maintainer|authorized|registered/iu);
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  harness.executeIssuerDecisionWithSignatures(issuer, "approve", approvalSignatures);
});

for (const role of [
  {
    name: "verifier",
    fixture: createVerifierScenarioFixture,
    id: (fixture) => fixture.authorizationId,
    scope: (harness, fixture) => createVerifierAuthorizationScopeFixture(fixture),
    resource: (harness, fixture) => ({ type: "requestProfile", id: fixture.scopeResourceId }),
    prepare: "prepareVerifierProposalAction",
    sign: "signVerifierProposalEvidence",
    execute: "executeVerifierProposalWithSignatures",
  },
  {
    name: "auditor",
    fixture: createAuditorScenarioFixture,
    id: (fixture) => fixture.authorizationId,
    scope: (harness, fixture) => createAuditorAuthorizationScopeFixture(fixture),
    resource: (harness, fixture) => ({ type: "requestProfile", id: fixture.scopeResourceId }),
    prepare: "prepareAuditorProposalAction",
    sign: "signAuditorProposalEvidence",
    execute: "executeAuditorProposalWithSignatures",
  },
  {
    name: "maintainer",
    fixture: createMaintainerScenarioFixture,
    id: (fixture) => fixture.maintainerId,
    scope: (harness) => createMaintainerAuthorizationScopeFixture(harness.registryId),
    resource: (harness) => ({ type: "registry", id: harness.registryId }),
    prepare: "prepareMaintainerProposalAction",
    sign: "signMaintainerProposalEvidence",
    execute: "executeMaintainerProposalWithSignatures",
  },
]) {
  const proposal = (label) => {
    const harness = new LocalTrustRegistryIntegrationHarness(label);
    const second = createMaintainerScenarioFixture(`${label}-second`);
    const third = createMaintainerScenarioFixture(`${label}-third`);
    const fixture = role.fixture(`${label}-${role.name}`);
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const evidence = harness.createApplicationEvidence({
      applicationId: role.id(fixture),
      subjectDid: fixture.subjectDid,
      role: role.name,
      scope: role.scope(harness, fixture),
      governedResource: role.resource(harness, fixture),
    });
    const prepared = harness[role.prepare](fixture, evidence);
    const verifierSignature = harness[role.sign](prepared);
    const signatures = [signAction(harness, second, prepared), signAction(harness, third, prepared)];
    return { harness, fixture, evidence, verifierSignature, signatures };
  };

  test(`compact-${role.name}-proposal-insufficient-quorum`, () => {
    const { harness, fixture, evidence, verifierSignature, signatures } =
      proposal(`isolated-${role.name}-proposal-quorum`);
    const before = harness.simulator.getLedger().governanceActionCount;
    assert.throws(() => harness[role.execute](
      fixture, evidence, signatures.slice(0, 1), verifierSignature,
    ), /Maintainer signer count must satisfy the action threshold/u);
    assert.equal(harness.simulator.getLedger().governanceActionCount, before);
    harness[role.execute](fixture, evidence, signatures, verifierSignature);
  });

  test(`compact-${role.name}-proposal-duplicate-signer`, () => {
    const { harness, fixture, evidence, verifierSignature, signatures } =
      proposal(`isolated-${role.name}-proposal-duplicate`);
    const before = harness.simulator.getLedger().governanceActionCount;
    assert.throws(() => harness[role.execute](
      fixture, evidence, [signatures[0], signatures[0]], verifierSignature,
    ), /Maintainer signer keys must be sorted/u);
    assert.equal(harness.simulator.getLedger().governanceActionCount, before);
    harness[role.execute](fixture, evidence, signatures, verifierSignature);
  });
}
