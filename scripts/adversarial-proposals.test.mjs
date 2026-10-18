import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";

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
  signDeploymentBoundMaintainerActionFromSeed,
  signIssuerProposalEvidenceFromSeed,
  verifyAuditorProposalEvidenceSignature,
  verifyIssuerProposalEvidenceSignature,
  verifyMaintainerProposalEvidenceSignature,
  verifyVerifierProposalEvidenceSignature,
} from "../contracts/trust-registry/dist/index.js";
import { bytes32Commitment } from "../packages/trust-registry-client/dist/index.js";
import {
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
    createPayload: computeCreateVerifierAuthorizationPayloadHash,
    bindPayload: computeVerifierEvidenceBoundProposalPayloadHash,
    verifySignature: verifyVerifierProposalEvidenceSignature,
    raw: "proposeVerifierAuthorization",
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
    createPayload: computeCreateAuditorAuthorizationPayloadHash,
    bindPayload: computeAuditorEvidenceBoundProposalPayloadHash,
    verifySignature: verifyAuditorProposalEvidenceSignature,
    raw: "proposeAuditorAuthorization",
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
    createPayload: computeCreateMaintainerMembershipPayloadHash,
    bindPayload: computeMaintainerEvidenceBoundProposalPayloadHash,
    verifySignature: verifyMaintainerProposalEvidenceSignature,
    raw: "proposeMaintainerMembership",
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
    return { harness, fixture, evidence, prepared, verifierSignature, signatures, second, third };
  };

  const submitRaw = (harness, fixture, prepared, verifierSignature, signers) => {
    const [primary, ...coSigners] = signers;
    assert.ok(primary);
    const authorization = [primary.keyId, primary.publicKey, primary.signature];
    const verifier = [prepared.evidenceVerifierAuthorizationId,
      prepared.evidenceVerifierKeyIdCommitment, verifierSignature, coSigners];
    if (role.name === "maintainer") {
      return harness.simulator[role.raw](
        ...authorization, fixture.maintainerIdCommitment,
        fixture.subjectDidCommitment, fixture.keyId,
        deriveJubjubPublicKeyFromSeed(fixture.seed), prepared.policyCommitment,
        bytes32Commitment(fixture.trustLevel), prepared.evidenceHash, ...verifier,
      );
    }
    return harness.simulator[role.raw](
      ...authorization, fixture.authorizationIdCommitment,
      fixture.subjectDidCommitment, fixture.requestResourceIdCommitment,
      fixture.allowedAttributeSetCommitment, fixture.allowedPredicateSetCommitment,
      fixture.disclosureLevelCommitment, prepared.policyCommitment,
      bytes32Commitment(fixture.trustLevel), prepared.evidenceHash, ...verifier,
    );
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

  test(`compact-${role.name}-proposal-altered-evidence-hash`, () => {
    const { harness, fixture, evidence, prepared, verifierSignature, signatures, second, third } =
      proposal(`isolated-${role.name}-proposal-evidence-substitution`);
    const alteredHash = Uint8Array.from(prepared.evidenceHash);
    alteredHash[0] ^= 1;
    const baseHash = role.name === "maintainer"
      ? role.createPayload(
        fixture.maintainerIdCommitment, fixture.subjectDidCommitment,
        fixture.keyId, deriveJubjubPublicKeyFromSeed(fixture.seed),
        prepared.policyCommitment, bytes32Commitment(fixture.trustLevel), alteredHash,
      )
      : role.createPayload(
        fixture.authorizationIdCommitment, fixture.subjectDidCommitment,
        fixture.requestResourceIdCommitment, fixture.allowedAttributeSetCommitment,
        fixture.allowedPredicateSetCommitment, fixture.disclosureLevelCommitment,
        prepared.policyCommitment, bytes32Commitment(fixture.trustLevel), alteredHash,
      );
    const altered = {
      ...prepared,
      evidenceHash: alteredHash,
      actionPayloadHash: role.bindPayload(
        baseHash, prepared.evidenceVerifierAuthorizationId,
        prepared.evidenceVerifierKeyIdCommitment,
        prepared.policyCommitment, prepared.policyVersion,
      ),
    };
    const alteredVerifierSignature = harness[role.sign](altered);
    const verifierKey = harness.simulator.getEvidenceVerifierKey(altered.evidenceVerifierAuthorizationId);
    assert.equal(role.verifySignature(
      verifierKey.publicKey, altered.registryId, altered.evidenceVerifierKeyIdCommitment,
      altered.actionPayloadHash, alteredVerifierSignature,
    ), true);
    const before = harness.simulator.getLedger().governanceActionCount;
    const originalContext = harness.simulator.circuitContext;
    try {
      submitRaw(harness, fixture, altered, alteredVerifierSignature, [
        signAction(harness, second, altered), signAction(harness, third, altered),
      ]);
      assert.equal(harness.simulator.getLedger().governanceActionCount, before + 1n);
    } finally {
      harness.simulator.circuitContext = originalContext;
    }
    assert.equal(harness.simulator.getLedger().governanceActionCount, before);
    assert.throws(() => submitRaw(
      harness, fixture, altered, alteredVerifierSignature, signatures,
    ), /Invalid Jubjub Schnorr signature/u);
    assert.equal(harness.simulator.getLedger().governanceActionCount, before);
    harness[role.execute](fixture, evidence, signatures, verifierSignature);
  });
}

for (const substitution of [
  {
    id: "compact-recognition-external-registry-substitution",
    field: "recognizedRegistryIdCommitment",
    value: "registry:external:substituted:v1",
  },
  {
    id: "compact-recognition-resource-substitution",
    field: "scopeResourceIdCommitment",
    value: "credential-family:substituted:v1",
  },
]) {
  test(substitution.id, () => {
    const harness = new LocalTrustRegistryIntegrationHarness(`isolated-${substitution.id}`);
    const second = createMaintainerScenarioFixture(`isolated-${substitution.id}-second`);
    const third = createMaintainerScenarioFixture(`isolated-${substitution.id}-third`);
    const recognition = createRecognitionScenarioFixture(`isolated-${substitution.id}-recognition`);
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const prepared = harness.prepareRecognitionProposalAction(recognition);
    const verifierSignature = harness.signRecognitionProposalEvidence(prepared);
    const signers = [signAction(harness, second, prepared), signAction(harness, third, prepared)];
    const propose = (overrides = {}) => harness.simulator.proposeRecognition(
      signers[0].keyId, signers[0].publicKey, signers[0].signature,
      recognition.recognitionIdCommitment,
      recognition.recognizedAuthorityDidCommitment,
      overrides.recognizedRegistryIdCommitment ?? recognition.recognizedRegistryIdCommitment,
      recognition.scopeResourceTypeCommitment,
      overrides.scopeResourceIdCommitment ?? recognition.scopeResourceIdCommitment,
      prepared.policyCommitment, bytes32Commitment(recognition.trustLevel),
      prepared.evidenceHash, prepared.evidenceVerifierAuthorizationId,
      prepared.evidenceVerifierKeyIdCommitment, verifierSignature, signers.slice(1),
    );
    const before = harness.simulator.getLedger().governanceActionCount;
    assert.throws(() => propose({ [substitution.field]: bytes32Commitment(substitution.value) }),
      /signature|payload/iu);
    assert.equal(harness.simulator.getLedger().governanceActionCount, before);
    propose();
    assert.equal(harness.simulator.getLedger().governanceActionCount, before + 1n);
  });
}
