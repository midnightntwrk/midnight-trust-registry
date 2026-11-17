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

const signAction = async (harness, maintainer, prepared) => {
  const ledger = await harness.simulator.getLedger();
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

const issuerProposal = async (label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const second = createMaintainerScenarioFixture(`${label}-second`);
  const third = createMaintainerScenarioFixture(`${label}-third`);
  const issuer = createIssuerScenarioFixture(`${label}-issuer`);
  await harness.authorizeMaintainer(second);
  await harness.authorizeMaintainer(third);
  await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const evidence = await harness.createApplicationEvidence({
    applicationId: issuer.authorizationId,
    subjectDid: issuer.subjectDid,
    role: "issuer",
    scope: createIssuerAuthorizationScopeFixture(issuer),
    governedResource: { type: "credentialFamily", id: issuer.resourceId },
  });
  const prepared = await harness.prepareIssuerProposalAction(issuer, evidence);
  const verifierSignature = await harness.signIssuerProposalEvidence(prepared);
  const signatures = [await signAction(harness, second, prepared), await signAction(harness, third, prepared)];
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

test("compact-issuer-proposal-insufficient-quorum", async () => {
  const { harness, issuer, evidence, verifierSignature, signatures } =
    await issuerProposal("isolated-issuer-proposal-quorum");
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.executeIssuerProposalWithSignatures(
    issuer, evidence, signatures.slice(0, 1), verifierSignature,
  ), /Maintainer signer count must satisfy the action threshold/u);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  await harness.executeIssuerProposalWithSignatures(issuer, evidence, signatures, verifierSignature);
});

test("client-issuer-proposal-duplicate-signer", async () => {
  const { harness, issuer, evidence, verifierSignature, signatures } =
    await issuerProposal("isolated-issuer-proposal-duplicate");
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.executeIssuerProposalWithSignatures(
    issuer, evidence, [signatures[0], signatures[0]], verifierSignature,
  ), /Maintainer authorization bundle contains a duplicate key ID/u);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  await harness.executeIssuerProposalWithSignatures(issuer, evidence, signatures, verifierSignature);
});

test("compact-issuer-proposal-altered-evidence-hash", async () => {
  const { harness, issuer, evidence, prepared, verifierSignature, signatures } =
    await issuerProposal("isolated-issuer-proposal-evidence-substitution");
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
  const alteredVerifierSignature = await harness.signIssuerProposalEvidence(altered);
  const verifierKey = await harness.simulator.getEvidenceVerifierKey(altered.evidenceVerifierAuthorizationId);
  assert.equal(verifyIssuerProposalEvidenceSignature(
    verifierKey.publicKey, altered.registryId, altered.networkIdCommitment, altered.contractAddress,
    altered.evidenceVerifierKeyIdCommitment,
    altered.actionPayloadHash, alteredVerifierSignature,
  ), true);
  const second = createMaintainerScenarioFixture("isolated-issuer-proposal-evidence-substitution-second");
  const third = createMaintainerScenarioFixture("isolated-issuer-proposal-evidence-substitution-third");
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  const originalContext = harness.simulator.circuitContext;
  try {
    await submitRawIssuerProposal(harness, issuer, altered, alteredVerifierSignature, [
      await signAction(harness, second, altered), await signAction(harness, third, altered),
    ]);
    assert.equal((await harness.simulator.getLedger()).governanceActionCount, before + 1n);
  } finally {
    harness.simulator.circuitContext = originalContext;
  }
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  await assert.rejects(submitRawIssuerProposal(
    harness, issuer, altered, alteredVerifierSignature, signatures,
  ), /Invalid Jubjub Schnorr signature/u);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  await harness.executeIssuerProposalWithSignatures(issuer, evidence, signatures, verifierSignature);
});

test("compact-issuer-proposal-scope-substitution", async () => {
  const { harness, issuer, evidence, prepared, signatures, verifierSignature } =
    await issuerProposal("isolated-issuer-proposal-scope-substitution");
  const changed = { ...issuer, resourceIdCommitment: bytes32Commitment("credential-family:substituted:v1") };
  const baseHash = computeCreateIssuerAuthorizationPayloadHash(
    changed.authorizationIdCommitment, changed.subjectDidCommitment,
    changed.resourceType, changed.resourceIdCommitment,
    prepared.policyCommitment, prepared.statusPolicyBindingCommitment,
    bytes32Commitment(changed.trustLevel), prepared.evidenceHash,
  );
  const altered = {
    ...prepared,
    actionPayloadHash: computeIssuerEvidenceBoundProposalPayloadHash(
      baseHash, prepared.evidenceVerifierAuthorizationId,
      prepared.evidenceVerifierKeyIdCommitment, prepared.policyCommitment, prepared.policyVersion,
    ),
  };
  const changedVerifierSignature = await harness.signIssuerProposalEvidence(altered);
  const second = createMaintainerScenarioFixture("isolated-issuer-proposal-scope-substitution-second");
  const third = createMaintainerScenarioFixture("isolated-issuer-proposal-scope-substitution-third");
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  const originalContext = harness.simulator.circuitContext;
  try {
    await submitRawIssuerProposal(harness, changed, altered, changedVerifierSignature, [
      await signAction(harness, second, altered), await signAction(harness, third, altered),
    ]);
    assert.equal((await harness.simulator.getLedger()).governanceActionCount, before + 1n);
  } finally {
    harness.simulator.circuitContext = originalContext;
  }
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  await assert.rejects(submitRawIssuerProposal(
    harness, changed, altered, changedVerifierSignature, signatures,
  ), /Invalid Jubjub Schnorr signature/u);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  await harness.executeIssuerProposalWithSignatures(issuer, evidence, signatures, verifierSignature);
});

test("issuer-unauthorized-evidence-verifier-compact", async () => {
  const { harness, issuer, evidence, prepared, verifierSignature, signatures } =
    await issuerProposal("isolated-issuer-unauthorized-verifier");
  const outsider = createMaintainerScenarioFixture("isolated-unauthorized-verifier-key");
  const wrongSignature = signIssuerProposalEvidenceFromSeed(
    outsider.seed, prepared.registryId, prepared.networkIdCommitment, prepared.contractAddress,
    prepared.evidenceVerifierKeyIdCommitment,
    prepared.actionPayloadHash,
  );
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.executeIssuerProposalWithSignatures(
    issuer, evidence, signatures, wrongSignature,
  ), /signature|verifier|assert|authorized/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  await harness.executeIssuerProposalWithSignatures(issuer, evidence, signatures, verifierSignature);
});

const pendingIssuerApproval = async (label) => {
  const setup = await issuerProposal(label);
  await setup.harness.executeIssuerProposalWithSignatures(
    setup.issuer, setup.evidence, setup.signatures, setup.verifierSignature,
  );
  const prepared = await setup.harness.prepareIssuerDecisionAction(setup.issuer, "approve");
  const second = createMaintainerScenarioFixture(`${label}-second`);
  const third = createMaintainerScenarioFixture(`${label}-third`);
  const signatures = [
    await signAction(setup.harness, second, prepared),
    await signAction(setup.harness, third, prepared),
  ];
  return { ...setup, prepared, approvalSignatures: signatures };
};

test("compact-issuer-altered-evidence-hash", async () => {
  const { harness, issuer, prepared, approvalSignatures } =
    await pendingIssuerApproval("isolated-issuer-approval-evidence");
  const altered = Uint8Array.from(prepared.evidenceHash);
  altered[0] ^= 1;
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.simulator.authorizeIssuerAuthorization(
    approvalSignatures[0].keyId,
    approvalSignatures[0].publicKey,
    approvalSignatures[0].signature,
    issuer.authorizationIdCommitment,
    altered,
    approvalSignatures.slice(1),
  ), /evidence|match/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  await harness.executeIssuerDecisionWithSignatures(issuer, "approve", approvalSignatures);
});

test("compact-issuer-insufficient-quorum", async () => {
  const { harness, issuer, approvalSignatures } =
    await pendingIssuerApproval("isolated-issuer-approval-quorum");
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.executeIssuerDecisionWithSignatures(
    issuer, "approve", approvalSignatures.slice(0, 1),
  ), /quorum|threshold|assert|signature|maintainer/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  await harness.executeIssuerDecisionWithSignatures(issuer, "approve", approvalSignatures);
});

test("client-issuer-duplicate-signer", async () => {
  const { harness, issuer, approvalSignatures } =
    await pendingIssuerApproval("isolated-issuer-approval-duplicate");
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.executeIssuerDecisionWithSignatures(
    issuer, "approve", [approvalSignatures[0], approvalSignatures[0]],
  ), /Maintainer authorization bundle contains a duplicate key ID/u);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  await harness.executeIssuerDecisionWithSignatures(issuer, "approve", approvalSignatures);
});

test("compact-issuer-unknown-signer", async () => {
  const { harness, issuer, prepared, approvalSignatures } =
    await pendingIssuerApproval("isolated-issuer-approval-outsider");
  const outsider = createMaintainerScenarioFixture("isolated-issuer-outsider");
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await assert.rejects(harness.executeIssuerDecisionWithSignatures(
    issuer, "approve", [approvalSignatures[0], await signAction(harness, outsider, prepared)],
  ), /assert|signature|maintainer|authorized|registered/iu);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  await harness.executeIssuerDecisionWithSignatures(issuer, "approve", approvalSignatures);
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
  const proposal = async (label) => {
    const harness = new LocalTrustRegistryIntegrationHarness(label);
    const second = createMaintainerScenarioFixture(`${label}-second`);
    const third = createMaintainerScenarioFixture(`${label}-third`);
    const fixture = role.fixture(`${label}-${role.name}`);
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(third);
    await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const evidence = await harness.createApplicationEvidence({
      applicationId: role.id(fixture),
      subjectDid: fixture.subjectDid,
      role: role.name,
      scope: role.scope(harness, fixture),
      governedResource: role.resource(harness, fixture),
    });
    const prepared = await harness[role.prepare](fixture, evidence);
    const verifierSignature = await harness[role.sign](prepared);
    const signatures = [await signAction(harness, second, prepared), await signAction(harness, third, prepared)];
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

  test(`compact-${role.name}-proposal-insufficient-quorum`, async () => {
    const { harness, fixture, evidence, verifierSignature, signatures } =
      await proposal(`isolated-${role.name}-proposal-quorum`);
    const before = (await harness.simulator.getLedger()).governanceActionCount;
    await assert.rejects(harness[role.execute](
      fixture, evidence, signatures.slice(0, 1), verifierSignature,
    ), /Maintainer signer count must satisfy the action threshold/u);
    assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
    await harness[role.execute](fixture, evidence, signatures, verifierSignature);
  });

  test(`client-${role.name}-proposal-duplicate-signer`, async () => {
    const { harness, fixture, evidence, verifierSignature, signatures } =
      await proposal(`isolated-${role.name}-proposal-duplicate`);
    const before = (await harness.simulator.getLedger()).governanceActionCount;
    await assert.rejects(harness[role.execute](
      fixture, evidence, [signatures[0], signatures[0]], verifierSignature,
    ), /Maintainer authorization bundle contains a duplicate key ID/u);
    assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
    await harness[role.execute](fixture, evidence, signatures, verifierSignature);
  });

  test(`compact-${role.name}-proposal-altered-evidence-hash`, async () => {
    const { harness, fixture, evidence, prepared, verifierSignature, signatures, second, third } =
      await proposal(`isolated-${role.name}-proposal-evidence-substitution`);
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
    const alteredVerifierSignature = await harness[role.sign](altered);
    const verifierKey = await harness.simulator.getEvidenceVerifierKey(altered.evidenceVerifierAuthorizationId);
    assert.equal(role.verifySignature(
      verifierKey.publicKey, altered.registryId, altered.networkIdCommitment, altered.contractAddress,
      altered.evidenceVerifierKeyIdCommitment,
      altered.actionPayloadHash, alteredVerifierSignature,
    ), true);
    const before = (await harness.simulator.getLedger()).governanceActionCount;
    const originalContext = harness.simulator.circuitContext;
    try {
      await submitRaw(harness, fixture, altered, alteredVerifierSignature, [
        await signAction(harness, second, altered), await signAction(harness, third, altered),
      ]);
      assert.equal((await harness.simulator.getLedger()).governanceActionCount, before + 1n);
    } finally {
      harness.simulator.circuitContext = originalContext;
    }
    assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
    await assert.rejects(submitRaw(
      harness, fixture, altered, alteredVerifierSignature, signatures,
    ), /Invalid Jubjub Schnorr signature/u);
    assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
    await harness[role.execute](fixture, evidence, signatures, verifierSignature);
  });

  if (role.name === "verifier" || role.name === "auditor") {
    test(`compact-${role.name}-proposal-scope-substitution`, async () => {
      const label = `isolated-${role.name}-proposal-scope-substitution`;
      const { harness, fixture, evidence, prepared, verifierSignature, signatures, second, third } = await proposal(label);
      const changed = role.name === "verifier"
        ? { ...fixture, allowedAttributeSetCommitment: bytes32Commitment("verifier:substituted-attributes") }
        : { ...fixture, requestResourceIdCommitment: bytes32Commitment("auditor:substituted-request") };
      const baseHash = role.createPayload(
        changed.authorizationIdCommitment, changed.subjectDidCommitment,
        changed.requestResourceIdCommitment, changed.allowedAttributeSetCommitment,
        changed.allowedPredicateSetCommitment, changed.disclosureLevelCommitment,
        prepared.policyCommitment, bytes32Commitment(changed.trustLevel), prepared.evidenceHash,
      );
      const altered = {
        ...prepared,
        actionPayloadHash: role.bindPayload(
          baseHash, prepared.evidenceVerifierAuthorizationId,
          prepared.evidenceVerifierKeyIdCommitment, prepared.policyCommitment, prepared.policyVersion,
        ),
      };
      const changedVerifierSignature = await harness[role.sign](altered);
      const before = (await harness.simulator.getLedger()).governanceActionCount;
      const originalContext = harness.simulator.circuitContext;
      try {
        await submitRaw(harness, changed, altered, changedVerifierSignature, [
          await signAction(harness, second, altered), await signAction(harness, third, altered),
        ]);
        assert.equal((await harness.simulator.getLedger()).governanceActionCount, before + 1n);
      } finally {
        harness.simulator.circuitContext = originalContext;
      }
      assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
      await assert.rejects(submitRaw(
        harness, changed, altered, changedVerifierSignature, signatures,
      ), /Invalid Jubjub Schnorr signature/u);
      assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
      await harness[role.execute](fixture, evidence, signatures, verifierSignature);
    });
  }
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
  test(substitution.id, async () => {
    const harness = new LocalTrustRegistryIntegrationHarness(`isolated-${substitution.id}`);
    const second = createMaintainerScenarioFixture(`isolated-${substitution.id}-second`);
    const third = createMaintainerScenarioFixture(`isolated-${substitution.id}-third`);
    const recognition = createRecognitionScenarioFixture(`isolated-${substitution.id}-recognition`);
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(third);
    await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const prepared = await harness.prepareRecognitionProposalAction(recognition);
    const verifierSignature = await harness.signRecognitionProposalEvidence(prepared);
    const signers = [await signAction(harness, second, prepared), await signAction(harness, third, prepared)];
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
    const before = (await harness.simulator.getLedger()).governanceActionCount;
    await assert.rejects(propose({ [substitution.field]: bytes32Commitment(substitution.value) }),
      /signature|payload/iu);
    assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
    await propose();
    assert.equal((await harness.simulator.getLedger()).governanceActionCount, before + 1n);
  });
}
