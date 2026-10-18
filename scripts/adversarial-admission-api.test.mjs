import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signDeploymentBoundMaintainerActionFromSeed,
  signIssuerProposalEvidenceFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { createMaintainerFixture } from "../contracts/trust-registry/dist/testing.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  ApplicationChallengeBindingSchema,
  computeApplicationEvidenceCommitment,
  computeAuthorizationScopeCommitment,
  createScopedIdentifier,
  sha256Hex,
} from "../packages/trust-registry-domain/dist/index.js";
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
  VP_FIXTURE_TIME_MS,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  createTrustRegistryApiServer,
  GovernedAuditorProposalRejectedError,
  GovernedIssuerProposalRejectedError,
  GovernedMaintainerProposalRejectedError,
  GovernedVerifierProposalRejectedError,
} from "../packages/trust-registry-api/dist/index.js";

const asHex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;
const fromHex = (hex) => Buffer.from(hex.slice(2), "hex");
const roleSpecs = [
  { name: "issuer", fixture: createIssuerScenarioFixture, id: (value) => value.authorizationId,
    scope: (_, value) => createIssuerAuthorizationScopeFixture(value),
    resource: (_, value) => ({ type: "credentialFamily", id: value.resourceId }),
    prepare: "prepareIssuerProposalAction", signEvidence: "signIssuerProposalEvidence",
    execute: "executeIssuerProposalWithSignatures", port: "governedIssuerProposals",
    rejected: GovernedIssuerProposalRejectedError },
  { name: "verifier", fixture: createVerifierScenarioFixture, id: (value) => value.authorizationId,
    scope: (_, value) => createVerifierAuthorizationScopeFixture(value),
    resource: (_, value) => ({ type: "requestProfile", id: value.scopeResourceId }),
    prepare: "prepareVerifierProposalAction", signEvidence: "signVerifierProposalEvidence",
    execute: "executeVerifierProposalWithSignatures", port: "governedVerifierProposals",
    rejected: GovernedVerifierProposalRejectedError },
  { name: "auditor", fixture: createAuditorScenarioFixture, id: (value) => value.authorizationId,
    scope: (_, value) => createAuditorAuthorizationScopeFixture(value),
    resource: (_, value) => ({ type: "requestProfile", id: value.scopeResourceId }),
    prepare: "prepareAuditorProposalAction", signEvidence: "signAuditorProposalEvidence",
    execute: "executeAuditorProposalWithSignatures", port: "governedAuditorProposals",
    rejected: GovernedAuditorProposalRejectedError },
  { name: "maintainer", fixture: createMaintainerScenarioFixture, id: (value) => value.maintainerId,
    scope: (harness) => createMaintainerAuthorizationScopeFixture(harness.registryId),
    resource: (harness) => ({ type: "registry", id: harness.registryId }),
    prepare: "prepareMaintainerProposalAction", signEvidence: "signMaintainerProposalEvidence",
    execute: "executeMaintainerProposalWithSignatures", port: "governedMaintainerProposals",
    rejected: GovernedMaintainerProposalRejectedError },
];

const acceptedReceipt = (applicationId, evidence) => ({
  receiptId: sha256Hex(`receipt:${applicationId}:${evidence.commitment}`),
  evidenceCommitment: evidence.commitment,
  acceptedAt: new Date(VP_FIXTURE_TIME_MS).toISOString(),
});

const startCase = async (context, role, label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const target = role.fixture(`${label}-target`);
  const scope = role.scope(harness, target);
  const governedResource = role.resource(harness, target);
  const evidence = harness.createApplicationEvidence({
    applicationId: role.id(target), subjectDid: target.subjectDid,
    role: role.name, scope, governedResource,
  });
  const applicationId = evidence.envelope.applicationId;
  const binding = ApplicationChallengeBindingSchema.parse({
    registryId: harness.registryId, applicationId, subjectDid: target.subjectDid,
    evidenceVerifierDid: harness.evidenceVerifier.did, role: role.name,
    policyId: harness.policyId, policyVersion: harness.policyRecord.version,
    scope, scopeCommitment: computeAuthorizationScopeCommitment(scope), governedResource,
  });
  const pending = new Map([[applicationId, {
    authorizationId: role.id(target), binding, status: "pending",
    createdAt: new Date(VP_FIXTURE_TIME_MS).toISOString(),
  }]]);
  const accepted = new Map([[applicationId, { evidence, receipt: acceptedReceipt(applicationId, evidence) }]]);
  const snapshot = publishSimulatorSnapshot(harness, { label });
  const port = {
    async prepare(id, submitted) {
      if (id !== role.id(target)) throw new role.rejected("unknown-authorization");
      try {
        return harness[role.prepare](target, submitted);
      } catch {
        throw new role.rejected("invalid-evidence");
      }
    },
    async execute(id, submitted, signers, verifierSignature) {
      if (id !== role.id(target)) throw new role.rejected("unknown-authorization");
      try {
        return { eventHash: asHex(harness[role.execute](
          target, submitted, signers, verifierSignature,
        )) };
      } catch {
        throw new role.rejected("invalid-signers");
      }
    },
  };
  const server = createTrustRegistryApiServer({
    source: { mode: "memory", loadSnapshot: async () => snapshot },
    proposalAdmission: {
      resolvePendingApplication: async (id) => pending.get(id) ?? null,
      resolveAcceptedEvidence: async (id) => accepted.get(id) ?? null,
    },
    [role.port]: port,
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  context.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const base = `http://127.0.0.1:${address.port}`;
  const endpoint = `${base}/v1/governed/${role.name}/${role.id(target)}/proposal`;
  const post = async (url, body) => {
    const response = await fetch(url, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  };
  const prepare = (submitted = evidence, targetEndpoint = endpoint) =>
    post(`${targetEndpoint}/prepare`, { evidence: submitted });
  return { harness, target, role, applicationId, evidence, accepted, pending, endpoint,
    prepare, post };
};

const assertProblem = (response, status, type) => {
  assert.equal(response.status, status, JSON.stringify(response.body));
  assert.equal(response.body.type.slice(response.body.type.lastIndexOf("/") + 1), type);
};
const assertAcceptedPrepare = async (fixture) => {
  const prepared = await fixture.prepare();
  assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
  return prepared.body;
};
const shortLivedEvidence = (harness, evidence) => {
  const envelope = {
    ...evidence.envelope,
    expiresAt: new Date(Date.parse(evidence.envelope.verifiedAt) + 1).toISOString(),
  };
  const commitment = computeApplicationEvidenceCommitment(envelope);
  const shortened = { envelope, commitment,
    signature: harness.signApplicationEvidenceCommitment(commitment) };
  assert.equal(harness.verifyApplicationEvidenceSignature(
    commitment, shortened.signature, harness.evidenceVerifier,
  ), true);
  harness.advanceEvidenceTimeBy(1000);
  return shortened;
};

for (const role of roleSpecs) {
  test(`${role.name}-expired-evidence-api-preflight`, async (context) => {
    const fixture = await startCase(context, role, `isolated-${role.name}-expired-preflight`);
    const shortened = shortLivedEvidence(fixture.harness, fixture.evidence);
    const before = fixture.harness.simulator.getLedger().governanceActionCount;
    assert.throws(() => fixture.harness[role.prepare](fixture.target, shortened), /expired/iu);
    assert.equal(fixture.harness.simulator.getLedger().governanceActionCount, before);
    await assertAcceptedPrepare(fixture);
  });

  test(`${role.name}-expired-accepted-evidence-api`, async (context) => {
    const fixture = await startCase(context, role, `isolated-${role.name}-expired-admission`);
    const shortened = shortLivedEvidence(fixture.harness, fixture.evidence);
    fixture.accepted.set(fixture.applicationId, {
      evidence: shortened, receipt: acceptedReceipt(fixture.applicationId, shortened),
    });
    const before = fixture.harness.simulator.getLedger().governanceActionCount;
    assertProblem(await fixture.prepare(shortened), 403, "governed-proposal-rejected");
    assert.equal(fixture.harness.simulator.getLedger().governanceActionCount, before);
    fixture.accepted.set(fixture.applicationId, {
      evidence: fixture.evidence, receipt: acceptedReceipt(fixture.applicationId, fixture.evidence),
    });
    await assertAcceptedPrepare(fixture);
  });

  test(`${role.name}-cross-role-evidence`, async (context) => {
    const fixture = await startCase(context, role, `isolated-${role.name}-cross-role`);
    const otherRole = roleSpecs.find((candidate) => candidate.name !== role.name);
    assert.ok(otherRole);
    const other = otherRole.fixture(`isolated-${role.name}-cross-role-other`);
    const otherEvidence = fixture.harness.createApplicationEvidence({
      applicationId: otherRole.id(other), subjectDid: other.subjectDid,
      role: otherRole.name, scope: otherRole.scope(fixture.harness, other),
      governedResource: otherRole.resource(fixture.harness, other),
    });
    assertProblem(await fixture.prepare(otherEvidence), 403, "unadmitted-proposal");
    await assertAcceptedPrepare(fixture);
  });

  test(`${role.name}-wrong-proposal-target`, async (context) => {
    const fixture = await startCase(context, role, `isolated-${role.name}-wrong-target`);
    const wrongEndpoint = fixture.endpoint.replace(`/${role.id(fixture.target)}/proposal`,
      `/${createScopedIdentifier("wrong", role.id(fixture.target))}/proposal`);
    assertProblem(await fixture.prepare(fixture.evidence, wrongEndpoint), 403, "unadmitted-proposal");
    await assertAcceptedPrepare(fixture);
  });

  test(`${role.name}-missing-vp-receipt`, async (context) => {
    const fixture = await startCase(context, role, `isolated-${role.name}-missing-receipt`);
    const original = fixture.accepted.get(fixture.applicationId);
    assert.ok(original);
    fixture.accepted.delete(fixture.applicationId);
    assertProblem(await fixture.prepare(), 403, "unadmitted-proposal");
    fixture.accepted.set(fixture.applicationId, original);
    await assertAcceptedPrepare(fixture);
  });
}

test("issuer-altered-evidence-commitment-api", async (context) => {
  const fixture = await startCase(context, roleSpecs[0], "isolated-issuer-altered-admission");
  const altered = { ...fixture.evidence,
    commitment: `${fixture.evidence.commitment.slice(0, -1)}${fixture.evidence.commitment.endsWith("0") ? "1" : "0"}` };
  assertProblem(await fixture.prepare(altered), 403, "unadmitted-proposal");
  await assertAcceptedPrepare(fixture);
});

test("issuer-altered-evidence-commitment-integration-preflight", async (context) => {
  const fixture = await startCase(context, roleSpecs[0], "isolated-issuer-altered-preflight");
  const altered = { ...fixture.evidence,
    commitment: `${fixture.evidence.commitment.slice(0, -1)}${fixture.evidence.commitment.endsWith("0") ? "1" : "0"}` };
  const before = fixture.harness.simulator.getLedger().governanceActionCount;
  assert.throws(() => fixture.harness.prepareIssuerProposalAction(fixture.target, altered),
    /commitment|evidence/iu);
  assert.equal(fixture.harness.simulator.getLedger().governanceActionCount, before);
  await assertAcceptedPrepare(fixture);
});

test("issuer-unauthorized-evidence-verifier-api", async (context) => {
  const fixture = await startCase(context, roleSpecs[0], "isolated-issuer-unauthorized-verifier-api");
  const prepared = await assertAcceptedPrepare(fixture);
  const bootstrap = createMaintainerFixture("bootstrap", 17);
  bootstrap.keyId = Buffer.from(fixture.harness.simulator.getLedger().lastAuthorizedMaintainerKeyId);
  const ledger = fixture.harness.simulator.getLedger();
  const publicKey = deriveJubjubPublicKeyFromSeed(bootstrap.seed);
  const signature = signDeploymentBoundMaintainerActionFromSeed(
    bootstrap.seed, ledger.registryId, ledger.deploymentNetworkIdCommitment,
    Buffer.from(fixture.harness.simulator.contractAddress, "hex"), ledger.governancePolicyCommitment,
    fromHex(prepared.actionKind), fromHex(prepared.actionPayloadHash), BigInt(prepared.actionSequence),
  );
  const signers = [{ keyId: asHex(bootstrap.keyId),
    publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
    signature: asHex(encodeJubjubSignature(signature)) }];
  const compactPrepared = fixture.harness.prepareIssuerProposalAction(fixture.target, fixture.evidence);
  const outsider = createMaintainerScenarioFixture("isolated-issuer-unauthorized-verifier-key");
  const wrong = signIssuerProposalEvidenceFromSeed(outsider.seed, compactPrepared.registryId,
    compactPrepared.evidenceVerifierKeyIdCommitment, compactPrepared.actionPayloadHash);
  const submit = (verifierSignature) => fixture.post(`${fixture.endpoint}/submit`, {
    evidence: fixture.evidence, prepared, signers,
    evidenceVerifierSignature: asHex(encodeJubjubSignature(verifierSignature)),
  });
  const before = fixture.harness.simulator.getLedger().governanceActionCount;
  assertProblem(await submit(wrong), 403, "governed-proposal-rejected");
  assert.equal(fixture.harness.simulator.getLedger().governanceActionCount, before);
  const good = fixture.harness.signIssuerProposalEvidence(compactPrepared);
  const accepted = await submit(good);
  assert.equal(accepted.status, 202, JSON.stringify(accepted.body));
});
