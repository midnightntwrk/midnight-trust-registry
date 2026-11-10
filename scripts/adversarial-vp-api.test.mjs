import assert from "node:assert/strict";
import { test } from "node:test";

import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  ApplicationChallengeBindingSchema,
  computeAuthorizationScopeCommitment,
  createScopedIdentifier,
  sha256Hex,
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
  LocalTrustRegistryIntegrationHarness,
  VP_FIXTURE_NONCE,
  VP_FIXTURE_TIME_MS,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  createTrustRegistryApiServer,
  InMemoryApplicationChallengeStore,
} from "../packages/trust-registry-api/dist/index.js";

const roles = [
  { name: "issuer", fixture: createIssuerScenarioFixture, id: (value) => value.authorizationId,
    scope: (_, value) => createIssuerAuthorizationScopeFixture(value),
    resource: (_, value) => ({ type: "credentialFamily", id: value.resourceId }) },
  { name: "verifier", fixture: createVerifierScenarioFixture, id: (value) => value.authorizationId,
    scope: (_, value) => createVerifierAuthorizationScopeFixture(value),
    resource: (_, value) => ({ type: "requestProfile", id: value.scopeResourceId }) },
  { name: "auditor", fixture: createAuditorScenarioFixture, id: (value) => value.authorizationId,
    scope: (_, value) => createAuditorAuthorizationScopeFixture(value),
    resource: (_, value) => ({ type: "requestProfile", id: value.scopeResourceId }) },
  { name: "maintainer", fixture: createMaintainerScenarioFixture, id: (value) => value.maintainerId,
    scope: (harness) => createMaintainerAuthorizationScopeFixture(harness.registryId),
    resource: (harness) => ({ type: "registry", id: harness.registryId }) },
];

const startCase = async (context, role, label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const target = role.fixture(`${label}-target`);
  const scope = role.scope(harness, target);
  const applicationId = createScopedIdentifier("application", role.name, role.id(target));
  const binding = ApplicationChallengeBindingSchema.parse({
    registryId: harness.registryId, applicationId, subjectDid: target.subjectDid,
    evidenceVerifierDid: harness.evidenceVerifier.did, role: role.name,
    policyId: harness.policyId, policyVersion: harness.policyRecord.version,
    scope, scopeCommitment: computeAuthorizationScopeCommitment(scope),
    governedResource: role.resource(harness, target),
  });
  const signingFixture = await createApplicationVpScenarioFixture(VP_FIXTURE_NONCE, {
    evidenceVerifierDid: harness.evidenceVerifier.did,
    evidenceVerifierMethodId: harness.evidenceVerifier.keyIds[0].split("#")[1],
  });
  const signingPorts = await createApplicationVpIntakePorts({
    resolver: signingFixture.input.resolver,
    family: signingFixture.input.family,
    signer: signingFixture.signer,
  });
  let verificationPorts;
  let accepted;
  let receipt;
  const snapshot = publishSimulatorSnapshot(harness, { label });
  const token = `isolated-${label}-applicant-token`;
  const server = createTrustRegistryApiServer({
    source: { mode: "memory", loadSnapshot: async () => snapshot },
    clock: () => new Date(VP_FIXTURE_TIME_MS).toISOString(),
    applicationVp: {
      challengeStore: new InMemoryApplicationChallengeStore(),
      authorizeRequest: async (id, request) => {
        if (id !== applicationId || request.headers.authorization !== `Bearer ${token}`) {
          throw new Error("Applicant authorization failed");
        }
        return binding.subjectDid;
      },
      resolvePendingApplication: async (id) => id === applicationId && accepted === undefined
        ? { binding, authorizedVerifiers: [harness.evidenceVerifier] } : null,
      verifyPresentation: async (presentation, verificationContext) => {
        assert.ok(verificationPorts);
        return verificationPorts.verifyPresentation(presentation, verificationContext);
      },
      signEvidence: signingPorts.signEvidence,
      verifyEvidenceSignature: signingPorts.verifyEvidenceSignature,
      persistRedactedEvidence: async (id, evidence) => {
        assert.equal(id, applicationId);
        assert.equal(accepted, undefined);
        accepted = evidence;
        receipt = {
          receiptId: sha256Hex(`receipt:${id}:${evidence.commitment}`),
          evidenceCommitment: evidence.commitment,
          acceptedAt: new Date(VP_FIXTURE_TIME_MS).toISOString(),
        };
        return receipt;
      },
      resolveAcceptedEvidence: async (id) => id === applicationId && accepted !== undefined
        ? { evidence: accepted, receipt } : null,
    },
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
  const endpoint = `http://127.0.0.1:${address.port}/v1/application-evidence/${applicationId}`;
  const post = async (suffix, body, authorized = true) => {
    const response = await fetch(`${endpoint}/${suffix}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(authorized ? { authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  };
  const challenge = async () => {
    const result = await post("challenges", {});
    assert.equal(result.status, 201, JSON.stringify(result.body));
    return result.body;
  };
  const submit = async (challengeValue, overrides = {}, transformPresentation = (value) => value) => {
    const proof = await createApplicationVpScenarioFixture(challengeValue.nonce, {
      subjectDid: target.subjectDid,
      evidenceVerifierDid: harness.evidenceVerifier.did,
      evidenceVerifierMethodId: harness.evidenceVerifier.keyIds[0].split("#")[1],
      scope, ...overrides,
    });
    verificationPorts = await createApplicationVpIntakePorts({
      resolver: proof.input.resolver, family: proof.input.family, signer: proof.signer,
    });
    const submission = {
      nonce: challengeValue.nonce, challengeHash: challengeValue.challengeHash,
      presentation: transformPresentation(proof.input.submission),
    };
    return { response: await post("submissions", submission), submission };
  };
  return { scope, post, challenge, submit,
    accepted: () => accepted };
};

const assertProblem = (response, status, type) => {
  assert.equal(response.status, status, JSON.stringify(response.body));
  assert.equal(response.body.type.slice(response.body.type.lastIndexOf("/") + 1), type);
};

for (const role of roles) {
  test(`${role.name}-unauthorized-vp-challenge`, async (context) => {
    const fixture = await startCase(context, role, `isolated-${role.name}-unauthorized-vp`);
    assertProblem(await fixture.post("challenges", {}, false), 403, "application-vp-forbidden");
    assert.equal(fixture.accepted(), undefined);
    const issued = await fixture.challenge();
    assert.equal((await fixture.submit(issued)).response.status, 202);
  });

  test(`${role.name}-vp-challenge-replay`, async (context) => {
    const fixture = await startCase(context, role, `isolated-${role.name}-vp-replay`);
    const issued = await fixture.challenge();
    const { response, submission } = await fixture.submit(issued);
    assert.equal(response.status, 202, JSON.stringify(response.body));
    assert.ok(fixture.accepted());
    assertProblem(await fixture.post("submissions", submission), 404, "application-vp-not-found");
  });
}

for (const invalid of [
  { id: "issuer-wrong-signed-vp-scope", value: (scope) => ({
    scope: { ...scope, credentialFamilyId: "credential-family:wrong" },
  }) },
  { id: "issuer-unbound-vp-credential", value: () => ({
    presentationCredentialBodyRoot: sha256Hex("unbound-credential-body"),
  }) },
  { id: "issuer-revoked-vp-credential", value: () => ({ statusDecision: { active: false } }) },
]) {
  test(invalid.id, async (context) => {
    const fixture = await startCase(context, roles[0], `isolated-${invalid.id}`);
    const issued = await fixture.challenge();
    const rejected = await fixture.submit(issued, invalid.value(fixture.scope));
    assertProblem(rejected.response, 403, "application-vp-rejected");
    assert.equal(fixture.accepted(), undefined);
    const accepted = await fixture.submit(issued);
    assert.equal(accepted.response.status, 202, JSON.stringify(accepted.response.body));
    assert.ok(fixture.accepted());
  });
}

test("issuer-vp-holder-method-substitution", async (context) => {
  const fixture = await startCase(context, roles[0], "isolated-issuer-holder-method-substitution");
  const issued = await fixture.challenge();
  const rejected = await fixture.submit(issued, {}, (presentation) => {
    const method = presentation.presentationProof.signerVerificationMethodRef;
    const methodId = method.methodId;
    return { ...presentation, presentationProof: {
      ...presentation.presentationProof,
      signerVerificationMethodRef: {
        ...method,
        methodId: `${methodId.slice(0, -1)}${methodId.endsWith("0") ? "1" : "0"}`,
      },
    } };
  });
  assertProblem(rejected.response, 403, "application-vp-rejected");
  assert.equal(fixture.accepted(), undefined);
  const accepted = await fixture.submit(issued);
  assert.equal(accepted.response.status, 202, JSON.stringify(accepted.response.body));
  assert.ok(fixture.accepted());
});
