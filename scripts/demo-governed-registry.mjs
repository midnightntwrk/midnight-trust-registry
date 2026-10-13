import assert from "node:assert/strict";
import { Buffer } from "node:buffer";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signPolicyBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { TrustRegistrySimulatorClient } from "../packages/trust-registry-client/dist/simulator-client.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  createAuditorScenarioFixture,
  createIssuerScenarioFixture,
  createMaintainerAuthorizationScopeFixture,
  createMaintainerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  createTrustRegistryApiServer,
  GovernedMembershipActionRejectedError,
} from "../packages/trust-registry-api/dist/index.js";

const asHex = (value) => `0x${Buffer.from(value).toString("hex")}`;
const fromHex = (value) => Buffer.from(value.slice(2), "hex");
const sign = (maintainer, prepared) => {
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
    signature: asHex(encodeJubjubSignature(signature)),
  };
};

const expectHttp = async (response, status) => {
  const payload = await response.json();
  assert.equal(response.status, status, JSON.stringify(payload));
  return payload;
};

const harness = new LocalTrustRegistryIntegrationHarness("governed-registry-demo");
const second = createMaintainerScenarioFixture("governed-demo-second");
const third = createMaintainerScenarioFixture("governed-demo-third");
const candidate = createMaintainerScenarioFixture("governed-demo-candidate");
const issuer = createIssuerScenarioFixture("governed-demo-issuer");
const verifier = createVerifierScenarioFixture("governed-demo-verifier");
const auditor = createAuditorScenarioFixture("governed-demo-auditor");
const recognition = createRecognitionScenarioFixture("governed-demo-recognition");
harness.authorizeMaintainer(second);
harness.authorizeMaintainer(third);
harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);

// Proposals use fixture signatures; the HTTP decisions below use supplied signatures only.
harness.proposeIssuer(issuer, [second]);
harness.proposeVerifier(verifier);
harness.proposeAuditor(auditor);
harness.proposeRecognition(recognition);
const candidateEvidence = harness.createApplicationEvidence({
  applicationId: candidate.maintainerId,
  subjectDid: candidate.subjectDid,
  role: "maintainer",
  scope: createMaintainerAuthorizationScopeFixture(harness.registryId),
});
harness.proposeMaintainerWithApplicationEvidence(candidate, candidateEvidence);

const fixtures = {
  label: "governed-registry-demo",
  issuers: [{ label: "issuer", fixture: issuer }],
  verifiers: [{ label: "verifier", fixture: verifier }],
  auditors: [{ label: "auditor", fixture: auditor }],
  recognitions: [{ label: "recognition", fixture: recognition }],
};
let snapshot = publishSimulatorSnapshot(harness, fixtures);
const targets = new Map([
  ["issuer", {
    id: issuer.authorizationId,
    prepare: (action) => harness.prepareIssuerDecisionAction(issuer, action),
    execute: (action, signers) => harness.executeIssuerDecisionWithSignatures(issuer, action, signers),
  }],
  ["verifier", {
    id: verifier.authorizationId,
    prepare: (action) => harness.prepareVerifierDecisionAction(verifier, action),
    execute: (action, signers) => harness.executeVerifierDecisionWithSignatures(verifier, action, signers),
  }],
  ["auditor", {
    id: auditor.authorizationId,
    prepare: (action) => harness.prepareAuditorDecisionAction(auditor, action),
    execute: (action, signers) => harness.executeAuditorDecisionWithSignatures(auditor, action, signers),
  }],
  ["maintainer", {
    id: candidate.maintainerId,
    prepare: (action) => {
      const prepared = harness.prepareMaintainerDecisionAction(candidate, action);
      return { ...prepared, authorizationId: prepared.maintainerId };
    },
    execute: (action, signers) => harness.executeMaintainerDecisionWithSignatures(candidate, action, signers),
  }],
  ["recognition", {
    id: recognition.recognitionId,
    prepare: (action) => {
      const prepared = harness.prepareRecognitionDecisionAction(recognition, action);
      return { ...prepared, authorizationId: prepared.recognitionId };
    },
    execute: (action, signers) => harness.executeRecognitionDecisionWithSignatures(recognition, action, signers),
  }],
]);
const findTarget = (role, id) => {
  const target = targets.get(role);
  if (target === undefined || target.id !== id) {
    throw new GovernedMembershipActionRejectedError("unknown-authorization");
  }
  return target;
};
const server = createTrustRegistryApiServer({
  source: { mode: "memory", loadSnapshot: async () => snapshot },
  governedMembershipActions: {
    async prepare(role, authorizationId, action) {
      return findTarget(role, authorizationId).prepare(action);
    },
    async execute(role, authorizationId, action, signers) {
      const target = findTarget(role, authorizationId);
      let eventHash;
      try {
        eventHash = target.execute(action, signers);
      } catch {
        throw new GovernedMembershipActionRejectedError("invalid-signers");
      }
      snapshot = publishSimulatorSnapshot(harness, fixtures);
      return { eventHash: asHex(eventHash) };
    },
  },
});

try {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("TCP address unavailable");
  const base = `http://127.0.0.1:${address.port}`;
  const client = new TrustRegistrySimulatorClient(harness.simulator);
  const decisions = [];
  for (const [role, target] of targets) {
    const events = {};
    for (const action of ["approve", "activate"]) {
      const endpoint = `${base}/v1/governed/${role}/${target.id}/actions/${action}`;
      const prepared = await expectHttp(await fetch(endpoint), 200);
      const submit = (preparedAction, signers) => fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ prepared: preparedAction, signers }),
      });
      const signers = [sign(second, prepared), sign(third, prepared)];
      await expectHttp(await submit(prepared, signers.slice(0, 1)), 403);
      if (role === "maintainer") {
        await expectHttp(await submit(prepared, [signers[0], sign(candidate, prepared)]), 403);
      }
      const accepted = await expectHttp(await submit(prepared, signers), 202);
      await expectHttp(await submit(prepared, signers), 409);
      events[action] = accepted.eventHash;
    }
    decisions.push({ role, id: target.id, events });
  }

  for (const [role, target] of targets) {
    if (role === "maintainer") continue;
    const evidencePath = role === "recognition"
      ? `/v1/recognitions/${target.id}/evidence`
      : `/v1/authorizations/${role}/${target.id}/evidence`;
    const bundle = await expectHttp(await fetch(`${base}${evidencePath}`), 200);
    if (role === "recognition") {
      assert.equal(bundle.recognition.status, "active");
      assert.equal(bundle.authorization, undefined);
      client.verifyRecognitionBundle(bundle, {});
    } else {
      assert.equal(bundle.authorization.status, "active");
      if (role === "issuer") client.verifyIssuerAuthorizationBundle(bundle, {});
      if (role === "verifier") client.verifyVerifierAuthorizationBundle(bundle, {});
      if (role === "auditor") client.verifyAuditorAuthorizationBundle(bundle, {});
    }
  }
  await expectHttp(await fetch(
    `${base}/v1/governed/issuer/${recognition.recognitionId}/actions/approve`,
  ), 404);
  await expectHttp(await fetch(`${base}/v1/authorizations/resolve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      role: "issuer", subjectDid: issuer.subjectDid,
      resourceId: createIssuerScenarioFixture("wrong-scope").resourceId,
    }),
  }), 404);
  const candidateCoSignedProposal = harness.proposeIssuer(
    createIssuerScenarioFixture("governed-demo-candidate-proposal"), [candidate],
  );

  process.stdout.write(`${JSON.stringify({
    mode: "Compact simulator fixture; not network finality",
    registryId: harness.registryId,
    governance: "2-of-3 external JubJub signatures for all decisions",
    proposals: "fixture-signed; not public applicant intake",
    decisions,
    activeEvidence: "issuer, verifier, auditor, and recognition independently verified",
    candidateCoSignedProposalEventHash: asHex(candidateCoSignedProposal),
    expectedRejections: ["one-signer:403", "candidate-self-vote:403", "replayed-context:409", "cross-role:404", "wrong-scope:404"],
  }, null, 2)}\n`);
} finally {
  await new Promise((resolve) => server.close(resolve));
}
