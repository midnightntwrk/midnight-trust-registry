import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signDeploymentBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
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
import {
  createTrustRegistryApiServer,
  GovernedAuditorProposalRejectedError,
  GovernedIssuerProposalRejectedError,
  GovernedMaintainerProposalRejectedError,
  GovernedVerifierProposalRejectedError,
} from "../packages/trust-registry-api/dist/index.js";

const asHex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;
const fromHex = (hex) => Buffer.from(hex.slice(2), "hex");

const roles = [
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

const sign = (harness, maintainer, prepared) => {
  const ledger = harness.simulator.getLedger();
  const publicKey = deriveJubjubPublicKeyFromSeed(maintainer.seed);
  const signature = signDeploymentBoundMaintainerActionFromSeed(
    maintainer.seed, ledger.registryId, ledger.deploymentNetworkIdCommitment,
    Buffer.from(harness.simulator.contractAddress, "hex"), ledger.governancePolicyCommitment,
    fromHex(prepared.actionKind), fromHex(prepared.actionPayloadHash), BigInt(prepared.actionSequence),
  );
  return {
    keyId: asHex(maintainer.keyId),
    publicKey: { x: publicKey.x.toString(), y: publicKey.y.toString() },
    signature: asHex(encodeJubjubSignature(signature)),
  };
};

const startCase = async (context, role, label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const second = createMaintainerScenarioFixture(`${label}-second`);
  const third = createMaintainerScenarioFixture(`${label}-third`);
  const target = role.fixture(`${label}-target`);
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const evidence = harness.createApplicationEvidence({
    applicationId: role.id(target), subjectDid: target.subjectDid, role: role.name,
    scope: role.scope(harness, target), governedResource: role.resource(harness, target),
  });
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
        const eventHash = harness[role.execute](target, submitted, signers, verifierSignature);
        return { eventHash: asHex(eventHash) };
      } catch {
        throw new role.rejected("invalid-signers");
      }
    },
  };
  // This suite isolates proposal signatures; VP admission has separate cases.
  const server = createTrustRegistryApiServer({
    source: { mode: "memory", loadSnapshot: async () => snapshot },
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
  const endpoint = `http://127.0.0.1:${address.port}/v1/governed/${role.name}/${role.id(target)}/proposal`;
  const post = async (suffix, payload) => {
    const response = await fetch(`${endpoint}/${suffix}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    return { status: response.status, body: await response.json() };
  };
  const preparedResponse = await post("prepare", { evidence });
  assert.equal(preparedResponse.status, 200, JSON.stringify(preparedResponse.body));
  const prepared = preparedResponse.body;
  const signers = [sign(harness, second, prepared), sign(harness, third, prepared)];
  const verifierSignature = asHex(encodeJubjubSignature(
    harness[role.signEvidence](harness[role.prepare](target, evidence)),
  ));
  const submit = (candidateSigners) => post("submit", {
    evidence, prepared, signers: candidateSigners, evidenceVerifierSignature: verifierSignature,
  });
  return { harness, submit, signers };
};

for (const role of roles) {
  for (const rejection of ["insufficient-quorum", "duplicate-signer"]) {
    test(`${role.name}-proposal-${rejection}`, async (context) => {
      const { harness, submit, signers } = await startCase(context, role,
        `isolated-${role.name}-proposal-api-${rejection}`);
      const before = harness.simulator.getLedger().governanceActionCount;
      const rejected = await submit(rejection === "insufficient-quorum"
        ? signers.slice(0, 1) : [signers[0], signers[0]]);
      assert.equal(rejected.status, 403, JSON.stringify(rejected.body));
      assert.equal(rejected.body.type.slice(rejected.body.type.lastIndexOf("/") + 1),
        rejection === "duplicate-signer" ? "invalid-governed-signature" : "governed-proposal-rejected");
      assert.equal(harness.simulator.getLedger().governanceActionCount, before);
      const accepted = await submit(signers);
      assert.equal(accepted.status, 202, JSON.stringify(accepted.body));
      assert.equal(harness.simulator.getLedger().governanceActionCount, before + 1n);
    });
  }
}
