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
  createAuditorScenarioFixture,
  createAuditorAuthorizationScopeFixture,
  createIssuerScenarioFixture,
  createIssuerAuthorizationScopeFixture,
  createMaintainerScenarioFixture,
  createMaintainerAuthorizationScopeFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
  createVerifierAuthorizationScopeFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  createTrustRegistryApiServer,
  GovernedMembershipActionRejectedError,
} from "../packages/trust-registry-api/dist/index.js";

const asHex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;
const fromHex = (hex) => Buffer.from(hex.slice(2), "hex");

const roles = [
  { name: "issuer", fixture: createIssuerScenarioFixture, id: (value) => value.authorizationId,
    scope: (_, value) => createIssuerAuthorizationScopeFixture(value),
    resource: (_, value) => ({ type: "credentialFamily", id: value.resourceId }),
    proposal: ["prepareIssuerProposalAction", "signIssuerProposalEvidence", "executeIssuerProposalWithSignatures"],
    prepare: "prepareIssuerDecisionAction",
    execute: "executeIssuerDecisionWithSignatures" },
  { name: "verifier", fixture: createVerifierScenarioFixture, id: (value) => value.authorizationId,
    scope: (_, value) => createVerifierAuthorizationScopeFixture(value),
    resource: (_, value) => ({ type: "requestProfile", id: value.scopeResourceId }),
    proposal: ["prepareVerifierProposalAction", "signVerifierProposalEvidence", "executeVerifierProposalWithSignatures"],
    prepare: "prepareVerifierDecisionAction",
    execute: "executeVerifierDecisionWithSignatures" },
  { name: "auditor", fixture: createAuditorScenarioFixture, id: (value) => value.authorizationId,
    scope: (_, value) => createAuditorAuthorizationScopeFixture(value),
    resource: (_, value) => ({ type: "requestProfile", id: value.scopeResourceId }),
    proposal: ["prepareAuditorProposalAction", "signAuditorProposalEvidence", "executeAuditorProposalWithSignatures"],
    prepare: "prepareAuditorDecisionAction",
    execute: "executeAuditorDecisionWithSignatures" },
  { name: "maintainer", fixture: createMaintainerScenarioFixture, id: (value) => value.maintainerId,
    scope: (harness) => createMaintainerAuthorizationScopeFixture(harness.registryId),
    resource: (harness) => ({ type: "registry", id: harness.registryId }),
    proposal: ["prepareMaintainerProposalAction", "signMaintainerProposalEvidence", "executeMaintainerProposalWithSignatures"],
    prepare: "prepareMaintainerDecisionAction",
    execute: "executeMaintainerDecisionWithSignatures" },
  { name: "recognition", fixture: createRecognitionScenarioFixture, id: (value) => value.recognitionId,
    proposal: ["prepareRecognitionProposalAction", "signRecognitionProposalEvidence", "executeRecognitionProposalWithSignatures"],
    prepare: "prepareRecognitionDecisionAction",
    execute: "executeRecognitionDecisionWithSignatures" },
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

const signCompact = (harness, maintainer, prepared) => {
  const ledger = harness.simulator.getLedger();
  return {
    keyId: maintainer.keyId,
    publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
    signature: signDeploymentBoundMaintainerActionFromSeed(
      maintainer.seed, ledger.registryId, ledger.deploymentNetworkIdCommitment,
      Buffer.from(harness.simulator.contractAddress, "hex"), ledger.governancePolicyCommitment,
      prepared.actionKind, prepared.actionPayloadHash, prepared.actionSequence,
    ),
  };
};

const startCase = async (context, role, action, label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const second = createMaintainerScenarioFixture(`${label}-second`);
  const third = createMaintainerScenarioFixture(`${label}-third`);
  const target = role.fixture(`${label}-target`);
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const [prepareProposal, signProposal, executeProposal] = role.proposal;
  const evidence = role.name === "recognition" ? undefined : harness.createApplicationEvidence({
    applicationId: role.id(target), subjectDid: target.subjectDid,
    role: role.name, scope: role.scope(harness, target),
    governedResource: role.resource(harness, target),
  });
  const proposal = role.name === "recognition"
    ? harness[prepareProposal](target) : harness[prepareProposal](target, evidence);
  const verifierSignature = harness[signProposal](proposal);
  const proposalSigners = [signCompact(harness, second, proposal), signCompact(harness, third, proposal)];
  if (role.name === "recognition") {
    harness[executeProposal](target, proposalSigners, verifierSignature, proposal);
  } else {
    harness[executeProposal](target, evidence, proposalSigners, verifierSignature);
  }
  if (action === "activate") {
    const approval = harness[role.prepare](target, "approve");
    harness[role.execute](target, "approve", [
      signCompact(harness, second, approval), signCompact(harness, third, approval),
    ]);
  }
  const snapshot = publishSimulatorSnapshot(harness, { label });
  const server = createTrustRegistryApiServer({
    source: { mode: "memory", loadSnapshot: async () => snapshot },
    governedMembershipActions: {
      async prepare(requestRole, id, requestedAction) {
        if (requestRole !== role.name || id !== role.id(target)) {
          throw new GovernedMembershipActionRejectedError("unknown-authorization");
        }
        return harness[role.prepare](target, requestedAction);
      },
      async execute(requestRole, id, requestedAction, signers) {
        if (requestRole !== role.name || id !== role.id(target)) {
          throw new GovernedMembershipActionRejectedError("unknown-authorization");
        }
        try {
          const eventHash = harness[role.execute](target, requestedAction, signers);
          return { eventHash: asHex(eventHash) };
        } catch {
          throw new GovernedMembershipActionRejectedError("invalid-signers");
        }
      },
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
  const endpoint = `http://127.0.0.1:${address.port}/v1/governed/${role.name}/${role.id(target)}/actions/${action}`;
  const preparedResponse = await fetch(endpoint);
  const prepared = await preparedResponse.json();
  assert.equal(preparedResponse.status, 200, JSON.stringify(prepared));
  const signers = [sign(harness, second, prepared), sign(harness, third, prepared)];
  const submit = async (candidateSigners) => {
    const response = await fetch(endpoint, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ prepared, signers: candidateSigners }),
    });
    return { status: response.status, body: await response.json() };
  };
  return { harness, target, prepared, signers, submit };
};

for (const role of roles) {
  for (const action of ["approve", "activate"]) {
    for (const rejection of ["insufficient-quorum", "duplicate-signer",
      ...(role.name === "maintainer" ? ["candidate-self-vote"] : [])]) {
      test(`${role.name}-${action}-${rejection}`, async (context) => {
        const fixture = await startCase(context, role, action,
          `isolated-${role.name}-${action}-${rejection}`);
        const { signers, submit, harness, target, prepared } = fixture;
        const before = harness.simulator.getLedger().governanceActionCount;
        const rejectedSigners = rejection === "insufficient-quorum" ? signers.slice(0, 1)
          : rejection === "duplicate-signer" ? [signers[0], signers[0]]
            : [signers[0], sign(harness, target, prepared)];
        const rejected = await submit(rejectedSigners);
        assert.equal(rejected.status, 403, JSON.stringify(rejected.body));
        assert.equal(rejected.body.type.slice(rejected.body.type.lastIndexOf("/") + 1),
          rejection === "duplicate-signer" ? "invalid-governed-signature" : "governed-action-rejected");
        assert.equal(harness.simulator.getLedger().governanceActionCount, before);
        const accepted = await submit(signers);
        assert.equal(accepted.status, 202, JSON.stringify(accepted.body));
        assert.equal(harness.simulator.getLedger().governanceActionCount, before + 1n);
      });
    }
  }
}
