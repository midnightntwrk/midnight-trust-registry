import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signDeploymentBoundMaintainerActionFromSeed,
} from "../contracts/trust-registry/dist/index.js";
import { createMaintainerFixture } from "../contracts/trust-registry/dist/testing.js";
import { bytes32Commitment } from "../packages/trust-registry-client/dist/index.js";
import { publishSimulatorSnapshot } from "../packages/trust-registry-cli/dist/index.js";
import {
  createMaintainerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  createTrustRegistryApiServer,
  GovernedPolicyActionRejectedError,
} from "../packages/trust-registry-api/dist/index.js";

const asHex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;
const fromHex = (hex) => Buffer.from(hex.slice(2), "hex");
const thresholds = { default: "3", emergency: "1", archival: "2" };
const recoveryThresholds = { default: "2", emergency: "1", archival: "2" };

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

const startCase = async (context, label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const second = createMaintainerScenarioFixture(`${label}-second`);
  const third = createMaintainerScenarioFixture(`${label}-third`);
  const candidate = createMaintainerScenarioFixture(`${label}-candidate`);
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.authorizeMaintainer(candidate);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const snapshot = publishSimulatorSnapshot(harness, { label });
  const port = {
    async prepareThresholds(value) {
      try {
        return harness.prepareThresholdPolicyRevisionAction(
          BigInt(value.default), BigInt(value.emergency), BigInt(value.archival),
        );
      } catch {
        throw new GovernedPolicyActionRejectedError();
      }
    },
    async executeThresholds(value, signers) {
      try {
        return { eventHash: asHex(harness.executeThresholdPolicyRevisionWithSignatures(
          BigInt(value.default), BigInt(value.emergency), BigInt(value.archival), signers,
        )) };
      } catch {
        throw new GovernedPolicyActionRejectedError();
      }
    },
    async prepareEvidenceVerifier() {
      return harness.prepareEvidenceVerifierRegistrationAction();
    },
    async executeEvidenceVerifier(signers) {
      try {
        return { eventHash: asHex(harness.executeEvidenceVerifierRegistrationWithSignatures(signers)) };
      } catch {
        throw new GovernedPolicyActionRejectedError();
      }
    },
    async prepareMaintainerRecovery(id, evidenceHash, value) {
      if (id !== asHex(candidate.maintainerIdCommitment)) throw new GovernedPolicyActionRejectedError();
      try {
        return harness.prepareAtomicMaintainerRecoveryAction(candidate, fromHex(evidenceHash),
          BigInt(value.default), BigInt(value.emergency), BigInt(value.archival));
      } catch {
        throw new GovernedPolicyActionRejectedError();
      }
    },
    async executeMaintainerRecovery(id, evidenceHash, value, signers) {
      if (id !== asHex(candidate.maintainerIdCommitment)) throw new GovernedPolicyActionRejectedError();
      try {
        return { eventHash: asHex(harness.executeAtomicMaintainerRecoveryWithSignatures(
          candidate, fromHex(evidenceHash), BigInt(value.default), BigInt(value.emergency),
          BigInt(value.archival), signers,
        )) };
      } catch {
        throw new GovernedPolicyActionRejectedError();
      }
    },
  };
  const server = createTrustRegistryApiServer({
    source: { mode: "memory", loadSnapshot: async () => snapshot },
    governedPolicyActions: port,
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
  const base = `http://127.0.0.1:${address.port}/v1/governed/policy`;
  const post = async (path, body) => {
    const response = await fetch(`${base}/${path}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  };
  const bootstrap = createMaintainerFixture("bootstrap", 17);
  bootstrap.keyId = bytes32Commitment(`${harness.maintainerDid}#key-1`);
  const revise = async () => {
    const prepared = await post("thresholds/prepare", { thresholds });
    assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
    const signers = [sign(harness, second, prepared.body), sign(harness, third, prepared.body)];
    const accepted = await post("thresholds/submit", { thresholds, prepared: prepared.body, signers });
    assert.equal(accepted.status, 202, JSON.stringify(accepted.body));
    return { prepared: prepared.body, signers };
  };
  const register = async () => {
    const prepared = await post("evidence-verifier/prepare", {});
    assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
    const signers = [second, third, candidate].map((maintainer) => sign(harness, maintainer, prepared.body));
    const accepted = await post("evidence-verifier/submit", { prepared: prepared.body, signers });
    assert.equal(accepted.status, 202, JSON.stringify(accepted.body));
  };
  return { harness, post, second, third, candidate, bootstrap, revise, register };
};

const assertProblem = (response, status, type) => {
  assert.equal(response.status, status, JSON.stringify(response.body));
  assert.equal(response.body.type.slice(response.body.type.lastIndexOf("/") + 1), type);
};

test("policy-revision-no-recovery-headroom", async (context) => {
  const { harness, post, revise } = await startCase(context, "isolated-policy-no-headroom");
  const before = harness.simulator.getLedger().governanceActionCount;
  assertProblem(await post("thresholds/prepare", {
    thresholds: { default: "4", emergency: "1", archival: "2" },
  }), 403, "governed-policy-rejected");
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  await revise();
});

test("policy-revision-one-signer", async (context) => {
  const { harness, post, second, revise } = await startCase(context, "isolated-policy-one-signer");
  const prepared = await post("thresholds/prepare", { thresholds });
  assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
  const before = harness.simulator.getLedger().governanceActionCount;
  assertProblem(await post("thresholds/submit", {
    thresholds, prepared: prepared.body, signers: [sign(harness, second, prepared.body)],
  }), 403, "governed-policy-rejected");
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  await revise();
});

test("policy-revision-stale-replay", async (context) => {
  const { harness, post, revise } = await startCase(context, "isolated-policy-stale-replay");
  const { prepared, signers } = await revise();
  const before = harness.simulator.getLedger().governanceActionCount;
  assertProblem(await post("thresholds/submit", { thresholds, prepared, signers }),
    409, "stale-governed-policy");
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
});

test("new-policy-registration-two-signers", async (context) => {
  const { harness, post, second, third, revise, register } =
    await startCase(context, "isolated-policy-registration-quorum");
  await revise();
  const prepared = await post("evidence-verifier/prepare", {});
  assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
  const before = harness.simulator.getLedger().governanceActionCount;
  assertProblem(await post("evidence-verifier/submit", {
    prepared: prepared.body,
    signers: [second, third].map((maintainer) => sign(harness, maintainer, prepared.body)),
  }), 403, "governed-policy-rejected");
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  await register();
});

test("atomic-recovery-target-self-vote", async (context) => {
  const { harness, post, second, third, candidate, bootstrap, revise, register } =
    await startCase(context, "isolated-policy-recovery-self-vote");
  await revise();
  await register();
  const request = {
    maintainerId: asHex(candidate.maintainerIdCommitment),
    evidenceHash: asHex(bytes32Commitment("incident:isolated-policy-recovery-self-vote")),
    thresholds: recoveryThresholds,
  };
  const prepared = await post("maintainer-recovery/prepare", request);
  assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
  const before = harness.simulator.getLedger().governanceActionCount;
  assertProblem(await post("maintainer-recovery/submit", {
    ...request, prepared: prepared.body,
    signers: [bootstrap, second, candidate].map((maintainer) => sign(harness, maintainer, prepared.body)),
  }), 403, "governed-policy-rejected");
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  const accepted = await post("maintainer-recovery/submit", {
    ...request, prepared: prepared.body,
    signers: [bootstrap, second, third].map((maintainer) => sign(harness, maintainer, prepared.body)),
  });
  assert.equal(accepted.status, 202, JSON.stringify(accepted.body));
  assert.equal(harness.simulator.getLedger().activeMaintainerCount, 3n);
});
