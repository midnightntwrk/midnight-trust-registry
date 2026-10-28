import assert from "node:assert/strict";

import { createMaintainerFixture } from "../contracts/trust-registry/dist/testing.js";
import { bytes32Commitment } from "../packages/trust-registry-client/dist/index.js";
import { createIssuerScenarioFixture } from "../packages/trust-registry-integration/dist/index.js";

export async function runGovernedPolicyRecovery(matrix, {
  base, harness, second, third, candidate, sign, expectHttp, publishCurrentSnapshot, asHex,
}) {
  const policyVersionBeforeRevision = harness.simulator.getLedger().governancePolicyVersion;
  const policyEndpoint = `${base}/v1/governed/policy`;
  const postPolicy = (path, body) => fetch(`${policyEndpoint}/${path}`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  const thresholds = { default: "3", emergency: "1", archival: "2" };
  await matrix.expectHttp(await postPolicy("thresholds/prepare", {
    thresholds: { default: "4", emergency: "1", archival: "2" },
  }), {
    id: "policy-revision-no-recovery-headroom",
    invariant: "Preparation rejects a threshold with no non-conflicted recovery quorum",
    boundary: "api", status: 403, problemType: "governed-policy-rejected",
  });
  const revisionContext = await expectHttp(await postPolicy("thresholds/prepare", { thresholds }), 200);
  await matrix.expectHttp(await postPolicy("thresholds/submit", {
    thresholds, prepared: revisionContext, signers: [sign(second, revisionContext)],
  }), {
    id: "policy-revision-one-signer",
    invariant: "Old-policy quorum is required for threshold revision",
    boundary: "api", status: 403, problemType: "governed-policy-rejected",
  });
  const revisionReceipt = await expectHttp(await postPolicy("thresholds/submit", {
    thresholds, prepared: revisionContext,
    signers: [sign(second, revisionContext), sign(third, revisionContext)],
  }), 202);
  await matrix.expectHttp(await postPolicy("thresholds/submit", {
    thresholds, prepared: revisionContext,
    signers: [sign(second, revisionContext), sign(third, revisionContext)],
  }), {
    id: "policy-revision-stale-replay",
    invariant: "A consumed old-policy context cannot revise governance twice",
    boundary: "api", status: 409, problemType: "stale-governed-policy",
  });
  assert.equal(harness.simulator.getLedger().governancePolicyVersion, policyVersionBeforeRevision + 1n);
  const threeSignerIssuer = createIssuerScenarioFixture("governed-demo-three-signer-issuer");
  assert.throws(() => harness.proposeIssuer(threeSignerIssuer, [second, third]),
    /policy|evidence|verifier|active|registered|signature|assert/iu);
  const registrationContext = await expectHttp(await postPolicy("evidence-verifier/prepare", {}), 200);
  await matrix.expectHttp(await postPolicy("evidence-verifier/submit", {
    prepared: registrationContext,
    signers: [sign(second, registrationContext), sign(third, registrationContext)],
  }), {
    id: "new-policy-registration-two-signers",
    invariant: "New-policy quorum is required to register the evidence verifier",
    boundary: "api", status: 403, problemType: "governed-policy-rejected",
  });
  const registrationReceipt = await expectHttp(await postPolicy("evidence-verifier/submit", {
    prepared: registrationContext,
    signers: [sign(second, registrationContext), sign(third, registrationContext), sign(candidate, registrationContext)],
  }), 202);
  assert.throws(() => harness.proposeIssuer(threeSignerIssuer, [second]), /action threshold/u);
  harness.proposeIssuer(threeSignerIssuer, [second, third]);
  const removalSequence = harness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => harness.suspendMaintainer(candidate), {
    id: "compact-recovery-policy-headroom-required",
    invariant: "A maintainer removal cannot leave an all-member quorum",
    boundary: "compact",
    messagePattern: /non-conflicted removal quorum/iu,
    category: "maintainer-recovery-protected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, removalSequence);
  const recoveryThresholds = { default: "2", emergency: "1", archival: "2" };
  const recoveryRequest = {
    maintainerId: asHex(candidate.maintainerIdCommitment),
    evidenceHash: asHex(bytes32Commitment("incident:governed-demo:maintainer-recovery")),
    thresholds: recoveryThresholds,
  };
  const recoveryContext = await expectHttp(await postPolicy("maintainer-recovery/prepare", {
    ...recoveryRequest,
  }), 200);
  const bootstrap = createMaintainerFixture("bootstrap", 17);
  bootstrap.keyId = bytes32Commitment(`${harness.maintainerDid}#key-1`);
  await matrix.expectHttp(await postPolicy("maintainer-recovery/submit", {
    ...recoveryRequest,
    prepared: recoveryContext,
    signers: [sign(bootstrap, recoveryContext), sign(second, recoveryContext), sign(candidate, recoveryContext)],
  }), {
    id: "atomic-recovery-target-self-vote",
    invariant: "The target cannot count toward the old-policy recovery quorum",
    boundary: "api", status: 403, problemType: "governed-policy-rejected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, removalSequence);
  const recoveryReceipt = await expectHttp(await postPolicy("maintainer-recovery/submit", {
    ...recoveryRequest,
    prepared: recoveryContext,
    signers: [sign(bootstrap, recoveryContext), sign(second, recoveryContext), sign(third, recoveryContext)],
  }), 202);
  assert.equal(harness.simulator.getLedger().activeMaintainerCount, 3n);
  assert.equal(harness.simulator.getLedger().governanceActionCount, removalSequence + 1n);
  publishCurrentSnapshot();
  const recoveryRegistrationContext = await expectHttp(await postPolicy("evidence-verifier/prepare", {}), 200);
  const recoveryRegistrationReceipt = await expectHttp(await postPolicy("evidence-verifier/submit", {
    prepared: recoveryRegistrationContext,
    signers: [sign(second, recoveryRegistrationContext), sign(third, recoveryRegistrationContext)],
  }), 202);
  const suspendedMaintainerEventHash = recoveryReceipt.eventHash;
  const postSuspensionIssuer = createIssuerScenarioFixture("governed-demo-post-suspension-issuer");
  assert.throws(() => harness.proposeIssuer(postSuspensionIssuer, [candidate, second]),
    /Maintainer must be active/u);
  const remainingQuorumEventHash = harness.proposeIssuer(postSuspensionIssuer, [second, third]);
  return {
    policyVersionBeforeRevision, revisionReceipt, registrationReceipt, recoveryReceipt,
    recoveryRegistrationReceipt, suspendedMaintainerEventHash, remainingQuorumEventHash,
  };
}
