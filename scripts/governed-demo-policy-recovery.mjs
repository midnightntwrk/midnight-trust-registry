import assert from "node:assert/strict";

import { createMaintainerFixture } from "../contracts/trust-registry/dist/testing.js";
import { bytes32Commitment } from "../packages/trust-registry-client/dist/index.js";
import { createIssuerScenarioFixture } from "../packages/trust-registry-integration/dist/index.js";

export async function runGovernedPolicyRecovery(matrix, {
  base, harness, second, third, candidate, sign, expectHttp, publishCurrentSnapshot, asHex,
}) {
  const policyVersionBeforeRevision = (await harness.simulator.getLedger()).governancePolicyVersion;
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
  const revisionSigners = [await sign(second, revisionContext), await sign(third, revisionContext)];
  await matrix.expectHttp(await postPolicy("thresholds/submit", {
    thresholds, prepared: revisionContext, signers: revisionSigners.slice(0, 1),
  }), {
    id: "policy-revision-one-signer",
    invariant: "Old-policy quorum is required for threshold revision",
    boundary: "api", status: 403, problemType: "governed-policy-rejected",
  });
  const revisionReceipt = await expectHttp(await postPolicy("thresholds/submit", {
    thresholds, prepared: revisionContext,
    signers: revisionSigners,
  }), 202);
  await matrix.expectHttp(await postPolicy("thresholds/submit", {
    thresholds, prepared: revisionContext,
    signers: revisionSigners,
  }), {
    id: "policy-revision-stale-replay",
    invariant: "A consumed old-policy context cannot revise governance twice",
    boundary: "api", status: 409, problemType: "stale-governed-policy",
  });
  assert.equal((await harness.simulator.getLedger()).governancePolicyVersion, policyVersionBeforeRevision + 1n);
  const threeSignerIssuer = createIssuerScenarioFixture("governed-demo-three-signer-issuer");
  await assert.rejects(() => harness.proposeIssuer(threeSignerIssuer, [second, third]),
    /policy|evidence|verifier|active|registered|signature|assert/iu);
  const registrationContext = await expectHttp(await postPolicy("evidence-verifier/prepare", {}), 200);
  const registrationSigners = [
    await sign(second, registrationContext), await sign(third, registrationContext),
    await sign(candidate, registrationContext),
  ];
  await matrix.expectHttp(await postPolicy("evidence-verifier/submit", {
    prepared: registrationContext,
    signers: registrationSigners.slice(0, 2),
  }), {
    id: "new-policy-registration-two-signers",
    invariant: "New-policy quorum is required to register the evidence verifier",
    boundary: "api", status: 403, problemType: "governed-policy-rejected",
  });
  const registrationReceipt = await expectHttp(await postPolicy("evidence-verifier/submit", {
    prepared: registrationContext,
    signers: registrationSigners,
  }), 202);
  await assert.rejects(() => harness.proposeIssuer(threeSignerIssuer, [second]), /action threshold/u);
  await harness.proposeIssuer(threeSignerIssuer, [second, third]);
  const removalSequence = (await harness.simulator.getLedger()).governanceActionCount;
  await matrix.expectRejected(() => harness.suspendMaintainer(candidate), {
    id: "compact-recovery-policy-headroom-required",
    invariant: "A maintainer removal cannot leave an all-member quorum",
    boundary: "compact",
    messagePattern: /non-conflicted removal quorum/iu,
    category: "maintainer-recovery-protected",
  });
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, removalSequence);
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
  const recoverySigners = [
    await sign(bootstrap, recoveryContext), await sign(second, recoveryContext),
    await sign(third, recoveryContext), await sign(candidate, recoveryContext),
  ];
  await matrix.expectHttp(await postPolicy("maintainer-recovery/submit", {
    ...recoveryRequest,
    prepared: recoveryContext,
    signers: [recoverySigners[0], recoverySigners[1], recoverySigners[3]],
  }), {
    id: "atomic-recovery-target-self-vote",
    invariant: "The target cannot count toward the old-policy recovery quorum",
    boundary: "api", status: 403, problemType: "governed-policy-rejected",
  });
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, removalSequence);
  const recoveryReceipt = await expectHttp(await postPolicy("maintainer-recovery/submit", {
    ...recoveryRequest,
    prepared: recoveryContext,
    signers: recoverySigners.slice(0, 3),
  }), 202);
  assert.equal((await harness.simulator.getLedger()).activeMaintainerCount, 3n);
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, removalSequence + 1n);
  await publishCurrentSnapshot();
  const recoveryRegistrationContext = await expectHttp(await postPolicy("evidence-verifier/prepare", {}), 200);
  const recoveryRegistrationReceipt = await expectHttp(await postPolicy("evidence-verifier/submit", {
    prepared: recoveryRegistrationContext,
    signers: [await sign(second, recoveryRegistrationContext), await sign(third, recoveryRegistrationContext)],
  }), 202);
  const suspendedMaintainerEventHash = recoveryReceipt.eventHash;
  const postSuspensionIssuer = createIssuerScenarioFixture("governed-demo-post-suspension-issuer");
  await assert.rejects(() => harness.proposeIssuer(postSuspensionIssuer, [candidate, second]),
    /Maintainer must be active/u);
  const remainingQuorumEventHash = await harness.proposeIssuer(postSuspensionIssuer, [second, third]);
  return {
    policyVersionBeforeRevision, revisionReceipt, registrationReceipt, recoveryReceipt,
    recoveryRegistrationReceipt, suspendedMaintainerEventHash, remainingQuorumEventHash,
  };
}
