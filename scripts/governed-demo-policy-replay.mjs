import assert from "node:assert/strict";

import { AuthorizationStatus } from "../contracts/trust-registry/dist/managed/trust-registry/contract/index.js";
import {
  createAuditorScenarioFixture,
  createMaintainerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
} from "../packages/trust-registry-integration/dist/index.js";

export async function runOldPolicyIssuerReplay(matrix, harness, issuer, second, third,
  formerPolicyCommitment, signCompact) {
  const action = await harness.prepareIssuerDecisionAction(issuer, "approve");
  const oldSignature = await signCompact(second, action, harness, formerPolicyCommitment);
  const oldCoSignature = await signCompact(third, action, harness, formerPolicyCommitment);
  const before = (await harness.simulator.getLedger()).governanceActionCount;
  await matrix.expectRejected(() => harness.simulator.authorizeIssuerAuthorization(
    oldSignature.keyId,
    oldSignature.publicKey,
    oldSignature.signature,
    issuer.authorizationIdCommitment,
    action.evidenceHash,
    [oldCoSignature],
  ), {
    id: "compact-old-policy-signature-replay",
    invariant: "Former-policy signatures cannot authorize the same payload and sequence under the revised policy",
    boundary: "compact",
    messagePattern: /Invalid Jubjub Schnorr signature/u,
    category: "old-policy-signature-rejected",
  });
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before);
  const signature = await signCompact(second, action, harness);
  const coSignature = await signCompact(third, action, harness);
  await harness.simulator.authorizeIssuerAuthorization(
    signature.keyId,
    signature.publicKey,
    signature.signature,
    issuer.authorizationIdCommitment,
    action.evidenceHash,
    [coSignature],
  );
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, before + 1n);
  await harness.activateIssuer(issuer, [second]);
  return await harness.evaluateCurrentIssuerDecision(issuer);
}

export async function runOldPolicyRecognitionReplay(matrix, harness, second, third,
  formerPolicyCommitment, signCompact) {
  const recognition = createRecognitionScenarioFixture("governed-demo-recognition-policy-replay");
  const proposal = await harness.prepareRecognitionProposalAction(recognition);
  const evidence = await harness.signRecognitionProposalEvidence(proposal);
  const proposalCount = (await harness.simulator.getLedger()).governanceActionCount;
  await matrix.expectRejected(async () => harness.executeRecognitionProposalWithSignatures(
    recognition,
    [await signCompact(second, proposal, harness, formerPolicyCommitment),
      await signCompact(third, proposal, harness, formerPolicyCommitment)],
    evidence,
    proposal,
  ), {
    id: "compact-recognition-proposal-old-policy-signature-replay",
    invariant: "A recognition proposal with a current payload cannot reuse former-policy maintainer signatures",
    boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
    category: "old-policy-signature-rejected",
  });
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, proposalCount);
  await harness.executeRecognitionProposalWithSignatures(
    recognition,
    [await signCompact(second, proposal, harness), await signCompact(third, proposal, harness)],
    evidence,
    proposal,
  );
  const approval = await harness.prepareRecognitionDecisionAction(recognition, "approve");
  const approvalCount = (await harness.simulator.getLedger()).governanceActionCount;
  await matrix.expectRejected(async () => harness.executeRecognitionDecisionWithSignatures(
    recognition, "approve",
    [await signCompact(second, approval, harness, formerPolicyCommitment),
      await signCompact(third, approval, harness, formerPolicyCommitment)],
  ), {
    id: "compact-recognition-approval-old-policy-signature-replay",
    invariant: "A recognition approval with a current payload cannot reuse former-policy maintainer signatures",
    boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
    category: "old-policy-signature-rejected",
  });
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, approvalCount);
  await harness.executeRecognitionDecisionWithSignatures(recognition, "approve", [
    await signCompact(second, approval, harness), await signCompact(third, approval, harness),
  ]);
}

export async function runRevisedPolicyRoleReplays(matrix, harness, client, second, third,
  formerPolicyCommitment, signCompact) {
  const verifier = createVerifierScenarioFixture("governed-demo-policy-verifier");
  await harness.proposeVerifier(verifier);
  const verifierApproval = await harness.prepareVerifierDecisionAction(verifier, "approve");
  const beforeVerifier = (await harness.simulator.getLedger()).governanceActionCount;
  await matrix.expectRejected(async () => harness.executeVerifierDecisionWithSignatures(
    verifier, "approve", [
      await signCompact(second, verifierApproval, harness, formerPolicyCommitment),
      await signCompact(third, verifierApproval, harness, formerPolicyCommitment),
    ],
  ), {
    id: "compact-verifier-old-policy-signature-replay",
    invariant: "Former-policy verifier approval signatures cannot authorize a revised-policy action",
    boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
    category: "old-policy-signature-rejected",
  });
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, beforeVerifier);
  await matrix.expectRejected(async () => harness.executeVerifierDecisionWithSignatures(
    verifier, "approve", [await signCompact(second, verifierApproval, harness)],
  ), {
    id: "verifier-revised-policy-insufficient-quorum",
    invariant: "A verifier approval under the revised policy requires the new maintainer quorum",
    boundary: "compact",
    messagePattern: /Maintainer signer count must satisfy the action threshold/u,
    category: "revised-policy-insufficient-quorum",
  });
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, beforeVerifier);
  await harness.approveVerifier(verifier);
  await harness.activateVerifier(verifier);
  const verifierBundle = await harness.evaluateCurrentVerifierDecision(verifier);
  await matrix.expectVerifiedAsync(() => client.verifyVerifierAuthorizationBundle(verifierBundle, {}), {
    id: "verifier-current-policy-after-threshold-change",
    invariant: "The verifier can be activated under the revised maintainer quorum",
    boundary: "client",
  });
  await matrix.expectRejected(() => client.verifyVerifierAuthorizationBundle(
    { ...verifierBundle, policy: { ...verifierBundle.policy, version: "v9" } }, {},
  ), {
    id: "verifier-uncommitted-policy-version",
    invariant: "A verifier cannot substitute an uncommitted policy version after threshold revision",
    boundary: "client", messagePattern: /not committed to the ledger/iu,
    category: "uncommitted-policy-version-rejected",
  });

  const auditor = createAuditorScenarioFixture("governed-demo-policy-auditor");
  await harness.proposeAuditor(auditor);
  const auditorApproval = await harness.prepareAuditorDecisionAction(auditor, "approve");
  const beforeAuditor = (await harness.simulator.getLedger()).governanceActionCount;
  await matrix.expectRejected(async () => harness.executeAuditorDecisionWithSignatures(
    auditor, "approve", [
      await signCompact(second, auditorApproval, harness, formerPolicyCommitment),
      await signCompact(third, auditorApproval, harness, formerPolicyCommitment),
    ],
  ), {
    id: "compact-auditor-old-policy-signature-replay",
    invariant: "Former-policy auditor approval signatures cannot authorize a revised-policy action",
    boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
    category: "old-policy-signature-rejected",
  });
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, beforeAuditor);
  await matrix.expectRejected(async () => harness.executeAuditorDecisionWithSignatures(
    auditor, "approve", [await signCompact(second, auditorApproval, harness)],
  ), {
    id: "auditor-revised-policy-insufficient-quorum",
    invariant: "An auditor approval under the revised policy requires the new maintainer quorum",
    boundary: "compact",
    messagePattern: /Maintainer signer count must satisfy the action threshold/u,
    category: "revised-policy-insufficient-quorum",
  });
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, beforeAuditor);
  await harness.approveAuditor(auditor);
  await harness.activateAuditor(auditor);
  await matrix.expectVerifiedAsync(async () => client.verifyAuditorAuthorizationBundle(
    await harness.evaluateCurrentAuditorDecision(auditor), {},
  ), {
    id: "auditor-current-policy-after-threshold-change",
    invariant: "The auditor can be activated under the revised maintainer quorum",
    boundary: "client",
  });

  const maintainer = createMaintainerScenarioFixture("governed-demo-policy-maintainer");
  await harness.proposeMaintainer(maintainer);
  const maintainerApproval = await harness.prepareMaintainerDecisionAction(maintainer, "approve");
  const beforeMaintainer = (await harness.simulator.getLedger()).governanceActionCount;
  await matrix.expectRejected(async () => harness.executeMaintainerDecisionWithSignatures(
    maintainer, "approve", [
      await signCompact(second, maintainerApproval, harness, formerPolicyCommitment),
      await signCompact(third, maintainerApproval, harness, formerPolicyCommitment),
    ],
  ), {
    id: "compact-maintainer-old-policy-signature-replay",
    invariant: "Former-policy maintainer approval signatures cannot authorize a revised-policy action",
    boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
    category: "old-policy-signature-rejected",
  });
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, beforeMaintainer);
  await matrix.expectRejected(async () => harness.executeMaintainerDecisionWithSignatures(
    maintainer, "approve", [await signCompact(second, maintainerApproval, harness)],
  ), {
    id: "maintainer-revised-policy-insufficient-quorum",
    invariant: "A maintainer approval under the revised policy requires the new maintainer quorum",
    boundary: "compact",
    messagePattern: /Maintainer signer count must satisfy the action threshold/u,
    category: "revised-policy-insufficient-quorum",
  });
  assert.equal((await harness.simulator.getLedger()).governanceActionCount, beforeMaintainer);
  await harness.approveMaintainer(maintainer);
  await harness.activateMaintainer(maintainer);
  await matrix.expectVerifiedAsync(async () => {
    const membership = await harness.simulator.getMaintainerMembership(maintainer.maintainerIdCommitment);
    assert.equal(membership.status, AuthorizationStatus.active);
    return membership;
  }, {
    id: "maintainer-current-policy-after-threshold-change",
    invariant: "The maintainer can be activated under the revised maintainer quorum",
    boundary: "integration",
  });
}

export async function runHistoricalPolicyClientChecks(matrix, client, {
  historicalPolicyBundle, originalVerifierBundle, originalAuditorBundle,
  originalRecognitionBundle, currentPolicyBundle,
}, changeLastHexNibble) {
  await matrix.expectVerifiedAsync(() => client.verifyIssuerAuthorizationBundle(historicalPolicyBundle, {}), {
    id: "issuer-history-survives-threshold-change",
    invariant: "Old issuer authorization remains verifiable under its original policy snapshot",
    boundary: "client",
  });
  await matrix.expectVerifiedAsync(() => client.verifyVerifierAuthorizationBundle(originalVerifierBundle, {}), {
    id: "verifier-history-survives-threshold-change",
    invariant: "Old verifier authorization remains verifiable under its original policy snapshot",
    boundary: "client",
  });
  await matrix.expectVerifiedAsync(() => client.verifyAuditorAuthorizationBundle(originalAuditorBundle, {}), {
    id: "auditor-history-survives-threshold-change",
    invariant: "Old auditor authorization remains verifiable under its original policy snapshot",
    boundary: "client",
  });
  await matrix.expectVerifiedAsync(() => client.verifyRecognitionBundle(originalRecognitionBundle, {}), {
    id: "recognition-history-survives-threshold-change",
    invariant: "Old recognition remains verifiable under its original policy snapshot",
    boundary: "client",
  });
  await matrix.expectRejected(() => client.verifyAuditorAuthorizationBundle(
    { ...originalAuditorBundle, policy: { ...originalAuditorBundle.policy, version: "v9" } }, {},
  ), {
    id: "auditor-uncommitted-policy-version",
    invariant: "An auditor cannot substitute an uncommitted policy version after threshold revision",
    boundary: "client", messagePattern: /not committed to the ledger/iu,
    category: "uncommitted-policy-version-rejected",
  });
  await matrix.expectRejected(() => client.verifyRecognitionBundle(
    { ...originalRecognitionBundle, policy: { ...originalRecognitionBundle.policy, version: "v9" } }, {},
  ), {
    id: "recognition-uncommitted-policy-version",
    invariant: "A recognition cannot substitute an uncommitted policy version after threshold revision",
    boundary: "client", messagePattern: /not committed to the ledger/iu,
    category: "uncommitted-policy-version-rejected",
  });
  await matrix.expectVerifiedAsync(() => client.verifyIssuerAuthorizationBundle(currentPolicyBundle, {}), {
    id: "issuer-current-policy-after-threshold-change",
    invariant: "New issuer authorization verifies under the revised policy snapshot",
    boundary: "client",
  });
  await matrix.expectRejected(() => client.verifyIssuerAuthorizationBundle(
    historicalPolicyBundle, { evaluationTime: currentPolicyBundle.policy.effectiveFrom },
  ), {
    id: "issuer-old-policy-current-time-replay",
    invariant: "Historical issuer evidence cannot establish trust after its policy is superseded",
    boundary: "client",
    messagePattern: /policy snapshot is superseded/iu,
    category: "superseded-policy-rejected",
  });
  await matrix.expectRejected(() => client.verifyIssuerAuthorizationBundle(
    { ...historicalPolicyBundle, policy: { ...historicalPolicyBundle.policy, version: "v9" } }, {},
  ), {
    id: "issuer-uncommitted-policy-version",
    invariant: "Changing the evidence policy version cannot create an uncommitted authorization",
    boundary: "client",
    messagePattern: /not committed to the ledger/iu,
    category: "uncommitted-policy-version-rejected",
  });
  await matrix.expectRejected(() => client.verifyIssuerAuthorizationBundle({
    ...historicalPolicyBundle,
    inclusionProof: {
      ...historicalPolicyBundle.inclusionProof,
      path: [changeLastHexNibble(historicalPolicyBundle.inclusionProof.path[0])],
    },
  }, {}), {
    id: "issuer-historical-proof-tampered-after-policy-revision",
    invariant: "A threshold revision cannot make a tampered old-policy Merkle proof valid",
    boundary: "client",
    messagePattern: /event sibling/iu,
    category: "historical-merkle-path-rejected",
  });
  const historicalEpochSignature = historicalPolicyBundle.epoch.maintainerSignatures[0];
  assert.ok(historicalEpochSignature);
  const alteredEpochSignature = `0x${historicalEpochSignature.signature[2] === "0" ? "1" : "0"}${historicalEpochSignature.signature.slice(3)}`;
  await matrix.expectRejected(() => client.verifyIssuerAuthorizationBundle({
    ...historicalPolicyBundle,
    epoch: {
      ...historicalPolicyBundle.epoch,
      maintainerSignatures: [{ ...historicalEpochSignature, signature: alteredEpochSignature }],
    },
  }, {}), {
    id: "issuer-historical-epoch-signature-tampered",
    invariant: "A policy revision cannot make a forged historical epoch signature valid",
    boundary: "client",
    messagePattern: /invalid/iu,
    category: "historical-epoch-signature-rejected",
  });
}
