import assert from "node:assert/strict";

import { AuthorizationStatus } from "../contracts/trust-registry/dist/managed/trust-registry/contract/index.js";
import {
  createAuditorScenarioFixture,
  createMaintainerScenarioFixture,
  createRecognitionScenarioFixture,
  createVerifierScenarioFixture,
} from "../packages/trust-registry-integration/dist/index.js";

export function runOldPolicyIssuerReplay(matrix, harness, issuer, second, third,
  formerPolicyCommitment, signCompact) {
  const action = harness.prepareIssuerDecisionAction(issuer, "approve");
  const oldSignature = signCompact(second, action, harness, formerPolicyCommitment);
  const oldCoSignature = signCompact(third, action, harness, formerPolicyCommitment);
  const before = harness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => harness.simulator.authorizeIssuerAuthorization(
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
  assert.equal(harness.simulator.getLedger().governanceActionCount, before);
  const signature = signCompact(second, action, harness);
  const coSignature = signCompact(third, action, harness);
  harness.simulator.authorizeIssuerAuthorization(
    signature.keyId,
    signature.publicKey,
    signature.signature,
    issuer.authorizationIdCommitment,
    action.evidenceHash,
    [coSignature],
  );
  assert.equal(harness.simulator.getLedger().governanceActionCount, before + 1n);
  harness.activateIssuer(issuer, [second]);
  return harness.evaluateCurrentIssuerDecision(issuer);
}

export function runOldPolicyRecognitionReplay(matrix, harness, second, third,
  formerPolicyCommitment, signCompact) {
  const recognition = createRecognitionScenarioFixture("governed-demo-recognition-policy-replay");
  const proposal = harness.prepareRecognitionProposalAction(recognition);
  const evidence = harness.signRecognitionProposalEvidence(proposal);
  const proposalCount = harness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => harness.executeRecognitionProposalWithSignatures(
    recognition,
    [signCompact(second, proposal, harness, formerPolicyCommitment),
      signCompact(third, proposal, harness, formerPolicyCommitment)],
    evidence,
    proposal,
  ), {
    id: "compact-recognition-proposal-old-policy-signature-replay",
    invariant: "A recognition proposal with a current payload cannot reuse former-policy maintainer signatures",
    boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
    category: "old-policy-signature-rejected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, proposalCount);
  harness.executeRecognitionProposalWithSignatures(
    recognition,
    [signCompact(second, proposal, harness), signCompact(third, proposal, harness)],
    evidence,
    proposal,
  );
  const approval = harness.prepareRecognitionDecisionAction(recognition, "approve");
  const approvalCount = harness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => harness.executeRecognitionDecisionWithSignatures(
    recognition, "approve",
    [signCompact(second, approval, harness, formerPolicyCommitment),
      signCompact(third, approval, harness, formerPolicyCommitment)],
  ), {
    id: "compact-recognition-approval-old-policy-signature-replay",
    invariant: "A recognition approval with a current payload cannot reuse former-policy maintainer signatures",
    boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
    category: "old-policy-signature-rejected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, approvalCount);
  harness.executeRecognitionDecisionWithSignatures(recognition, "approve", [
    signCompact(second, approval, harness), signCompact(third, approval, harness),
  ]);
}

export function runRevisedPolicyRoleReplays(matrix, harness, client, second, third,
  formerPolicyCommitment, signCompact) {
  const verifier = createVerifierScenarioFixture("governed-demo-policy-verifier");
  harness.proposeVerifier(verifier);
  const verifierApproval = harness.prepareVerifierDecisionAction(verifier, "approve");
  const beforeVerifier = harness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => harness.executeVerifierDecisionWithSignatures(
    verifier, "approve", [
      signCompact(second, verifierApproval, harness, formerPolicyCommitment),
      signCompact(third, verifierApproval, harness, formerPolicyCommitment),
    ],
  ), {
    id: "compact-verifier-old-policy-signature-replay",
    invariant: "Former-policy verifier approval signatures cannot authorize a revised-policy action",
    boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
    category: "old-policy-signature-rejected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, beforeVerifier);
  matrix.expectThrown(() => harness.executeVerifierDecisionWithSignatures(
    verifier, "approve", [signCompact(second, verifierApproval, harness)],
  ), {
    id: "verifier-revised-policy-insufficient-quorum",
    invariant: "A verifier approval under the revised policy requires the new maintainer quorum",
    boundary: "compact",
    messagePattern: /Maintainer signer count must satisfy the action threshold/u,
    category: "revised-policy-insufficient-quorum",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, beforeVerifier);
  harness.approveVerifier(verifier);
  harness.activateVerifier(verifier);
  const verifierBundle = harness.evaluateCurrentVerifierDecision(verifier);
  matrix.expectVerified(() => client.verifyVerifierAuthorizationBundle(verifierBundle, {}), {
    id: "verifier-current-policy-after-threshold-change",
    invariant: "The verifier can be activated under the revised maintainer quorum",
    boundary: "client",
  });
  matrix.expectThrown(() => client.verifyVerifierAuthorizationBundle(
    { ...verifierBundle, policy: { ...verifierBundle.policy, version: "v9" } }, {},
  ), {
    id: "verifier-uncommitted-policy-version",
    invariant: "A verifier cannot substitute an uncommitted policy version after threshold revision",
    boundary: "client", messagePattern: /not committed to the ledger/iu,
    category: "uncommitted-policy-version-rejected",
  });

  const auditor = createAuditorScenarioFixture("governed-demo-policy-auditor");
  harness.proposeAuditor(auditor);
  const auditorApproval = harness.prepareAuditorDecisionAction(auditor, "approve");
  const beforeAuditor = harness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => harness.executeAuditorDecisionWithSignatures(
    auditor, "approve", [
      signCompact(second, auditorApproval, harness, formerPolicyCommitment),
      signCompact(third, auditorApproval, harness, formerPolicyCommitment),
    ],
  ), {
    id: "compact-auditor-old-policy-signature-replay",
    invariant: "Former-policy auditor approval signatures cannot authorize a revised-policy action",
    boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
    category: "old-policy-signature-rejected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, beforeAuditor);
  matrix.expectThrown(() => harness.executeAuditorDecisionWithSignatures(
    auditor, "approve", [signCompact(second, auditorApproval, harness)],
  ), {
    id: "auditor-revised-policy-insufficient-quorum",
    invariant: "An auditor approval under the revised policy requires the new maintainer quorum",
    boundary: "compact",
    messagePattern: /Maintainer signer count must satisfy the action threshold/u,
    category: "revised-policy-insufficient-quorum",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, beforeAuditor);
  harness.approveAuditor(auditor);
  harness.activateAuditor(auditor);
  matrix.expectVerified(() => client.verifyAuditorAuthorizationBundle(
    harness.evaluateCurrentAuditorDecision(auditor), {},
  ), {
    id: "auditor-current-policy-after-threshold-change",
    invariant: "The auditor can be activated under the revised maintainer quorum",
    boundary: "client",
  });

  const maintainer = createMaintainerScenarioFixture("governed-demo-policy-maintainer");
  harness.proposeMaintainer(maintainer);
  const maintainerApproval = harness.prepareMaintainerDecisionAction(maintainer, "approve");
  const beforeMaintainer = harness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => harness.executeMaintainerDecisionWithSignatures(
    maintainer, "approve", [
      signCompact(second, maintainerApproval, harness, formerPolicyCommitment),
      signCompact(third, maintainerApproval, harness, formerPolicyCommitment),
    ],
  ), {
    id: "compact-maintainer-old-policy-signature-replay",
    invariant: "Former-policy maintainer approval signatures cannot authorize a revised-policy action",
    boundary: "compact", messagePattern: /Invalid Jubjub Schnorr signature/u,
    category: "old-policy-signature-rejected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, beforeMaintainer);
  matrix.expectThrown(() => harness.executeMaintainerDecisionWithSignatures(
    maintainer, "approve", [signCompact(second, maintainerApproval, harness)],
  ), {
    id: "maintainer-revised-policy-insufficient-quorum",
    invariant: "A maintainer approval under the revised policy requires the new maintainer quorum",
    boundary: "compact",
    messagePattern: /Maintainer signer count must satisfy the action threshold/u,
    category: "revised-policy-insufficient-quorum",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, beforeMaintainer);
  harness.approveMaintainer(maintainer);
  harness.activateMaintainer(maintainer);
  matrix.expectVerified(() => {
    const membership = harness.simulator.getMaintainerMembership(maintainer.maintainerIdCommitment);
    assert.equal(membership.status, AuthorizationStatus.active);
    return membership;
  }, {
    id: "maintainer-current-policy-after-threshold-change",
    invariant: "The maintainer can be activated under the revised maintainer quorum",
    boundary: "integration",
  });
}
