import assert from "node:assert/strict";

import { createRecognitionScenarioFixture } from "../packages/trust-registry-integration/dist/index.js";

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
