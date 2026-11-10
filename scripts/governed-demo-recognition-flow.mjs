import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { signJubjubDigestFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";

import { encodeJubjubSignature } from "../contracts/trust-registry/dist/index.js";
import { bytes32Commitment } from "../packages/trust-registry-client/dist/index.js";
import {
  createRecognitionAccreditationVpScenarioFixture,
  RECOGNITION_VP_FIXTURE_ANCHOR,
  recognitionAuthorityAssertionDigest,
  recognitionAccreditationSubmissionCommitment,
  VP_FIXTURE_TIME_MS,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  InMemoryApplicationChallengeStore,
  RecognitionAuthorityChallengeService,
} from "../packages/trust-registry-api/dist/index.js";
import { runRecognitionIntakeSafetyScenarios } from "./governed-demo-recognition-intake-safety.mjs";

const asHex = (value) => `0x${Buffer.from(value).toString("hex")}`;
const fromHex = (value) => Buffer.from(value.slice(2), "hex");

export async function runGovernedRecognitionFlow(matrix, {
  harness, recognition, recognitionAuthorityDid, recognitionAuthoritySeed,
  vcAuthorityAnchor, vcAuthorityKeyIdCommitment, second, third, signCompact,
}) {
  const recognitionMethodId = `${recognitionAuthorityDid}#assertion-1`;
  const recognitionChallengeBinding = {
    targetRegistryId: harness.registryId,
    recognitionId: recognition.recognitionId,
    authorityDid: recognitionAuthorityDid,
    recognizedRegistryId: recognition.recognizedRegistryId,
    scopeResourceType: recognition.scopeResourceType,
    scopeResourceId: recognition.scopeResourceId,
  };
  const recognitionAnchor = {
    ...RECOGNITION_VP_FIXTURE_ANCHOR,
    targetRegistryId: harness.registryId,
    policyId: harness.policyId,
    policyVersion: `v${(harness.simulator.getLedger().governancePolicyVersion + 1n).toString()}`,
    recognizedRegistryId: recognition.recognizedRegistryId,
    scopeResourceType: recognition.scopeResourceType,
    scopeResourceId: recognition.scopeResourceId,
  };
  harness.governRecognitionAccreditorAnchor(recognitionAnchor, [second]);
  harness.registerVcAuthorityKey({
    domain: vcAuthorityAnchor.domain,
    keyIdCommitment: vcAuthorityKeyIdCommitment,
    publicKey: vcAuthorityAnchor.publicKey,
  });
  harness.advanceEvidenceTimeBy(60_000);
  const recognitionEvaluationMs = Math.max(
    VP_FIXTURE_TIME_MS, Date.parse(harness.policyRecord.effectiveFrom) + 60_000,
  );
  const governedRecognitionAnchor = harness.resolveCurrentRecognitionAccreditorAnchor({
    recognizedRegistryId: recognition.recognizedRegistryId,
    scopeResourceType: recognition.scopeResourceType,
    scopeResourceId: recognition.scopeResourceId,
    evaluatedAtMs: recognitionEvaluationMs,
  });
  const recognitionChallengeService = new RecognitionAuthorityChallengeService(
    new InMemoryApplicationChallengeStore(), () => recognitionEvaluationMs,
  );
  const recognitionChallenge = await recognitionChallengeService.issue(recognitionChallengeBinding);
  const recognitionAccreditationFixture = await createRecognitionAccreditationVpScenarioFixture({
    nonce: recognitionChallenge.nonce,
    evaluatedAtMs: recognitionEvaluationMs,
    authorityDid: recognitionAuthorityDid,
    authorityAssertionSeed: recognitionAuthoritySeed,
    anchor: governedRecognitionAnchor.anchor,
  });
  const recognitionStatement = {
    version: "tr-recognition-authority-assertion-v1",
    ...recognitionChallengeBinding,
    accreditationSubmissionCommitment: recognitionAccreditationSubmissionCommitment(
      recognitionAccreditationFixture.input.submission,
    ),
    challengeHash: recognitionChallenge.challengeHash,
    issuedAt: new Date(recognitionEvaluationMs).toISOString(),
    expiresAt: new Date(recognitionEvaluationMs + 50 * 60_000).toISOString(),
  };
  const recognitionAssertion = {
    statement: recognitionStatement,
    proof: {
      verificationMethodId: recognitionMethodId,
      algorithm: "jubjub-schnorr",
      signature: asHex(encodeJubjubSignature(signJubjubDigestFromSeed(
        recognitionAuthoritySeed,
        recognitionAuthorityAssertionDigest(recognitionStatement, recognitionMethodId),
      ))),
    },
  };
  const verifyRecognitionChallenge = (signed, overrides = {}) =>
    recognitionChallengeService.verifyAndConsumeAccreditedAssertion({
      binding: recognitionChallengeBinding,
      nonce: recognitionChallenge.nonce,
      signed,
      accreditation: recognitionAccreditationFixture.input.submission,
      readCurrentGovernance: async () => ({
        governancePolicy: harness.policyRecord,
        activePolicyCommitment: asHex(harness.simulator.getLedger().governancePolicyCommitment),
      }),
      resolver: recognitionAccreditationFixture.input.resolver,
      statusSource: recognitionAccreditationFixture.input.statusSource,
      ...overrides,
    });
  const recognitionSequenceBefore = harness.simulator.getLedger().governanceActionCount;
  await runRecognitionIntakeSafetyScenarios(matrix, {
    verifyRecognitionChallenge, recognitionAssertion, recognitionStatement,
    recognitionAuthoritySeed, recognitionMethodId, recognitionAuthorityDid,
    recognitionAccreditationFixture, harness,
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, recognitionSequenceBefore);
  const verifiedRecognition = await verifyRecognitionChallenge(recognitionAssertion);
  await assert.rejects(verifyRecognitionChallenge(recognitionAssertion), /already consumed/u);
  const recognitionPrepared = harness.prepareRecognitionProposalAction(
    recognition, fromHex(verifiedRecognition.evidenceCommitment),
  );
  assert.equal(asHex(recognitionPrepared.evidenceHash), verifiedRecognition.evidenceCommitment);
  const recognitionEvidenceSignature = harness.signRecognitionProposalEvidence(recognitionPrepared);
  const recognitionSigners = [
    signCompact(second, recognitionPrepared, harness),
    signCompact(third, recognitionPrepared, harness),
  ];
  const proposeRecognitionWithChangedScope = (registryIdCommitment, resourceIdCommitment) =>
    harness.simulator.proposeRecognition(
      recognitionSigners[0].keyId,
      recognitionSigners[0].publicKey,
      recognitionSigners[0].signature,
      recognition.recognitionIdCommitment,
      recognition.recognizedAuthorityDidCommitment,
      registryIdCommitment,
      recognition.scopeResourceTypeCommitment,
      resourceIdCommitment,
      recognitionPrepared.policyCommitment,
      bytes32Commitment(recognition.trustLevel),
      recognitionPrepared.evidenceHash,
      recognitionPrepared.evidenceVerifierAuthorizationId,
      recognitionPrepared.evidenceVerifierKeyIdCommitment,
      recognitionEvidenceSignature,
      recognitionSigners.slice(1),
    );
  matrix.expectThrown(() => proposeRecognitionWithChangedScope(
    bytes32Commitment("registry:external:substituted:v1"), recognition.scopeResourceIdCommitment,
  ), {
    id: "compact-recognition-external-registry-substitution",
    invariant: "A recognition quorum signature cannot be reused for another external registry",
    boundary: "compact", messagePattern: /signature|payload/iu,
    category: "recognition-scope-signature-rejected",
  });
  matrix.expectThrown(() => proposeRecognitionWithChangedScope(
    recognition.recognizedRegistryIdCommitment, bytes32Commitment("credential-family:substituted:v1"),
  ), {
    id: "compact-recognition-resource-substitution",
    invariant: "A recognition quorum signature cannot be reused for another resource scope",
    boundary: "compact", messagePattern: /signature|payload/iu,
    category: "recognition-scope-signature-rejected",
  });
  assert.equal(harness.simulator.getLedger().governanceActionCount, recognitionSequenceBefore);
  assert.throws(() => harness.executeRecognitionProposalWithSignatures(
    recognition,
    recognitionSigners.slice(0, 1),
    recognitionEvidenceSignature,
    recognitionPrepared,
  ), /action threshold/u);
  const recognitionProposalEventHash = harness.executeRecognitionProposalWithSignatures(
    recognition,
    recognitionSigners,
    recognitionEvidenceSignature,
    recognitionPrepared,
  );
  assert.equal(asHex(harness.simulator.getRecognitionProposalEvidence(
    recognition.recognitionIdCommitment,
  ).evidenceCommitment), verifiedRecognition.evidenceCommitment);
  return { verifiedRecognition, recognitionProposalEventHash };
}
