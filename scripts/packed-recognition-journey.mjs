import assert from "node:assert/strict";
import { Buffer } from "node:buffer";

import { signJubjubDigestFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signDeploymentBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { bytes32Commitment } from "@midnight-ntwrk/trust-registry-client";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";
import {
  createMaintainerScenarioFixture,
  createMidnightDid,
  createRecognitionAccreditationVpScenarioFixture,
  createRecognitionScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  RECOGNITION_VP_FIXTURE_ANCHOR,
  recognitionAccreditationSubmissionCommitment,
  recognitionAuthorityAssertionDigest,
  VP_FIXTURE_TIME_MS,
} from "@midnight-ntwrk/trust-registry-integration";
import {
  InMemoryApplicationChallengeStore,
  RecognitionAuthorityChallengeService,
} from "@midnight-ntwrk/trust-registry-api";

const hex = (value) => `0x${Buffer.from(value).toString("hex")}`;
const bytes = (value) => Buffer.from(value.slice(2), "hex");
const harness = new LocalTrustRegistryIntegrationHarness("packed-recognition");
const client = new TrustRegistrySimulatorClient(harness.simulator);
const second = createMaintainerScenarioFixture("packed-recognition-second");
const third = createMaintainerScenarioFixture("packed-recognition-third");
harness.authorizeMaintainer(second);
harness.authorizeMaintainer(third);
harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);

const authoritySeed = new Uint8Array(32).fill(116);
const authorityDid = createMidnightDid("packed-recognition-authority");
const base = createRecognitionScenarioFixture("packed-recognition-authority");
const anchor = {
  ...RECOGNITION_VP_FIXTURE_ANCHOR,
  targetRegistryId: harness.registryId,
  policyId: harness.policyId,
  policyVersion: `v${(harness.simulator.getLedger().governancePolicyVersion + 1n).toString()}`,
};
const recognition = {
  ...base,
  recognizedAuthorityDid: authorityDid,
  recognizedAuthorityDidCommitment: bytes32Commitment(authorityDid),
  recognizedRegistryId: anchor.recognizedRegistryId,
  recognizedRegistryIdCommitment: bytes32Commitment(anchor.recognizedRegistryId),
  scopeResourceType: anchor.scopeResourceType,
  scopeResourceTypeCommitment: bytes32Commitment(anchor.scopeResourceType),
  scopeResourceId: anchor.scopeResourceId,
  scopeResourceIdCommitment: bytes32Commitment(anchor.scopeResourceId),
};
harness.governRecognitionAccreditorAnchor(anchor, [second]);
harness.advanceEvidenceTimeBy(60_000);
const evaluatedAtMs = Math.max(VP_FIXTURE_TIME_MS, Date.parse(harness.policyRecord.effectiveFrom) + 60_000);
const binding = {
  targetRegistryId: harness.registryId,
  recognitionId: recognition.recognitionId,
  authorityDid,
  recognizedRegistryId: recognition.recognizedRegistryId,
  scopeResourceType: recognition.scopeResourceType,
  scopeResourceId: recognition.scopeResourceId,
};
const challengeService = new RecognitionAuthorityChallengeService(
  new InMemoryApplicationChallengeStore(), () => evaluatedAtMs,
);
const challenge = await challengeService.issue(binding);
const governedAnchor = harness.resolveCurrentRecognitionAccreditorAnchor({
  recognizedRegistryId: recognition.recognizedRegistryId,
  scopeResourceType: recognition.scopeResourceType,
  scopeResourceId: recognition.scopeResourceId,
  evaluatedAtMs,
});
const accreditation = await createRecognitionAccreditationVpScenarioFixture({
  nonce: challenge.nonce,
  evaluatedAtMs,
  authorityDid,
  authorityAssertionSeed: authoritySeed,
  anchor: governedAnchor.anchor,
});
const methodId = `${authorityDid}#assertion-1`;
const statement = {
  version: "tr-recognition-authority-assertion-v1",
  ...binding,
  accreditationSubmissionCommitment: recognitionAccreditationSubmissionCommitment(
    accreditation.input.submission,
  ),
  challengeHash: challenge.challengeHash,
  issuedAt: new Date(evaluatedAtMs).toISOString(),
  expiresAt: new Date(evaluatedAtMs + 50 * 60_000).toISOString(),
};
const signed = {
  statement,
  proof: {
    verificationMethodId: methodId,
    algorithm: "jubjub-schnorr",
    signature: hex(encodeJubjubSignature(signJubjubDigestFromSeed(
      authoritySeed, recognitionAuthorityAssertionDigest(statement, methodId),
    ))),
  },
};
const verifyAccreditation = (assertion, overrides = {}) =>
  challengeService.verifyAndConsumeAccreditedAssertion({
    binding,
    nonce: challenge.nonce,
    signed: assertion,
    accreditation: accreditation.input.submission,
    readCurrentGovernance: async () => ({
      governancePolicy: harness.policyRecord,
      activePolicyCommitment: hex(harness.simulator.getLedger().governancePolicyCommitment),
    }),
    resolver: accreditation.input.resolver,
    statusSource: accreditation.input.statusSource,
    ...overrides,
  });
await assert.rejects(verifyAccreditation({
  ...signed,
  statement: { ...statement, recognizedRegistryId: "registry:external:substituted:v1" },
}), /does not match/u);
await assert.rejects(verifyAccreditation({
  ...signed,
  proof: {
    ...signed.proof,
    signature: hex(encodeJubjubSignature(signJubjubDigestFromSeed(
      authoritySeed,
      recognitionAuthorityAssertionDigest({
        ...statement,
        scopeResourceId: "credential-family:substituted:v1",
      }, methodId),
    ))),
  },
}), /signature is invalid/u);
await assert.rejects(verifyAccreditation(signed, {
  statusSource: {
    verifyPinnedStatus: async (request) => ({
      ...await accreditation.input.statusSource.verifyPinnedStatus(request),
      active: false,
    }),
  },
}), /status is not active/u);
const verified = await verifyAccreditation(signed);
await assert.rejects(verifyAccreditation(signed), /already consumed/u);

const prepared = harness.prepareRecognitionProposalAction(recognition, bytes(verified.evidenceCommitment));
const signMaintainer = (maintainer) => {
  const ledger = harness.simulator.getLedger();
  return {
    keyId: maintainer.keyId,
    publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
    signature: signDeploymentBoundMaintainerActionFromSeed(
      maintainer.seed,
      ledger.registryId,
      ledger.deploymentNetworkIdCommitment,
      Buffer.from(harness.simulator.contractAddress, "hex"),
      ledger.governancePolicyCommitment,
      prepared.actionKind,
      prepared.actionPayloadHash,
      prepared.actionSequence,
    ),
  };
};
const signers = [signMaintainer(second), signMaintainer(third)];
const verifierSignature = harness.signRecognitionProposalEvidence(prepared);
assert.throws(() => harness.executeRecognitionProposalWithSignatures(
  recognition, signers.slice(0, 1), verifierSignature, prepared,
), /action threshold/u);
const proposalEventHash = harness.executeRecognitionProposalWithSignatures(
  recognition, signers, verifierSignature, prepared,
);
assert.equal(hex(harness.simulator.getRecognitionProposalEvidence(
  recognition.recognitionIdCommitment,
).evidenceCommitment), verified.evidenceCommitment);
harness.approveRecognition(recognition);
harness.activateRecognition(recognition);
const bundle = harness.evaluateCurrentRecognitionDecision(recognition, { expectedRegistryId: harness.registryId });
assert.equal(client.verifyRecognitionBundle(bundle, {
  expectedRecognizedRegistryId: recognition.recognizedRegistryId,
  expectedResourceId: recognition.scopeResourceId,
}).recognition?.status, "active");
assert.throws(() => client.verifyRecognitionBundle(bundle, {
  expectedRecognizedRegistryId: "registry:external:substituted:v1",
}), /registry mismatch/u);
harness.suspendRecognition(recognition);
assert.throws(() => harness.evaluateCurrentRecognitionDecision(recognition), /not active/i);
assert.equal(harness.simulator.getLedger().issuerAuthorizationCount, 0n);
assert.match(hex(proposalEventHash), /^0x[0-9a-f]{64}$/u);
console.log("[packed-recognition] VC/VP accreditation, governed proposal, replay refusal, and suspension passed.");
