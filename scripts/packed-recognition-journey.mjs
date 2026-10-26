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
import { publishSimulatorSnapshot } from "@midnight-ntwrk/trust-registry-cli";
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
  createTrustRegistryApiServer,
  InMemoryApplicationChallengeStore,
  RecognitionAccreditationAuthorizationDeniedError,
  RecognitionAuthorityChallengeService,
  resolveCompactProposalEvidenceSnapshot,
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
const proposalSnapshot = await resolveCompactProposalEvidenceSnapshot(
  async () => harness.simulator.getLedger(), harness.registryId, "recognition", recognition.recognitionId,
  Buffer.from(harness.simulator.contractAddress, "hex"),
);
assert.equal(proposalSnapshot?.evidenceCommitment, verified.evidenceCommitment);
assert.equal(proposalSnapshot?.eventHash, hex(proposalEventHash));
assert.equal(proposalSnapshot?.signatureVerified, true);
assert.match(proposalSnapshot.boundActionPayloadHash, /^0x[0-9a-f]{64}$/u);
await assert.rejects(resolveCompactProposalEvidenceSnapshot(
  async () => harness.simulator.getLedger(), "registry:other", "recognition", recognition.recognitionId,
  Buffer.from(harness.simulator.contractAddress, "hex"),
), /different trust registry/u);
const recognitionAccreditationPort = {
  challengeStore: new InMemoryApplicationChallengeStore(),
  authorizeRequest: async (_recognitionId, request) => {
    if (request.headers.authorization !== "Bearer packed-recognition-fixture") {
      throw new RecognitionAccreditationAuthorizationDeniedError();
    }
  },
  resolveCurrentContext: async (recognitionId) => recognitionId === recognition.recognitionId ? {
    binding,
    governancePolicy: harness.policyRecord,
    activePolicyCommitment: hex(harness.simulator.getLedger().governancePolicyCommitment),
    resolver: accreditation.input.resolver,
    statusSource: accreditation.input.statusSource,
  } : null,
};
const api = createTrustRegistryApiServer({
  source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "packed-recognition" }) },
  proposalContractAddress: Buffer.from(harness.simulator.contractAddress, "hex"),
  readFinalizedProposalLedger: async () => harness.simulator.getLedger(),
  recognitionAccreditation: recognitionAccreditationPort,
});
try {
  await new Promise((resolve) => api.listen(0, "127.0.0.1", resolve));
  const address = api.address();
  if (address === null || typeof address === "string") throw new Error("TCP address unavailable");
  const endpoint = `http://127.0.0.1:${address.port}/v1/governed/recognition/`;
  const evidenceUrl = `${endpoint}${encodeURIComponent(recognition.recognitionId)}/proposal/evidence`;
  const unauthorized = await fetch(evidenceUrl);
  assert.equal(unauthorized.status, 403);
  assert.match((await unauthorized.json()).type, /recognition-accreditation-forbidden$/u);
  const authorization = { authorization: "Bearer packed-recognition-fixture" };
  const response = await fetch(evidenceUrl, { headers: authorization });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const observed = await response.json();
  assert.equal(observed.evidenceCommitment, proposalSnapshot.evidenceCommitment);
  assert.equal(observed.eventHash, proposalSnapshot.eventHash);
  assert.equal(observed.signatureVerified, true);
  const absent = await fetch(`${endpoint}${encodeURIComponent("recognition:absent")}/proposal/evidence`, {
    headers: authorization,
  });
  assert.equal(absent.status, 404);
  assert.match((await absent.json()).type, /proposal-evidence-not-found$/u);
} finally {
  await new Promise((resolve, reject) => api.close((error) => error ? reject(error) : resolve()));
}
const unavailableApi = createTrustRegistryApiServer({
  source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "packed-recognition" }) },
});
try {
  await new Promise((resolve) => unavailableApi.listen(0, "127.0.0.1", resolve));
  const address = unavailableApi.address();
  if (address === null || typeof address === "string") throw new Error("TCP address unavailable");
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/governed/recognition/`
    + `${encodeURIComponent(recognition.recognitionId)}/proposal/evidence`);
  assert.equal(response.status, 503);
  assert.match((await response.json()).type, /recognition-accreditation-unavailable$/u);
} finally {
  await new Promise((resolve, reject) => unavailableApi.close((error) => error ? reject(error) : resolve()));
}
const missingLedgerApi = createTrustRegistryApiServer({
  source: { mode: "memory", loadSnapshot: async () => publishSimulatorSnapshot(harness, { label: "packed-recognition" }) },
  recognitionAccreditation: recognitionAccreditationPort,
});
try {
  await new Promise((resolve) => missingLedgerApi.listen(0, "127.0.0.1", resolve));
  const address = missingLedgerApi.address();
  if (address === null || typeof address === "string") throw new Error("TCP address unavailable");
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/governed/recognition/`
    + `${encodeURIComponent(recognition.recognitionId)}/proposal/evidence`, {
    headers: { authorization: "Bearer packed-recognition-fixture" },
  });
  assert.equal(response.status, 503);
  assert.match((await response.json()).type, /proposal-evidence-unavailable$/u);
} finally {
  await new Promise((resolve, reject) => missingLedgerApi.close((error) => error ? reject(error) : resolve()));
}
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
process.stdout.write(`${JSON.stringify({
  demo: "packed-recognition-journey",
  mode: "local Compact simulator; no network finality",
  policyVersion: proposalSnapshot.policyVersion,
  epochId: bundle.epoch.epochId,
  signerKeyIds: signers.map(({ keyId }) => hex(keyId)),
  evidenceCommitment: proposalSnapshot.evidenceCommitment,
  proposalEventHash: proposalSnapshot.eventHash,
  proposalSignatureVerified: proposalSnapshot.signatureVerified,
  proposalApiEvidenceVerified: true,
  activeDecision: "trusted recognition, not local issuer authorization",
  finalDecision: "suspended recognition",
  expectedRejections: [
    "wrong-external-registry", "substituted-authority-assertion", "inactive-accreditation-status",
    "replayed-challenge", "insufficient-maintainer-quorum", "wrong-recognition-registry",
    "suspended-current-decision", "unauthorized-proposal-evidence:403", "missing-proposal-evidence:404",
    "unavailable-accreditation-port:503", "unavailable-ledger-reader:503",
  ],
}, null, 2)}\n`);
