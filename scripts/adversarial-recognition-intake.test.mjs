import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { test } from "node:test";

import { signJubjubDigestFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { deriveJubjubPublicKeyFromSeed, encodeJubjubSignature } from "../contracts/trust-registry/dist/index.js";
import { sha256Hex } from "../packages/trust-registry-domain/dist/index.js";
import {
  createMaintainerScenarioFixture,
  createMidnightDid,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
  createRecognitionAccreditationVpScenarioFixture,
  createRecognitionScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
  RECOGNITION_VP_FIXTURE_ANCHOR,
  recognitionAccreditationSubmissionCommitment,
  recognitionAuthorityAssertionDigest,
  VP_FIXTURE_TIME_MS,
} from "../packages/trust-registry-integration/dist/index.js";
import {
  InMemoryApplicationChallengeStore,
  RecognitionAuthorityChallengeService,
} from "../packages/trust-registry-api/dist/index.js";

const hex = (value) => `0x${Buffer.from(value).toString("hex")}`;

const startIntake = async (label) => {
  const harness = new LocalTrustRegistryIntegrationHarness(label);
  const second = createMaintainerScenarioFixture(`${label}-second`);
  const third = createMaintainerScenarioFixture(`${label}-third`);
  harness.authorizeMaintainer(second);
  harness.authorizeMaintainer(third);
  harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
  const authoritySeed = new Uint8Array(32).fill(116);
  const authorityDid = createMidnightDid(`${label}-authority`);
  const recognition = createRecognitionScenarioFixture(`${label}-recognition`);
  const anchor = {
    ...RECOGNITION_VP_FIXTURE_ANCHOR,
    targetRegistryId: harness.registryId,
    policyId: harness.policyId,
    policyVersion: `v${(harness.simulator.getLedger().governancePolicyVersion + 1n).toString()}`,
    recognizedRegistryId: recognition.recognizedRegistryId,
    scopeResourceType: recognition.scopeResourceType,
    scopeResourceId: recognition.scopeResourceId,
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
  const service = new RecognitionAuthorityChallengeService(
    new InMemoryApplicationChallengeStore(), () => evaluatedAtMs,
  );
  const challenge = await service.issue(binding);
  const governedAnchor = harness.resolveCurrentRecognitionAccreditorAnchor({
    recognizedRegistryId: binding.recognizedRegistryId,
    scopeResourceType: binding.scopeResourceType,
    scopeResourceId: binding.scopeResourceId,
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
    accreditationSubmissionCommitment: recognitionAccreditationSubmissionCommitment(accreditation.input.submission),
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
  const verify = (assertion = signed, overrides = {}) => service.verifyAndConsumeAccreditedAssertion({
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
  return { harness, accreditation, authorityDid, authoritySeed, methodId, signed, statement, verify };
};

const cases = [
  {
    id: "recognition-intake-wrong-registry-binding",
    reject: ({ signed, statement, verify }) => verify({
      ...signed, statement: { ...statement, recognizedRegistryId: "registry:external:wrong:v1" },
    }),
    message: /does not match/u,
  },
  {
    id: "recognition-intake-authority-signature-mismatch",
    reject: ({ authoritySeed, methodId, signed, statement, verify }) => verify({
      ...signed,
      proof: { ...signed.proof, signature: hex(encodeJubjubSignature(signJubjubDigestFromSeed(
        authoritySeed,
        recognitionAuthorityAssertionDigest({ ...statement, scopeResourceId: "credential-family:wrong:v1" }, methodId),
      ))) },
    }),
    message: /signature is invalid/u,
  },
  {
    id: "recognition-intake-governance-policy-drift",
    reject: ({ harness, verify }) => verify(undefined, {
      readCurrentGovernance: async () => ({
        governancePolicy: harness.policyRecord,
        activePolicyCommitment: sha256Hex("stale-recognition-policy"),
      }),
    }),
    message: /active governed policy/u,
  },
  {
    id: "recognition-intake-inactive-accreditation-status",
    reject: ({ accreditation, verify }) => verify(undefined, {
      statusSource: {
        verifyPinnedStatus: async (request) => ({
          ...await accreditation.input.statusSource.verifyPinnedStatus(request), active: false,
        }),
      },
    }),
    message: /status is not active/u,
  },
  {
    id: "recognition-intake-accreditation-substitution",
    reject: ({ accreditation, verify }) => verify(undefined, {
      accreditation: {
        ...accreditation.input.submission,
        rawCredentialBody: `${accreditation.input.submission.rawCredentialBody} `,
      },
    }),
    message: /submitted accreditation VP/u,
  },
  {
    id: "recognition-intake-rotated-authority-did-key",
    reject: ({ authorityDid, verify }) => verify(undefined, {
      resolver: createMidnightDidResolver([
        createMidnightDidLedgerFixture(authorityDid, {
          schnorrJubjubAssertionMethods: [{
            id: "assertion-1",
            publicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(117)),
          }],
        }),
      ]),
    }),
    message: /signature is invalid/u,
  },
];

for (const scenario of cases) {
  test(scenario.id, async () => {
    const fixture = await startIntake(`isolated-${scenario.id}`);
    const actionsBefore = fixture.harness.simulator.getLedger().governanceActionCount;
    await assert.rejects(scenario.reject(fixture), scenario.message);
    assert.equal(fixture.harness.simulator.getLedger().governanceActionCount, actionsBefore);
    const accepted = await fixture.verify();
    assert.match(accepted.evidenceCommitment, /^0x[0-9a-f]{64}$/u);
    await assert.rejects(fixture.verify(), /already consumed/u);
  });
}
