import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { signJubjubDigestFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";

import {
  deriveJubjubPublicKeyFromSeed,
  encodeJubjubSignature,
  signPolicyBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import type { MaintainerCoAuthorizer } from "@midnight-ntwrk/trust-registry-contract/testing";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";
import { sha256Hex, type RecognitionAuthorityAssertion } from "@midnight-ntwrk/trust-registry-domain";

import { createMidnightDidLedgerFixture, createMidnightDidResolver } from "../did-resolution.js";
import {
  bytes32Commitment,
  createMaintainerScenarioFixture,
  createMidnightDid,
  createRecognitionScenarioFixture,
  type MaintainerScenarioFixture,
} from "../fixtures.js";
import {
  LocalTrustRegistryIntegrationHarness,
  type PreparedRecognitionAction,
} from "../local-simulator-harness.js";
import { recognitionAuthorityAssertionDigest } from "../recognition-authority-assertion.js";

const signPrepared = (
  maintainer: MaintainerScenarioFixture,
  action: Pick<PreparedRecognitionAction,
    "registryId" | "policyCommitment" | "actionKind" | "actionPayloadHash" | "actionSequence">,
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    action.registryId,
    action.policyCommitment,
    action.actionKind,
    action.actionPayloadHash,
    action.actionSequence,
  ),
});

describe("externally signed Compact authority recognition", () => {
  it("archives a proposed recognition with a fresh external quorum", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("denied-recognition");
    const second = createMaintainerScenarioFixture("denial-second");
    const third = createMaintainerScenarioFixture("denial-third");
    const recognition = createRecognitionScenarioFixture("denied-authority");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.proposeRecognition(recognition);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);

    const prepared = harness.prepareRecognitionDecisionAction(recognition, "archive");
    const signers = [signPrepared(second, prepared), signPrepared(third, prepared)];
    expect(() => harness.executeRecognitionDecisionWithSignatures(
      recognition, "archive", signers.slice(0, 1),
    )).toThrow();
    harness.executeRecognitionDecisionWithSignatures(recognition, "archive", signers);
    expect(harness.readRecognitionStatus(recognition)).toBe("archived");
    expect(() => harness.executeRecognitionDecisionWithSignatures(
      recognition, "archive", signers,
    )).toThrow();
  });

  it("commits a DID-verified authority statement rather than fixture evidence", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("did-recognition");
    const authoritySeed = new Uint8Array(32).fill(116);
    const authorityDid = createMidnightDid("did-recognition-authority");
    const methodId = `${authorityDid}#assert-1`;
    const base = createRecognitionScenarioFixture("did-recognition-authority");
    const recognition = {
      ...base,
      recognizedAuthorityDid: authorityDid,
      recognizedAuthorityDidCommitment: bytes32Commitment(authorityDid),
    };
    const resolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(authorityDid, {
        schnorrJubjubAssertionMethods: [
          { id: "assert-1", publicKey: deriveJubjubPublicKeyFromSeed(authoritySeed) },
        ],
      }),
    ]);
    const challengeHash = sha256Hex("did-recognition-challenge");
    const statement: RecognitionAuthorityAssertion = {
      version: "tr-recognition-authority-assertion-v1",
      targetRegistryId: harness.registryId,
      recognitionId: recognition.recognitionId,
      authorityDid,
      recognizedRegistryId: recognition.recognizedRegistryId,
      scopeResourceType: recognition.scopeResourceType,
      scopeResourceId: recognition.scopeResourceId,
      accreditationSubmissionCommitment: sha256Hex("external-accreditation-document"),
      challengeHash,
      issuedAt: "2026-05-20T00:00:00.000Z",
      expiresAt: "2026-05-20T01:00:00.000Z",
    };
    const signed = {
      statement,
      proof: {
        verificationMethodId: methodId,
        algorithm: "jubjub-schnorr" as const,
        signature: `0x${Buffer.from(encodeJubjubSignature(
          signJubjubDigestFromSeed(
            authoritySeed, recognitionAuthorityAssertionDigest(statement, methodId),
          ),
        )).toString("hex")}`,
      },
    };
    const prepare = (candidate = signed) => harness.prepareRecognitionProposalFromAuthorityAssertion({
      fixture: recognition,
      signed: candidate,
      challengeHash,
      evaluatedAtMs: Date.parse("2026-05-20T00:10:00.000Z"),
      resolver,
    });
    const before = harness.simulator.getLedger().governanceActionCount;
    await expect(prepare({
      ...signed,
      statement: { ...statement, recognizedRegistryId: "registry:substituted:v1" },
    })).rejects.toThrow(/does not match/u);
    await expect(prepare({
      ...signed,
      proof: { ...signed.proof, signature: `0x${"00".repeat(96)}` },
    })).rejects.toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before);

    const prepared = await prepare();
    expect(prepared.evidenceHash).not.toEqual(bytes32Commitment(`${recognition.recognitionId}:propose`));
    const second = createMaintainerScenarioFixture("did-recognition-second");
    const third = createMaintainerScenarioFixture("did-recognition-third");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const current = await prepare();
    const evidenceSignature = harness.signRecognitionProposalEvidence(current);
    const signers = [signPrepared(second, current), signPrepared(third, current)];
    expect(() => harness.executeRecognitionProposalWithSignatures(
      recognition, signers, evidenceSignature, prepared,
    )).toThrow(/stale or substituted/u);
    const eventHash = harness.executeRecognitionProposalWithSignatures(
      recognition, signers, evidenceSignature, current,
    );
    const evidence = harness.simulator.getRecognitionProposalEvidence(recognition.recognitionIdCommitment);
    expect(Buffer.from(evidence.evidenceCommitment)).toEqual(Buffer.from(current.evidenceHash));
    expect(Buffer.from(evidence.proposalGovernanceEventHash)).toEqual(Buffer.from(eventHash));
    harness.approveRecognition(recognition);
    harness.activateRecognition(recognition);
    const bundle = harness.evaluateCurrentRecognitionDecision(recognition, {
      expectedRegistryId: harness.registryId,
    });
    expect(bundle.recognition?.status).toBe("active");
    expect(bundle.authorization).toBeUndefined();
  });

  it("binds external authority and scope across 2-of-3 proposal, approval, and activation", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-recognition");
    const second = createMaintainerScenarioFixture("recognition-second");
    const third = createMaintainerScenarioFixture("recognition-third");
    const recognition = createRecognitionScenarioFixture("recognized-authority");
    const substituted = createRecognitionScenarioFixture("other-authority");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    const proposal = harness.prepareRecognitionProposalAction(recognition);
    const evidenceSignature = harness.signRecognitionProposalEvidence(proposal);
    const initial = harness.simulator.getLedger().governanceActionCount;
    const signers = [signPrepared(second, proposal), signPrepared(third, proposal)];
    expect(() => harness.executeRecognitionProposalWithSignatures(
      recognition, signers.slice(0, 1), evidenceSignature,
    )).toThrow();
    expect(() => harness.executeRecognitionProposalWithSignatures(
      recognition, [signers[0]!, signers[0]!], evidenceSignature,
    )).toThrow();
    expect(() => harness.executeRecognitionProposalWithSignatures(
      substituted, signers, evidenceSignature,
    )).toThrow();
    expect(() => harness.executeRecognitionProposalWithSignatures(
      recognition, signers, { ...evidenceSignature, response: 0n },
    )).toThrow(/invalid jubjub schnorr signature/i);
    expect(harness.simulator.getLedger().governanceActionCount).toBe(initial);
    harness.executeRecognitionProposalWithSignatures(recognition, signers, evidenceSignature);

    const approval = harness.prepareRecognitionDecisionAction(recognition, "approve");
    expect(() => harness.prepareRecognitionDecisionAction(recognition, "unsupported" as "approve"))
      .toThrow(/Unsupported recognition decision action/u);
    const beforeApproval = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeRecognitionDecisionWithSignatures(recognition, "approve", [
      signPrepared(second, { ...approval, policyCommitment: new Uint8Array(32) }),
      signPrepared(third, approval),
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeApproval);
    harness.executeRecognitionDecisionWithSignatures(recognition, "approve", [
      signPrepared(second, approval), signPrepared(third, approval),
    ]);

    const activation = harness.prepareRecognitionDecisionAction(recognition, "activate");
    const beforeActivation = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeRecognitionDecisionWithSignatures(recognition, "activate", [
      signPrepared(second, approval), signPrepared(third, approval),
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeActivation);
    harness.executeRecognitionDecisionWithSignatures(recognition, "activate", [
      signPrepared(second, activation), signPrepared(third, activation),
    ]);

    const bundle = harness.evaluateCurrentRecognitionDecision(recognition, {
      expectedRegistryId: harness.registryId,
    });
    expect(bundle.recognition?.status).toBe("active");
    expect(bundle.recognition?.recognizedRegistryId).toBe(recognition.recognizedRegistryId);
    expect(bundle.recognition?.scope.resourceId).toBe(recognition.scopeResourceId);
    expect(bundle.authorization).toBeUndefined();
    expect(() => new TrustRegistrySimulatorClient(harness.simulator)
      .verifyRecognitionBundle(bundle, {})).not.toThrow();
  });
});
