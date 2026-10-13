import { describe, expect, it } from "vitest";

import {
  deriveJubjubPublicKeyFromSeed,
  signPolicyBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import type { MaintainerCoAuthorizer } from "@midnight-ntwrk/trust-registry-contract/testing";
import { TrustRegistrySimulatorClient } from "@midnight-ntwrk/trust-registry-client/simulator";

import {
  createMaintainerScenarioFixture,
  createRecognitionScenarioFixture,
  type MaintainerScenarioFixture,
} from "../fixtures.js";
import {
  LocalTrustRegistryIntegrationHarness,
  type PreparedRecognitionAction,
} from "../local-simulator-harness.js";

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
    const initial = harness.simulator.getLedger().governanceActionCount;
    const signers = [signPrepared(second, proposal), signPrepared(third, proposal)];
    expect(() => harness.executeRecognitionProposalWithSignatures(
      recognition, signers.slice(0, 1),
    )).toThrow();
    expect(() => harness.executeRecognitionProposalWithSignatures(
      recognition, [signers[0]!, signers[0]!],
    )).toThrow();
    expect(() => harness.executeRecognitionProposalWithSignatures(substituted, signers)).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(initial);
    harness.executeRecognitionProposalWithSignatures(recognition, signers);

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
