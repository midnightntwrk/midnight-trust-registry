import { describe, expect, it } from "vitest";

import {
  computeUpdateIssuerAuthorizationPayloadHash,
  deriveJubjubPublicKeyFromSeed,
  signPolicyBoundMaintainerActionFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import type { MaintainerCoAuthorizer } from "@midnight-ntwrk/trust-registry-contract/testing";

import {
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  type MaintainerScenarioFixture,
} from "../fixtures.js";
import {
  LocalTrustRegistryIntegrationHarness,
  type PreparedIssuerDecisionAction,
} from "../local-simulator-harness.js";

const signPreparedAction = (
  maintainer: MaintainerScenarioFixture,
  prepared: PreparedIssuerDecisionAction,
): MaintainerCoAuthorizer => ({
  keyId: maintainer.keyId,
  publicKey: deriveJubjubPublicKeyFromSeed(maintainer.seed),
  signature: signPolicyBoundMaintainerActionFromSeed(
    maintainer.seed,
    prepared.registryId,
    prepared.policyCommitment,
    prepared.actionKind,
    prepared.actionPayloadHash,
    prepared.actionSequence,
  ),
});

describe("externally signed Compact issuer decisions", () => {
  it("requires two distinct active maintainer signatures for approval and activation", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-signers");
    const second = createMaintainerScenarioFixture("external-second");
    const third = createMaintainerScenarioFixture("external-third");
    const issuer = createIssuerScenarioFixture("external-issuer");

    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    harness.proposeIssuer(issuer, [second]);

    const approval = harness.prepareIssuerDecisionAction(issuer, "approve");
    expect(approval.actionPayloadHash).toEqual(computeUpdateIssuerAuthorizationPayloadHash(
      approval.authorizationId,
      approval.previousLifecycleEventHash,
      approval.evidenceHash,
    ));
    const firstSignature = signPreparedAction(second, approval);
    const secondSignature = signPreparedAction(third, approval);
    const beforeApproval = harness.simulator.getLedger().governanceActionCount;

    expect(() => harness.executeIssuerDecisionWithSignatures(
      issuer, "approve", [firstSignature],
    )).toThrow();
    expect(() => harness.executeIssuerDecisionWithSignatures(
      issuer, "approve", [firstSignature, firstSignature],
    )).toThrow();
    expect(() => harness.executeIssuerDecisionWithSignatures(
      issuer, "approve", [
        firstSignature,
        signPreparedAction(createMaintainerScenarioFixture("unknown-signer"), approval),
      ],
    )).toThrow();
    expect(() => harness.prepareIssuerDecisionAction(issuer, "unknown" as "approve")).toThrow(
      /Unsupported issuer decision action/,
    );
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeApproval);

    harness.executeIssuerDecisionWithSignatures(issuer, "approve", [firstSignature, secondSignature]);
    const activation = harness.prepareIssuerDecisionAction(issuer, "activate");
    const beforeActivation = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeIssuerDecisionWithSignatures(
      issuer, "activate", [firstSignature, secondSignature],
    )).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(beforeActivation);

    harness.executeIssuerDecisionWithSignatures(issuer, "activate", [
      signPreparedAction(second, activation),
      signPreparedAction(third, activation),
    ]);
    expect(harness.evaluateCurrentIssuerDecision(issuer).authorization?.status).toBe("active");
  });

  it("rejects a policy-substituted signature without changing the proposal", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("external-policy");
    const issuer = createIssuerScenarioFixture("external-policy-issuer");
    const second = createMaintainerScenarioFixture("external-policy-second");
    const third = createMaintainerScenarioFixture("external-policy-third");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);
    harness.proposeIssuer(issuer, [second]);

    const prepared = harness.prepareIssuerDecisionAction(issuer, "approve");
    const altered = { ...prepared, policyCommitment: new Uint8Array(32) };
    const before = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.executeIssuerDecisionWithSignatures(issuer, "approve", [
      signPreparedAction(second, altered),
      signPreparedAction(third, prepared),
    ])).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before);
  });
});
