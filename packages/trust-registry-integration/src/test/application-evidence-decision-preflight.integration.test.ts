import { describe, expect, it } from "vitest";

import {
  createAuditorScenarioFixture,
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  createVerifierAuthorizationScopeFixture,
  createVerifierScenarioFixture,
} from "../fixtures.js";
import {
  LocalTrustRegistryIntegrationHarness,
  type SimulatorApplicationEvidenceExpectation,
} from "../local-simulator-harness.js";

describe("accepted application evidence at the decision boundary", () => {
  it("does not prepare stale verifier, auditor, or maintainer approvals after policy revision", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("evidence-decision-preflight");
    const second = createMaintainerScenarioFixture("evidence-decision-second");
    const third = createMaintainerScenarioFixture("evidence-decision-third");
    const fourth = createMaintainerScenarioFixture("evidence-decision-fourth");
    harness.authorizeMaintainer(second);
    harness.authorizeMaintainer(third);
    harness.authorizeMaintainer(fourth);
    harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);

    const verifier = createVerifierScenarioFixture("evidence-decision-verifier");
    const auditor = createAuditorScenarioFixture("evidence-decision-auditor");
    const candidate = createMaintainerScenarioFixture("evidence-decision-candidate");
    harness.proposeVerifier(verifier);
    harness.proposeAuditor(auditor);
    harness.proposeMaintainer(candidate);
    expect(harness.prepareVerifierDecisionAction(verifier, "approve").evidenceHash).toHaveLength(32);
    expect(harness.prepareAuditorDecisionAction(auditor, "approve").evidenceHash).toHaveLength(32);
    expect(harness.prepareMaintainerDecisionAction(candidate, "approve").evidenceHash).toHaveLength(32);

    harness.updateMaintainerThresholdPolicy(3n, 1n, 2n, [second]);
    const before = harness.simulator.getLedger().governanceActionCount;
    for (const prepare of [
      () => harness.prepareVerifierDecisionAction(verifier, "approve"),
      () => harness.prepareVerifierDecisionAction(verifier, "activate"),
      () => harness.prepareAuditorDecisionAction(auditor, "approve"),
      () => harness.prepareAuditorDecisionAction(auditor, "activate"),
      () => harness.prepareMaintainerDecisionAction(candidate, "approve"),
      () => harness.prepareMaintainerDecisionAction(candidate, "activate"),
    ]) {
      expect(prepare).toThrow();
    }
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before);
  });

  it("does not prepare any applicant approval after accepted evidence expires", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("evidence-decision-expiry");
    const issuer = createIssuerScenarioFixture("evidence-expiry-issuer");
    const verifier = createVerifierScenarioFixture("evidence-expiry-verifier");
    const auditor = createAuditorScenarioFixture("evidence-expiry-auditor");
    const candidate = createMaintainerScenarioFixture("evidence-expiry-maintainer");
    harness.proposeIssuer(issuer);
    harness.proposeVerifier(verifier);
    harness.proposeAuditor(auditor);
    harness.proposeMaintainer(candidate);

    harness.advanceEvidenceTimeBy(24 * 60 * 60 * 1000 + 1);
    const before = harness.simulator.getLedger().governanceActionCount;
    for (const prepare of [
      () => harness.prepareIssuerDecisionAction(issuer, "approve"),
      () => harness.prepareVerifierDecisionAction(verifier, "approve"),
      () => harness.prepareAuditorDecisionAction(auditor, "approve"),
      () => harness.prepareMaintainerDecisionAction(candidate, "approve"),
    ]) {
      expect(prepare).toThrow();
    }
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before);
  });

  it("rechecks the current issuer and verifier scope before preparing approval", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("evidence-decision-scope");
    const issuer = createIssuerScenarioFixture("evidence-scope-issuer");
    const verifier = createVerifierScenarioFixture("evidence-scope-verifier");
    harness.proposeIssuer(issuer);
    harness.proposeVerifier(verifier);

    const changedIssuer = {
      ...issuer,
      authorizationScope: { ...issuer.authorizationScope, schemaVersion: "2.0.0" },
    };
    const changedVerifier = { ...verifier, requestProfileId: `${verifier.requestProfileId}-changed` };
    expect(() => harness.prepareIssuerDecisionAction(changedIssuer, "approve")).toThrow();
    expect(() => harness.prepareVerifierDecisionAction(changedVerifier, "approve")).toThrow();
  });

  it("snapshots accepted evidence before crossing the Compact proposal boundary", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("evidence-snapshot-boundary");
    const verifier = createVerifierScenarioFixture("evidence-snapshot-verifier");
    const scope = createVerifierAuthorizationScopeFixture(verifier);
    const evidence = harness.createApplicationEvidence({
      applicationId: verifier.authorizationId,
      subjectDid: verifier.subjectDid,
      role: "verifier",
      scope,
    });
    const expectation = {
      scope,
      challengeHash: evidence.envelope.challengeHash,
      governedResource: { type: "requestProfile", id: verifier.scopeResourceId },
      uncloneable: () => true,
    } as SimulatorApplicationEvidenceExpectation;
    const before = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.proposeVerifierWithApplicationEvidence(verifier, evidence, expectation)).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before);
    expect(() => harness.simulator.getVerifierAuthorization(verifier.authorizationIdCommitment)).toThrow();
  });
});
