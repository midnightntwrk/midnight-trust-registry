import { describe, expect, it } from "vitest";
import { EvidenceVerifierKeyStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import {
  createAuditorScenarioFixture,
  createAuditorAuthorizationScopeFixture,
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

  it("rejects pending approvals after verifier-key rotation and accepts fresh evidence", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("evidence-decision-key-rotation");
    const pendingIssuer = createIssuerScenarioFixture("evidence-key-pending-issuer");
    const pendingVerifier = createVerifierScenarioFixture("evidence-key-pending-verifier");
    const pendingAuditor = createAuditorScenarioFixture("evidence-key-pending-auditor");
    const pendingMaintainer = createMaintainerScenarioFixture("evidence-key-pending-maintainer");
    harness.proposeIssuer(pendingIssuer);
    harness.proposeVerifier(pendingVerifier);
    harness.proposeAuditor(pendingAuditor);
    harness.proposeMaintainer(pendingMaintainer);
    const previousKeyId = harness.evidenceVerifier.keyIds[0];
    const previousKey = harness.simulator.getIssuerProposalEvidence(
      pendingIssuer.authorizationIdCommitment,
    ).evidenceVerifierAuthorizationId;

    harness.rotateEvidenceVerifierKey("replacement");
    expect(harness.evidenceVerifier.keyIds).toHaveLength(1);
    expect(harness.evidenceVerifier.keyIds[0]).not.toBe(previousKeyId);
    expect(harness.simulator.getLedger().evidenceVerifierKeyCount).toBe(2n);
    expect(harness.simulator.getEvidenceVerifierKey(previousKey).status)
      .toBe(EvidenceVerifierKeyStatus.retired);
    for (const prepare of [
      () => harness.prepareIssuerDecisionAction(pendingIssuer, "approve"),
      () => harness.prepareVerifierDecisionAction(pendingVerifier, "approve"),
      () => harness.prepareAuditorDecisionAction(pendingAuditor, "approve"),
      () => harness.prepareMaintainerDecisionAction(pendingMaintainer, "approve"),
    ]) {
      expect(prepare).toThrow();
    }

    const nextIssuer = createIssuerScenarioFixture("evidence-key-next-issuer");
    const nextVerifier = createVerifierScenarioFixture("evidence-key-next-verifier");
    const nextAuditor = createAuditorScenarioFixture("evidence-key-next-auditor");
    const nextMaintainer = createMaintainerScenarioFixture("evidence-key-next-maintainer");
    harness.proposeIssuer(nextIssuer);
    harness.proposeVerifier(nextVerifier);
    harness.proposeAuditor(nextAuditor);
    harness.proposeMaintainer(nextMaintainer);
    const replacementKey = harness.simulator.getIssuerProposalEvidence(
      nextIssuer.authorizationIdCommitment,
    ).evidenceVerifierAuthorizationId;
    expect(harness.simulator.getEvidenceVerifierKey(replacementKey).status)
      .toBe(EvidenceVerifierKeyStatus.active);
    for (const prepare of [
      () => harness.prepareIssuerDecisionAction(nextIssuer, "approve"),
      () => harness.prepareVerifierDecisionAction(nextVerifier, "approve"),
      () => harness.prepareAuditorDecisionAction(nextAuditor, "approve"),
      () => harness.prepareMaintainerDecisionAction(nextMaintainer, "approve"),
    ]) {
      expect(prepare().evidenceHash).toHaveLength(32);
    }
  });

  it("rejects evidence before signing when the verifier key is suspended or revoked", () => {
    const harness = new LocalTrustRegistryIntegrationHarness("evidence-decision-key-suspension");
    const issuer = createIssuerScenarioFixture("evidence-key-suspended-issuer");
    const verifier = createVerifierScenarioFixture("evidence-key-suspended-verifier");
    harness.proposeIssuer(issuer);
    harness.proposeVerifier(verifier);
    const keyAuthorizationId = harness.simulator.getIssuerProposalEvidence(
      issuer.authorizationIdCommitment,
    ).evidenceVerifierAuthorizationId;

    harness.suspendEvidenceVerifierKey("incident");
    expect(harness.simulator.getEvidenceVerifierKey(keyAuthorizationId).status)
      .toBe(EvidenceVerifierKeyStatus.suspended);
    const auditor = createAuditorScenarioFixture("evidence-key-suspended-auditor");
    const scope = createAuditorAuthorizationScopeFixture(auditor);
    const evidence = harness.createApplicationEvidence({
      applicationId: auditor.authorizationId,
      subjectDid: auditor.subjectDid,
      role: "auditor",
      scope,
    });
    const before = harness.simulator.getLedger().governanceActionCount;
    expect(() => harness.prepareIssuerDecisionAction(issuer, "approve")).toThrow();
    expect(() => harness.prepareVerifierDecisionAction(verifier, "approve")).toThrow();
    expect(() => harness.assertApplicationEvidence({
      evidence,
      applicationId: auditor.authorizationId,
      subjectDid: auditor.subjectDid,
      role: "auditor",
      scope,
    })).toThrow();
    expect(harness.simulator.getLedger().governanceActionCount).toBe(before);

    harness.revokeEvidenceVerifierKey("compromise");
    expect(harness.simulator.getEvidenceVerifierKey(keyAuthorizationId).status)
      .toBe(EvidenceVerifierKeyStatus.revoked);
    expect(() => harness.prepareIssuerDecisionAction(issuer, "approve")).toThrow();
    expect(() => harness.assertApplicationEvidence({
      evidence,
      applicationId: auditor.authorizationId,
      subjectDid: auditor.subjectDid,
      role: "auditor",
      scope,
    })).toThrow();
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
