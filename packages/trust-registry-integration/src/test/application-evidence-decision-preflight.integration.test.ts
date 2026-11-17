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
  it("does not prepare stale verifier, auditor, or maintainer approvals after policy revision", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("evidence-decision-preflight");
    const second = createMaintainerScenarioFixture("evidence-decision-second");
    const third = createMaintainerScenarioFixture("evidence-decision-third");
    const fourth = createMaintainerScenarioFixture("evidence-decision-fourth");
    await harness.authorizeMaintainer(second);
    await harness.authorizeMaintainer(third);
    await harness.authorizeMaintainer(fourth);
    await harness.updateMaintainerThresholdPolicy(2n, 1n, 2n);

    const verifier = createVerifierScenarioFixture("evidence-decision-verifier");
    const auditor = createAuditorScenarioFixture("evidence-decision-auditor");
    const candidate = createMaintainerScenarioFixture("evidence-decision-candidate");
    await harness.proposeVerifier(verifier);
    await harness.proposeAuditor(auditor);
    await harness.proposeMaintainer(candidate);
    expect((await harness.prepareVerifierDecisionAction(verifier, "approve")).evidenceHash).toHaveLength(32);
    expect((await harness.prepareAuditorDecisionAction(auditor, "approve")).evidenceHash).toHaveLength(32);
    expect((await harness.prepareMaintainerDecisionAction(candidate, "approve")).evidenceHash).toHaveLength(32);

    await harness.updateMaintainerThresholdPolicy(3n, 1n, 2n, [second]);
    const before = (await harness.simulator.getLedger()).governanceActionCount;
    for (const prepare of [
      () => harness.prepareVerifierDecisionAction(verifier, "approve"),
      () => harness.prepareVerifierDecisionAction(verifier, "activate"),
      () => harness.prepareAuditorDecisionAction(auditor, "approve"),
      () => harness.prepareAuditorDecisionAction(auditor, "activate"),
      () => harness.prepareMaintainerDecisionAction(candidate, "approve"),
      () => harness.prepareMaintainerDecisionAction(candidate, "activate"),
    ]) {
      await expect(prepare()).rejects.toThrow();
    }
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before);
  });

  it("does not prepare any applicant approval after accepted evidence expires", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("evidence-decision-expiry");
    const issuer = createIssuerScenarioFixture("evidence-expiry-issuer");
    const verifier = createVerifierScenarioFixture("evidence-expiry-verifier");
    const auditor = createAuditorScenarioFixture("evidence-expiry-auditor");
    const candidate = createMaintainerScenarioFixture("evidence-expiry-maintainer");
    await harness.proposeIssuer(issuer);
    await harness.proposeVerifier(verifier);
    await harness.proposeAuditor(auditor);
    await harness.proposeMaintainer(candidate);

    harness.advanceEvidenceTimeBy(24 * 60 * 60 * 1000 + 1);
    const before = (await harness.simulator.getLedger()).governanceActionCount;
    for (const prepare of [
      () => harness.prepareIssuerDecisionAction(issuer, "approve"),
      () => harness.prepareVerifierDecisionAction(verifier, "approve"),
      () => harness.prepareAuditorDecisionAction(auditor, "approve"),
      () => harness.prepareMaintainerDecisionAction(candidate, "approve"),
    ]) {
      await expect(prepare()).rejects.toThrow();
    }
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before);
  });

  it("rechecks the current issuer and verifier scope before preparing approval", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("evidence-decision-scope");
    const issuer = createIssuerScenarioFixture("evidence-scope-issuer");
    const verifier = createVerifierScenarioFixture("evidence-scope-verifier");
    await harness.proposeIssuer(issuer);
    await harness.proposeVerifier(verifier);

    const changedIssuer = {
      ...issuer,
      authorizationScope: { ...issuer.authorizationScope, schemaVersion: "2.0.0" },
    };
    const changedVerifier = { ...verifier, requestProfileId: `${verifier.requestProfileId}-changed` };
    await expect(harness.prepareIssuerDecisionAction(changedIssuer, "approve")).rejects.toThrow();
    await expect(harness.prepareVerifierDecisionAction(changedVerifier, "approve")).rejects.toThrow();
  });

  it("rejects pending approvals after verifier-key rotation and accepts fresh evidence", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("evidence-decision-key-rotation");
    const pendingIssuer = createIssuerScenarioFixture("evidence-key-pending-issuer");
    const pendingVerifier = createVerifierScenarioFixture("evidence-key-pending-verifier");
    const pendingAuditor = createAuditorScenarioFixture("evidence-key-pending-auditor");
    const pendingMaintainer = createMaintainerScenarioFixture("evidence-key-pending-maintainer");
    await harness.proposeIssuer(pendingIssuer);
    await harness.proposeVerifier(pendingVerifier);
    await harness.proposeAuditor(pendingAuditor);
    await harness.proposeMaintainer(pendingMaintainer);
    const previousKeyId = harness.evidenceVerifier.keyIds[0];
    const previousKey = (await harness.simulator.getIssuerProposalEvidence(
      pendingIssuer.authorizationIdCommitment,
    )).evidenceVerifierAuthorizationId;

    await harness.rotateEvidenceVerifierKey("replacement");
    expect(harness.evidenceVerifier.keyIds).toHaveLength(1);
    expect(harness.evidenceVerifier.keyIds[0]).not.toBe(previousKeyId);
    expect((await harness.simulator.getLedger()).evidenceVerifierKeyCount).toBe(2n);
    expect((await harness.simulator.getEvidenceVerifierKey(previousKey)).status)
      .toBe(EvidenceVerifierKeyStatus.retired);
    for (const prepare of [
      () => harness.prepareIssuerDecisionAction(pendingIssuer, "approve"),
      () => harness.prepareVerifierDecisionAction(pendingVerifier, "approve"),
      () => harness.prepareAuditorDecisionAction(pendingAuditor, "approve"),
      () => harness.prepareMaintainerDecisionAction(pendingMaintainer, "approve"),
    ]) {
      await expect(prepare()).rejects.toThrow();
    }

    const nextIssuer = createIssuerScenarioFixture("evidence-key-next-issuer");
    const nextVerifier = createVerifierScenarioFixture("evidence-key-next-verifier");
    const nextAuditor = createAuditorScenarioFixture("evidence-key-next-auditor");
    const nextMaintainer = createMaintainerScenarioFixture("evidence-key-next-maintainer");
    await harness.proposeIssuer(nextIssuer);
    await harness.proposeVerifier(nextVerifier);
    await harness.proposeAuditor(nextAuditor);
    await harness.proposeMaintainer(nextMaintainer);
    const replacementKey = (await harness.simulator.getIssuerProposalEvidence(
      nextIssuer.authorizationIdCommitment,
    )).evidenceVerifierAuthorizationId;
    expect((await harness.simulator.getEvidenceVerifierKey(replacementKey)).status)
      .toBe(EvidenceVerifierKeyStatus.active);
    for (const prepare of [
      () => harness.prepareIssuerDecisionAction(nextIssuer, "approve"),
      () => harness.prepareVerifierDecisionAction(nextVerifier, "approve"),
      () => harness.prepareAuditorDecisionAction(nextAuditor, "approve"),
      () => harness.prepareMaintainerDecisionAction(nextMaintainer, "approve"),
    ]) {
      expect((await prepare()).evidenceHash).toHaveLength(32);
    }
  });

  it("rejects evidence before signing when the verifier key is suspended or revoked", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("evidence-decision-key-suspension");
    const issuer = createIssuerScenarioFixture("evidence-key-suspended-issuer");
    const verifier = createVerifierScenarioFixture("evidence-key-suspended-verifier");
    await harness.proposeIssuer(issuer);
    await harness.proposeVerifier(verifier);
    const keyAuthorizationId = (await harness.simulator.getIssuerProposalEvidence(
      issuer.authorizationIdCommitment,
    )).evidenceVerifierAuthorizationId;

    await harness.suspendEvidenceVerifierKey("incident");
    expect((await harness.simulator.getEvidenceVerifierKey(keyAuthorizationId)).status)
      .toBe(EvidenceVerifierKeyStatus.suspended);
    const auditor = createAuditorScenarioFixture("evidence-key-suspended-auditor");
    const scope = createAuditorAuthorizationScopeFixture(auditor);
    const evidence = await harness.createApplicationEvidence({
      applicationId: auditor.authorizationId,
      subjectDid: auditor.subjectDid,
      role: "auditor",
      scope,
    });
    const before = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.prepareIssuerDecisionAction(issuer, "approve")).rejects.toThrow();
    await expect(harness.prepareVerifierDecisionAction(verifier, "approve")).rejects.toThrow();
    await expect(harness.assertApplicationEvidence({
      evidence,
      applicationId: auditor.authorizationId,
      subjectDid: auditor.subjectDid,
      role: "auditor",
      scope,
    })).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before);

    await harness.revokeEvidenceVerifierKey("compromise");
    expect((await harness.simulator.getEvidenceVerifierKey(keyAuthorizationId)).status)
      .toBe(EvidenceVerifierKeyStatus.revoked);
    await expect(harness.prepareIssuerDecisionAction(issuer, "approve")).rejects.toThrow();
    await expect(harness.assertApplicationEvidence({
      evidence,
      applicationId: auditor.authorizationId,
      subjectDid: auditor.subjectDid,
      role: "auditor",
      scope,
    })).rejects.toThrow();
  });

  it("snapshots accepted evidence before crossing the Compact proposal boundary", async () => {
    const harness = new LocalTrustRegistryIntegrationHarness("evidence-snapshot-boundary");
    const verifier = createVerifierScenarioFixture("evidence-snapshot-verifier");
    const scope = createVerifierAuthorizationScopeFixture(verifier);
    const evidence = await harness.createApplicationEvidence({
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
    const before = (await harness.simulator.getLedger()).governanceActionCount;
    await expect(harness.proposeVerifierWithApplicationEvidence(verifier, evidence, expectation)).rejects.toThrow();
    expect((await harness.simulator.getLedger()).governanceActionCount).toBe(before);
    await expect(harness.simulator.getVerifierAuthorization(verifier.authorizationIdCommitment)).rejects.toThrow();
  });
});
