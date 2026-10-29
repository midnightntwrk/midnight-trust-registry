import assert from "node:assert/strict";

import {
  createIssuerScenarioFixture,
  createMaintainerScenarioFixture,
  LocalTrustRegistryIntegrationHarness,
} from "../packages/trust-registry-integration/dist/index.js";

/** Isolated fixture scenarios; these do not share the main demo's ledger. */
export function runMaintainerSafetyScenarios(matrix, signCompact) {
  const lastActiveHarness = new LocalTrustRegistryIntegrationHarness("governed-demo-last-active");
  const bootstrapMembership = {
    maintainerIdCommitment: lastActiveHarness.maintainerIdCommitment,
    maintainerId: lastActiveHarness.maintainerId,
    subjectDidCommitment: lastActiveHarness.maintainerDidCommitment,
    keyId: lastActiveHarness.simulator.getLedger().lastAuthorizedMaintainerKeyId,
    seed: new Uint8Array(32),
    subjectDid: lastActiveHarness.maintainerDid,
    trustLevel: "bootstrap-maintainer",
  };
  const lastActiveActionCount = lastActiveHarness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => lastActiveHarness.suspendMaintainer(bootstrapMembership), {
    id: "compact-self-voted-maintainer-suspension",
    invariant: "A maintainer cannot vote to suspend its own DID",
    boundary: "compact",
    messagePattern: /own DID/iu,
    category: "conflicted-maintainer-vote-rejected",
  });
  matrix.expectThrown(() => lastActiveHarness.revokeMaintainer(bootstrapMembership), {
    id: "compact-self-voted-maintainer-revocation",
    invariant: "A maintainer cannot vote to revoke its own DID",
    boundary: "compact",
    messagePattern: /own DID/iu,
    category: "conflicted-maintainer-vote-rejected",
  });
  assert.equal(lastActiveHarness.simulator.getLedger().activeMaintainerCount, 1n);
  assert.equal(lastActiveHarness.simulator.getLedger().governanceActionCount, lastActiveActionCount);
  const thresholdSecond = createMaintainerScenarioFixture("governed-demo-threshold-second");
  const thresholdThird = createMaintainerScenarioFixture("governed-demo-threshold-third");
  lastActiveHarness.authorizeMaintainer(thresholdSecond);
  lastActiveHarness.authorizeMaintainer(thresholdThird);
  lastActiveHarness.updateMaintainerThresholdPolicy(2n, 1n, 1n, [thresholdSecond]);
  const thresholdRemoval = lastActiveHarness.prepareMaintainerDecisionAction(bootstrapMembership, "suspend");
  const thresholdActionCount = lastActiveHarness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => lastActiveHarness.executeMaintainerDecisionWithSignatures(
    bootstrapMembership, "suspend", [signCompact(thresholdSecond, thresholdRemoval, lastActiveHarness)],
  ), {
    id: "compact-removal-below-maintainer-threshold",
    invariant: "A non-conflicted signer cannot remove a maintainer into an all-member quorum",
    boundary: "compact",
    messagePattern: /non-conflicted removal quorum/iu,
    category: "maintainer-threshold-protected",
  });
  assert.equal(lastActiveHarness.simulator.getLedger().activeMaintainerCount, 3n);
  assert.equal(lastActiveHarness.simulator.getLedger().governanceActionCount, thresholdActionCount);

  const removedSignerHarness = new LocalTrustRegistryIntegrationHarness("governed-demo-removed-signer");
  const removedSigner = createMaintainerScenarioFixture("governed-demo-removed-signer");
  const removedSignerIssuer = createIssuerScenarioFixture("governed-demo-removed-signer-issuer");
  removedSignerHarness.authorizeMaintainer(removedSigner);
  removedSignerHarness.suspendMaintainer(removedSigner);
  removedSignerHarness.proposeIssuer(removedSignerIssuer);
  const removedSignerApproval = removedSignerHarness.prepareIssuerDecisionAction(removedSignerIssuer, "approve");
  const removedSignerActionCount = removedSignerHarness.simulator.getLedger().governanceActionCount;
  matrix.expectThrown(() => removedSignerHarness.executeIssuerDecisionWithSignatures(
    removedSignerIssuer, "approve", [signCompact(removedSigner, removedSignerApproval, removedSignerHarness)],
  ), {
    id: "compact-removed-maintainer-signer",
    invariant: "A suspended maintainer key cannot approve a new issuer",
    boundary: "compact",
    messagePattern: /active|authorized|maintainer|signature|assert/iu,
    category: "removed-signer-rejected",
  });
  assert.equal(removedSignerHarness.simulator.getLedger().governanceActionCount, removedSignerActionCount);
}
